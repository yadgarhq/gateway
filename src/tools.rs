//! The MCP tools this gateway exposes, and their dispatch to module services.
//!
//! **A tool is named as the CALLER names it**, not as the gRPC method is named.
//! D67 rolls up per `tool`, and the number a person tunes is "what did
//! `create_task` cost me" — so the label has to be the string the client sent.

use serde_json::{json, Value};

use crate::pb::yadgar::common::v1::Scope;
use crate::pb::yadgar::taskapi::v1::{
    read_task_request::Key, task_service_client::TaskServiceClient, ReadTaskRequest,
};
use crate::upstream::{CallError, TaskUpstream};

mod change;
mod create;
mod find;
pub(crate) mod reason;
mod view;

use view::status_name;
pub use view::TaskView;

/// A tool's name, as a bounded value.
///
/// `&'static str` because it becomes a METRIC LABEL, and a metric label must come
/// from a closed set — the cardinality rule D67 exists to enforce. Accepting an
/// arbitrary caller string here would put one series per invented tool name into
/// Prometheus.
pub const CREATE_TASK: &str = "create_task";
pub const READ_TASK: &str = "read_task";
pub const FIND_TASKS: &str = "find_tasks";
pub const EDIT_TASK: &str = "edit_task";
pub const TRANSITION_TASK: &str = "transition_task";
/// The per-user project listing (ADR-0963 (8), `plans/team-access.md` §8).
/// THE ONE TOOL EXEMPT FROM `X-Yadgar-Project`: it names no project, so it is
/// attested without a workspace and never reaches the project validator. It
/// is served by the gateway itself from the loaded registry, so it never
/// reaches [`call`] either — see `http::listing`.
pub const LIST_PROJECTS: &str = "list_projects";

/// EVERY tool this gateway serves, stated ONCE.
///
/// **ADR-0492: an administrative verb is never a member.** Its rule is about
/// CALLABILITY, not advertisement — "an MCP tool is callable by the agent, and
/// therefore callable by anything that can influence the agent's context" — and
/// the catalogue is not what makes a verb callable. `tools_call`
/// (`http.rs:1051`) never reads [`definitions`]; it gates on [`label_for`] and
/// [`module_for`] and dispatches through [`call`]'s own match. Those were four
/// independent literals, so a verb wired into three of them was fully callable,
/// absent from `tools/list`, and green on every check that existed.
///
/// This array is the MEMBERSHIP AUTHORITY, not a payload source. [`module_for`],
/// [`definitions`] and [`call`] each keep their own per-tool body — no array of
/// names yields a module string, a JSON schema, or a dispatch — but each gates
/// on membership here first, so a name outside this array reaches none of them.
/// **Adding a tool anywhere is adding it HERE.**
///
/// **CO-CHANGE (ledger 1550): the client's rules ship in the binary and name
/// these tools.** `yadgarhq/yadgar` `src/install/rules.rs` and
/// `assets/rules.md` list the served tool names. Adding, removing or renaming a
/// member here changes what those rules must say — change them in the same
/// release, or a rename recreates ledger 1543.
pub const SERVED: [&str; 6] = [
    CREATE_TASK,
    READ_TASK,
    FIND_TASKS,
    EDIT_TASK,
    TRANSITION_TASK,
    LIST_PROJECTS,
];

/// Whether `name` is a tool this gateway serves.
///
/// **THE GUARD BEING THE ONLY ROUTE INTO EACH FUNCTION BELOW IS A REVIEW
/// OBLIGATION, NOT AN ASSERTED ONE**, and it is stated here rather than left to
/// be discovered. `the_served_set_is_exactly_the_five_task_tools` bounds the
/// ARRAY; nothing bounds the derivation. A `match` arm added AHEAD of one of
/// these calls makes a verb reachable with the array untouched, and the tests
/// catch it only if the verb happens to be one they probe by name. Read the
/// diff.
fn is_served(name: &str) -> bool {
    SERVED.contains(&name)
}

/// Resolve a caller-supplied name to the bounded label, or refuse it.
///
/// A lookup in [`SERVED`] rather than a match of its own, because the answer IS
/// the name — every arm this replaced read `CREATE_TASK => Some(CREATE_TASK)`.
/// `.copied()` turns the `&&'static str` the iterator yields into the
/// `&'static str` a metric label needs.
pub fn label_for(name: &str) -> Option<&'static str> {
    SERVED.iter().find(|&&served| served == name).copied()
}

/// Whether a tool writes. Decides `CallRecord.kind`, and a wrong answer here
/// makes read and write traffic indistinguishable in the roll-ups.
///
/// **FAIL CLOSED: THE READS ARE THE LIST.** A tool added to [`SERVED`] and not
/// classified here is a write, so it spends the write bucket and reports as
/// write traffic until somebody says otherwise. The opposite default would let
/// a new writing tool pass as a read.
pub fn is_write(name: &str) -> bool {
    !matches!(name, READ_TASK | FIND_TASKS | LIST_PROJECTS)
}

/// The MODULE a tool belongs to, as a bounded value.
///
/// D74 keys a token bucket on `(user, module, kind)`, so this is the second half
/// of that key — and it is `&'static str` from a closed set for the same reason
/// [`label_for`] is: an arbitrary caller string here would put one bucket, and
/// one metric series, per invented name.
///
/// Every tool this gateway serves today reaches `task`. The function exists
/// rather than the constant being inlined because the next module makes this a
/// real mapping, and a limit keyed on a hardcoded `"task"` would silently pool
/// `memory` writes into `task`'s bucket.
pub fn module_for(name: &str) -> Option<&'static str> {
    // ADR-0492's membership gate, FIRST. The body below is this function's own
    // and stays so — `"task"` is a string no array of tool names produces — but
    // a name outside `SERVED` never reaches it.
    if !is_served(name) {
        return None;
    }
    match name {
        CREATE_TASK | READ_TASK | FIND_TASKS | EDIT_TASK | TRANSITION_TASK => Some("task"),
        // Its own D74 bucket, so listing never spends `task`'s; an unconfigured
        // `project.read` pair takes the configured fallback (`Limits::effective`).
        LIST_PROJECTS => Some("project"),
        _ => None,
    }
}

/// The `tools/list` payload.
///
/// `inputSchema` is REQUIRED and must be a valid JSON Schema object — not null,
/// not absent. Clients drive argument collection from it.
///
/// The NAME LIST is [`SERVED`], iterated in order; the descriptions and schemas
/// are [`definition`]'s, per tool. So the catalogue cannot advertise a name the
/// membership authority does not carry, and cannot silently drop one it does.
pub fn definitions() -> Value {
    Value::Array(SERVED.iter().map(|&name| definition(name)).collect())
}

/// One catalogue entry.
///
/// The name is stamped from the argument rather than repeated in each arm, so a
/// member of [`SERVED`] always appears under its own name. A member with no arm
/// here is a defect, and it surfaces as a MISSING SCHEMA rather than a missing
/// entry — `every_tool_declares_an_object_input_schema` fails, and nothing
/// panics in a request path.
fn definition(name: &str) -> Value {
    let (title, description, input_schema) = match name {
        CREATE_TASK => (
            "Create a task",
            "Create a task in the caller's project. \
             The id, number and version are assigned by the module.",
            create::schema(),
        ),
        READ_TASK => (
            "Read a task",
            "Read one task by its id or by its per-project number.",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "URN, e.g. yadgar:task:0192..." },
                    "number": { "type": "integer", "description": "Per-project task number" },
                },
            }),
        ),
        FIND_TASKS => (
            "Find tasks",
            "List tasks visible to the caller, oldest first (by id, a UUIDv7 \
             timestamp; task-db runs 2 replicas, so ids are ordered to the \
             millisecond across replicas, not strictly by number). \
             Filter by status with `statuses`; ask for `fields: \"summary\"` to \
             leave out bodies, tags and links, or `fields: \"index\"` for \
             number, status and title only. A listing reaches the caller's \
             project and the projects below it, but edit_task and \
             transition_task resolve a number in the caller's exact project \
             only. So an index row from another project carries its \
             `project_id`: to edit or move that task, use its id (from \
             `fields: \"summary\"`), or work from that project.",
            find::schema(),
        ),
        EDIT_TASK => (
            "Edit a task",
            "Change a task's title, body, or both. Name the task by id or by \
             number, not both. Only the fields sent are written; send at least \
             one. Status is changed with transition_task, never here. Refused if \
             the task's version is not expect_version, or if the body does not \
             match expect_body_sha256. To change part of a body, send `patch` \
             instead of `body`: a literal (not regex) replace of every \
             occurrence of `old` by `new`, refused unless `old` occurs exactly \
             expect_count times (counted non-overlapping, left to right). With \
             a patch, expect_body_sha256 is the hash of the pre-edit body as \
             read, and patch.expect_new_sha256 is the hash of `new`. `old` and \
             `new` are at most 65536 bytes each. A refusal a program can act on \
             starts with a reason token and a colon: VERSION_MISMATCH (re-read, \
             then retry with the version you see), PATCH_COUNT_MISMATCH, \
             PATCH_RESULT_TOO_LARGE, BODY_SHA256_MISMATCH or \
             PATCH_NEW_SHA256_MISMATCH. Any other refusal carries no token.",
            change::edit_schema(),
        ),
        TRANSITION_TASK => (
            "Transition a task",
            "Move a task to another status. Name the task by id or by number, \
             not both. The module decides which moves are legal. Refused if the \
             task's version is not expect_version.",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "URN, e.g. yadgar:task:0192..." },
                    "number": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Per-project task number, instead of id",
                    },
                    "expect_version": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "The version last read; the move is refused if it moved",
                    },
                    "to": {
                        "type": "string",
                        "enum": change::TARGETS,
                        "description": "The status to move to",
                    },
                },
                "required": ["expect_version", "to"],
            }),
        ),
        LIST_PROJECTS => list_definition(),
        // Unreachable for a member of `SERVED`, and deliberately not a panic.
        _ => ("", "", Value::Null),
    };
    json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": input_schema,
    })
}

/// `list_projects`' catalogue entry, split out of [`definition`] for the
/// function-size ceiling.
fn list_definition() -> (&'static str, &'static str, Value) {
    (
        "List your projects",
        "List the projects you may reach: every organisation project one of \
         your teams is granted, with `access` read or readWrite, and your own \
         private projects, with `access` owner. Each entry carries `path`, \
         `status` (active or archived) and `kind` (root, project or private). \
         Needs no x-yadgar-project header. Takes no arguments except \
         `page_token`, the `next_page_token` of the previous page.",
        json!({
            "type": "object",
            "properties": {
                "page_token": {
                    "type": "string",
                    "description": "The next_page_token a previous call answered",
                },
            },
            "additionalProperties": false,
        }),
    )
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    /// The caller's fault: bad arguments. Becomes a tool-level failure
    /// (`isError: true`) rather than a protocol error, because the request was
    /// well-formed MCP — it is the tool that could not run.
    #[error("{0}")]
    Invalid(String),

    /// The upstream module's fault, or the network's, or a refusal the module
    /// answered. Rendered by [`reason::upstream_text`].
    #[error("{}", reason::upstream_text(.0))]
    Upstream(#[from] tonic::Status),

    #[error("unknown tool: {0}")]
    Unknown(String),
}

/// The `content` payload for one tool call, and how many records it carried.
///
/// **The row count is returned rather than dropped**, which is the whole reason
/// this is a pair. `CallRecord.rows_returned` was `0` on every gateway call while
/// `find_tasks` knew `resp.tasks.len()` and discarded it — so D67 could say what
/// a call cost in bytes and never how much it fetched, and "twenty tasks" and
/// "one task" were indistinguishable in the roll-ups.
pub struct Output {
    pub content: Value,
    pub rows: u32,
}

/// Call one tool.
///
/// Returns the `content` payload for a successful `tools/call` result. Telemetry
/// is NOT emitted here: the record's bytes and words must measure the OUTWARD
/// JSON, which only exists once the HTTP layer has serialised the whole
/// response — measuring here would count the protobuf on the wrong side of the
/// boundary, which is the mistake D67 was written to avoid.
pub async fn call(
    task: &TaskUpstream,
    scope: Scope,
    name: &str,
    args: &Value,
) -> Result<Output, ToolError> {
    // ADR-0492'S MEMBERSHIP GATE, AND IT IS THE FIRST STATEMENT IN THE FUNCTION
    // deliberately. Nothing below dispatches for a name outside `SERVED`, and
    // the `other =>` arm at the bottom would refuse it anyway — but this is
    // where a reader is told that the array governs CALLABILITY, which is
    // ADR-0492's actual property and the one the catalogue does not carry.
    //
    // Like the other two guards, its being the only route in is a review
    // obligation. See [`is_served`].
    if !is_served(name) {
        return Err(ToolError::Unknown(name.to_string()));
    }

    // ONE DEADLINE FOR THE CALL, built before its own work (ADR-1019): the
    // chart's `task.requestTimeoutSeconds`, which `bounded` also SENDS.
    let deadline = yadgar_dial::Deadline::after(task.timeout());
    // The request id and tool `bounded` logs, read before `scope` moves.
    let who = (scope.request_id.clone(), name);
    let mut client = TaskServiceClient::new(crate::upstream::request_id::carrying(
        task.channel(),
        &scope.request_id,
    ));

    match name {
        CREATE_TASK => {
            let request = create::request(scope, args, crate::idempotency_key)?;
            let resp = bounded(task, deadline, &who, request, |r| client.create_task(r))
                .await?
                .into_inner();
            let meta = resp.meta.unwrap_or_default();
            Ok(Output {
                content: json!({ "id": meta.id, "number": resp.number, "version": meta.version }),
                // One task created is one row written.
                rows: 1,
            })
        }

        READ_TASK => {
            // Exactly one key, and saying so is the contract: the proto models it
            // as a oneof, so sending both is not expressible and sending neither
            // has no meaning.
            let key = match (
                args.get("id").and_then(Value::as_str),
                args.get("number").and_then(Value::as_u64),
            ) {
                (Some(id), None) => Key::Id(id.to_string()),
                (None, Some(n)) => Key::Number(n as u32),
                (Some(_), Some(_)) => {
                    return Err(ToolError::Invalid("give `id` or `number`, not both".into()))
                }
                (None, None) => {
                    return Err(ToolError::Invalid("`id` or `number` is required".into()))
                }
            };
            let request = ReadTaskRequest {
                scope: Some(scope),
                key: Some(key),
            };
            let resp = bounded(task, deadline, &who, request, |r| client.read_task(r))
                .await?
                .into_inner();
            Ok(Output {
                content: serde_json::to_value(TaskView::full(resp.task)).unwrap_or(Value::Null),
                rows: 1,
            })
        }

        FIND_TASKS => {
            let scope_project = scope.project_id.clone();
            let (request, fields) = find::request(scope, args)?;
            let resp = bounded(task, deadline, &who, request, |r| client.find_tasks(r))
                .await?
                .into_inner();
            Ok(find::output(resp, fields, &scope_project))
        }

        EDIT_TASK => change::edit(&mut client, task, deadline, scope, args).await,
        TRANSITION_TASK => change::transition(&mut client, task, deadline, scope, args).await,

        other => Err(ToolError::Unknown(other.to_string())),
    }
}

/// Send one `task` RPC under `deadline`, and await it for no longer.
///
/// **EVERY `TaskServiceClient` call goes through this** (yaadgaar #361), and
/// through [`TaskUpstream::call`] (ADR-1019): `task` is sent the deadline as
/// `grpc-timeout`, so it and the hops behind it stop when this gateway does,
/// and the wait for a ready endpoint is bounded by the same value.
///
/// A timeout is `DEADLINE_EXCEEDED`, the code the `iam` and `attest` deadlines
/// already use, so it reaches the caller as the same class of failure. The
/// gateway's OWN timeout carries the bound and nothing from the peer; a
/// `DEADLINE_EXCEEDED` that `task` answered itself keeps its own words.
pub(super) async fn bounded<M, T, F, Fut>(
    task: &TaskUpstream,
    deadline: yadgar_dial::Deadline,
    who: &(String, &str),
    request: M,
    rpc: F,
) -> Result<tonic::Response<T>, ToolError>
where
    F: FnOnce(tonic::Request<M>) -> Fut,
    Fut: std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
{
    let (request_id, tool) = (who.0.as_str(), who.1);
    task.call(deadline, request, rpc)
        .await
        .map_err(|e| match e {
            CallError::Expired => ToolError::Upstream(tonic::Status::deadline_exceeded(format!(
                "task did not answer within {}s",
                task.timeout().as_secs()
            ))),
            CallError::Answered(status) => {
                // THE ONLY PLACE A TRANSPORT FAILURE'S DETAIL IS WRITTEN DOWN
                // (yaadgaar #452): the caller reads `reason::TRANSPORT_FAILED`.
                if std::error::Error::source(&status).is_some() {
                    tracing::warn!(request_id, tool, error = ?status, "a task call failed below gRPC");
                }
                ToolError::Upstream(status)
            }
        })
}

#[cfg(test)]
mod tests;
