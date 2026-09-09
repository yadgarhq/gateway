//! The MCP tools this gateway exposes, and their dispatch to module services.
//!
//! **A tool is named as the CALLER names it**, not as the gRPC method is named.
//! D67 rolls up per `tool`, and the number a person tunes is "what did
//! `create_task` cost me" — so the label has to be the string the client sent.

use serde_json::{json, Value};
use tonic::transport::Channel;

use crate::pb::yadgar::common::v1::{Idempotency, Scope};
use crate::pb::yadgar::taskapi::v1::{
    read_task_request::Key, task_service_client::TaskServiceClient, CreateTaskRequest,
    FindTasksRequest, FindTasksResponse, ReadTaskRequest,
};

/// A tool's name, as a bounded value.
///
/// `&'static str` because it becomes a METRIC LABEL, and a metric label must come
/// from a closed set — the cardinality rule D67 exists to enforce. Accepting an
/// arbitrary caller string here would put one series per invented tool name into
/// Prometheus.
pub const CREATE_TASK: &str = "create_task";
pub const READ_TASK: &str = "read_task";
pub const FIND_TASKS: &str = "find_tasks";

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
pub const SERVED: [&str; 3] = [CREATE_TASK, READ_TASK, FIND_TASKS];

/// Whether `name` is a tool this gateway serves.
///
/// **THE GUARD BEING THE ONLY ROUTE INTO EACH FUNCTION BELOW IS A REVIEW
/// OBLIGATION, NOT AN ASSERTED ONE**, and it is stated here rather than left to
/// be discovered. `the_served_set_is_exactly_the_three_task_tools` bounds the
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
pub fn is_write(name: &str) -> bool {
    name == CREATE_TASK
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
        CREATE_TASK | READ_TASK | FIND_TASKS => Some("task"),
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
            json!({
                "type": "object",
                "properties": {
                    "title": { "type": "string", "description": "Short summary of the task" },
                    "body": { "type": "string", "description": "Full description" },
                    "tags": { "type": "array", "items": { "type": "string" } },
                },
                "required": ["title"],
            }),
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
            "List tasks visible to the caller, newest first.",
            json!({
                "type": "object",
                "properties": {
                    "page_size": { "type": "integer", "description": "Maximum results" },
                    "page_token": { "type": "string", "description": "Continuation token" },
                },
            }),
        ),
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

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    /// The caller's fault: bad arguments. Becomes a tool-level failure
    /// (`isError: true`) rather than a protocol error, because the request was
    /// well-formed MCP — it is the tool that could not run.
    #[error("{0}")]
    Invalid(String),

    /// The upstream module's fault, or the network's.
    #[error("{0}")]
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

/// Shape a `find_tasks` response, and count what it returned.
///
/// Split out so the count is testable without a task service behind it: `build.rs`
/// generates the CLIENT half only, so there is no server stub to fake, and a row
/// count that only a live upstream can exercise is a row count nothing pins.
fn find_tasks_output(resp: FindTasksResponse) -> Output {
    let rows = resp.tasks.len() as u32;
    Output {
        content: json!({
            "tasks": resp.tasks.into_iter().map(|t| TaskView::from(Some(t))).collect::<Vec<_>>(),
            "next_page_token": resp.next_page_token,
        }),
        rows,
    }
}

/// Call one tool.
///
/// Returns the `content` payload for a successful `tools/call` result. Telemetry
/// is NOT emitted here: the record's bytes and words must measure the OUTWARD
/// JSON, which only exists once the HTTP layer has serialised the whole
/// response — measuring here would count the protobuf on the wrong side of the
/// boundary, which is the mistake D67 was written to avoid.
pub async fn call(
    channel: Channel,
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

    let mut client = TaskServiceClient::new(channel);

    match name {
        CREATE_TASK => {
            let title = args
                .get("title")
                .and_then(Value::as_str)
                .ok_or_else(|| ToolError::Invalid("`title` is required".into()))?;
            let resp = client
                .create_task(CreateTaskRequest {
                    idempotency: Some(Idempotency {
                        key: crate::idempotency_key(),
                    }),
                    scope: Some(scope),
                    title: title.to_string(),
                    body: args
                        .get("body")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    tags: args
                        .get("tags")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default(),
                    links: Vec::new(),
                })
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
            let resp = client
                .read_task(ReadTaskRequest {
                    scope: Some(scope),
                    key: Some(key),
                })
                .await?
                .into_inner();
            Ok(Output {
                content: serde_json::to_value(TaskView::from(resp.task)).unwrap_or(Value::Null),
                rows: 1,
            })
        }

        FIND_TASKS => {
            let resp = client
                .find_tasks(FindTasksRequest {
                    scope: Some(scope),
                    statuses: Vec::new(),
                    page_size: args.get("page_size").and_then(Value::as_i64).unwrap_or(20) as i32,
                    page_token: args
                        .get("page_token")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                })
                .await?
                .into_inner();
            Ok(find_tasks_output(resp))
        }

        other => Err(ToolError::Unknown(other.to_string())),
    }
}

/// The JSON shape of a task as a CLIENT sees it.
///
/// Deliberately not `serde_json::to_value` over the generated protobuf type. The
/// generated struct carries wire-level shapes — `Option` around every message,
/// enums as `i32` — and serialising it directly would leak the transport into the
/// public JSON and change whenever the proto's internal representation did.
#[derive(serde::Serialize)]
pub struct TaskView {
    id: String,
    number: u32,
    title: String,
    body: String,
    status: String,
    version: u64,
}

impl From<Option<crate::pb::yadgar::task::v1::Task>> for TaskView {
    fn from(task: Option<crate::pb::yadgar::task::v1::Task>) -> Self {
        let task = task.unwrap_or_default();
        let meta = task.meta.unwrap_or_default();
        Self {
            id: meta.id,
            number: task.number,
            title: task.title,
            body: task.body,
            // The enum's own name, lowercased and stripped of its prefix — a
            // number would make the payload unreadable and would silently change
            // meaning if the enum were ever reordered.
            status: crate::pb::yadgar::task::v1::TaskStatus::try_from(task.status)
                .map(|s| {
                    s.as_str_name()
                        .trim_start_matches("TASK_STATUS_")
                        .to_ascii_lowercase()
                })
                .unwrap_or_else(|_| "unspecified".to_string()),
            version: meta.version,
        }
    }
}

#[cfg(test)]
mod tests;
