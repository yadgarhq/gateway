//! `find_tasks`: the request this gateway builds from the caller's arguments,
//! and the shape of what it returns.
//!
//! **SPLIT OUT AS PURE FUNCTIONS FOR ONE REASON**: `build.rs` generates the
//! CLIENT half of `TaskService` only, so there is no server stub to fake, and
//! the request this gateway BUILDS is what a test can pin rather than what it
//! sends.

use serde_json::{json, Value};

use super::change::{present, target, TARGETS};
use super::{Output, TaskView, ToolError};
use crate::pb::yadgar::common::v1::Scope;
use crate::pb::yadgar::taskapi::v1::{FindTasksRequest, FindTasksResponse};

/// How much of each task a `find_tasks` row carries.
///
/// **A NAMED SHAPE, NOT AN `include_body` FLAG.** The summary drops `body`,
/// `tags` and `links` together — it is the five fields a caller needs to pick a
/// task (`id`, `number`, `title`, `status`, `version`), and a boolean named for
/// one of the three it drops would misdescribe the other two. A string enum is
/// also the convention this catalogue already has for a closed choice
/// (`transition_task`'s `to`).
///
/// **THE INDEX IS LEANER STILL: `number`, `status` and `title`** (yaadgaar
/// #397). Measured over 243 tasks, 40% of a summary was not titles: each row
/// repeats a 50-character URN, its `version` and the key names. An agent
/// addresses a task by its number (`read_task`, `edit_task` and
/// `transition_task` all take one), and reads the version it must send from a
/// `read_task`, so a listing it only scans needs neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fields {
    Full,
    Summary,
    Index,
}

/// The spellings `fields` accepts, as the schema advertises them. `full` first:
/// it is what a caller that sends nothing gets, so an existing caller sees no
/// change.
pub(super) const FIELDS: [&str; 3] = ["full", "summary", "index"];

/// One `find_tasks` row in the index shape.
///
/// **A ROW FROM ANOTHER PROJECT NAMES THAT PROJECT.** A listing reaches the
/// scope's whole subtree (D53), but `edit_task` and `transition_task` resolve a
/// number in the caller's EXACT project. A bare `7` from a descendant project
/// would send an edit by number to the caller's own task 7, or to NOT_FOUND. So
/// `project_id` is present exactly when the task's project differs from the
/// scope's, and absent when they are equal, which keeps the common listing lean.
#[derive(serde::Serialize)]
struct IndexRow {
    number: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    status: String,
    title: String,
}

impl IndexRow {
    fn of(task: crate::pb::yadgar::task::v1::Task, scope_project: &str) -> Value {
        let project_id = task
            .meta
            .map(|m| m.project_id)
            .filter(|p| p != scope_project);
        serde_json::to_value(Self {
            number: task.number,
            project_id,
            status: super::status_name(task.status),
            title: task.title,
        })
        .unwrap_or(Value::Null)
    }
}

/// `page_size` exactly as the MCP caller sent it, with no second default
/// (ledger 1281, ADR-0569). Absence and an explicit `0` both forward as `0`
/// rather than this gateway's own `20` — a page size has exactly one source,
/// `task-db`'s `DEFAULT_PAGE`, and a gateway-side default was a second one
/// nobody could see drift from the first.
pub(super) fn requested_page_size(args: &Value) -> i32 {
    args.get("page_size").and_then(Value::as_i64).unwrap_or(0) as i32
}

/// The status filter, in the proto's numbering.
///
/// **AN UNKNOWN NAME IS REFUSED, NEVER DROPPED.** Dropping it would turn
/// `["open", "opne"]` into `["open"]`, and `["opne"]` into an EMPTY filter —
/// which `task-db` reads as every status. A typo would then answer with more
/// rows than were asked for, and look like success. Absent, `null` and `[]`
/// all mean "every status", which is `task-db`'s own rule for an empty filter.
///
/// **AT MOST [`TARGETS`]`.len()` ENTRIES, DE-DUPLICATED.** `task-db` builds one
/// `?` placeholder per entry, so an array longer than the number of statuses
/// is refused before any name is read, and a repeated name is sent once (first
/// occurrence wins the order).
fn statuses(args: &Value) -> Result<Vec<i32>, ToolError> {
    let Some(value) = present(args, "statuses") else {
        return Ok(Vec::new());
    };
    let allowed = TARGETS.join(", ");
    let names = value
        .as_array()
        .ok_or_else(|| ToolError::Invalid(format!("`statuses` must be an array of: {allowed}")))?;
    if names.len() > TARGETS.len() {
        return Err(ToolError::Invalid(format!(
            "`statuses` takes at most {} entries, one per status: {allowed}",
            TARGETS.len()
        )));
    }
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let status = name.as_str().and_then(target).ok_or_else(|| {
            ToolError::Invalid(format!(
                "unknown status {} in `statuses`; use: {allowed}",
                shown(name)
            ))
        })? as i32;
        if !out.contains(&status) {
            out.push(status);
        }
    }
    Ok(out)
}

/// How long a caller's string may be before a refusal shortens it.
const SHOWN_MAX: usize = 32;

/// A caller's value as a refusal names it: a string, quoted and cut to
/// [`SHOWN_MAX`] characters; anything else, by its JSON type. A refusal never
/// echoes an unbounded value back into the caller's context.
fn shown(value: &Value) -> String {
    match value {
        Value::String(s) if s.chars().count() > SHOWN_MAX => {
            format!("\"{}…\"", s.chars().take(SHOWN_MAX).collect::<String>())
        }
        Value::String(s) => format!("\"{s}\""),
        Value::Null => "null".into(),
        Value::Bool(_) => "a boolean".into(),
        Value::Number(_) => "a number".into(),
        Value::Array(_) => "an array".into(),
        Value::Object(_) => "an object".into(),
    }
}

/// The row shape. Absent or `null` is [`Fields::Full`].
fn fields(args: &Value) -> Result<Fields, ToolError> {
    match present(args, "fields").map(|v| v.as_str()) {
        None | Some(Some("full")) => Ok(Fields::Full),
        Some(Some("summary")) => Ok(Fields::Summary),
        Some(Some("index")) => Ok(Fields::Index),
        Some(_) => Err(ToolError::Invalid(format!(
            "`fields` must be one of: {}",
            FIELDS.join(", ")
        ))),
    }
}

/// The upstream request and the row shape, or the caller's mistake.
pub(super) fn request(scope: Scope, args: &Value) -> Result<(FindTasksRequest, Fields), ToolError> {
    let request = FindTasksRequest {
        scope: Some(scope),
        statuses: statuses(args)?,
        page_size: requested_page_size(args),
        page_token: args
            .get("page_token")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    };
    Ok((request, fields(args)?))
}

/// Shape a `find_tasks` response, and count what it returned.
///
/// The row count is the number of TASKS, whatever the shape: a summary fetched
/// the same rows a full page did, and D67 measures what a call fetched.
///
/// `scope_project` is the project the listing was scoped to. Only the index
/// shape reads it, to name the project of a row from elsewhere in the subtree.
pub(super) fn output(resp: FindTasksResponse, fields: Fields, scope_project: &str) -> Output {
    let rows = resp.tasks.len() as u32;
    let view = |t| match fields {
        Fields::Full => serde_json::to_value(TaskView::full(Some(t))).unwrap_or(Value::Null),
        Fields::Summary => serde_json::to_value(TaskView::summary(Some(t))).unwrap_or(Value::Null),
        Fields::Index => IndexRow::of(t, scope_project),
    };
    Output {
        content: json!({
            "tasks": resp.tasks.into_iter().map(view).collect::<Vec<_>>(),
            "next_page_token": resp.next_page_token,
        }),
        rows,
    }
}

/// `find_tasks`'s `inputSchema`, kept beside the parsing that enforces it so the two
/// change together. The catalogue entry itself is [`super::definition`]'s.
pub(super) fn schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "statuses": {
                "type": "array",
                "items": { "type": "string", "enum": TARGETS },
                "maxItems": TARGETS.len(),
                "description": "Only tasks in one of these statuses; omit for every \
                                status. A repeated status counts once",
            },
            "fields": {
                "type": "string",
                "enum": FIELDS,
                "default": "full",
                "description": "summary: id, number, title, status and version only. \
                                index: number, status and title only, plus project_id \
                                on a row from a project other than the caller's",
            },
            "page_size": { "type": "integer", "description": "Maximum results" },
            "page_token": { "type": "string", "description": "Continuation token" },
        },
    })
}
