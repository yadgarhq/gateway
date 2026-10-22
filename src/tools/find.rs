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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fields {
    Full,
    Summary,
}

/// The spellings `fields` accepts, as the schema advertises them. `full` first:
/// it is what a caller that sends nothing gets, so an existing caller sees no
/// change.
pub(super) const FIELDS: [&str; 2] = ["full", "summary"];

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
fn statuses(args: &Value) -> Result<Vec<i32>, ToolError> {
    let Some(value) = present(args, "statuses") else {
        return Ok(Vec::new());
    };
    let allowed = TARGETS.join(", ");
    let names = value
        .as_array()
        .ok_or_else(|| ToolError::Invalid(format!("`statuses` must be an array of: {allowed}")))?;
    names
        .iter()
        .map(|name| {
            name.as_str()
                .and_then(target)
                .map(|s| s as i32)
                .ok_or_else(|| {
                    ToolError::Invalid(format!(
                        "unknown status {name} in `statuses`; use: {allowed}"
                    ))
                })
        })
        .collect()
}

/// The row shape. Absent or `null` is [`Fields::Full`].
fn fields(args: &Value) -> Result<Fields, ToolError> {
    match present(args, "fields").map(|v| v.as_str()) {
        None | Some(Some("full")) => Ok(Fields::Full),
        Some(Some("summary")) => Ok(Fields::Summary),
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
pub(super) fn output(resp: FindTasksResponse, fields: Fields) -> Output {
    let rows = resp.tasks.len() as u32;
    let view = match fields {
        Fields::Full => TaskView::full,
        Fields::Summary => TaskView::summary,
    };
    Output {
        content: json!({
            "tasks": resp.tasks.into_iter().map(|t| view(Some(t))).collect::<Vec<_>>(),
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
                "description": "Only tasks in one of these statuses; omit for every status",
            },
            "fields": {
                "type": "string",
                "enum": FIELDS,
                "default": "full",
                "description": "summary: id, number, title, status and version only",
            },
            "page_size": { "type": "integer", "description": "Maximum results" },
            "page_token": { "type": "string", "description": "Continuation token" },
        },
    })
}
