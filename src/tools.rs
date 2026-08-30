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
    FindTasksRequest, ReadTaskRequest,
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

/// Resolve a caller-supplied name to the bounded label, or refuse it.
pub fn label_for(name: &str) -> Option<&'static str> {
    match name {
        CREATE_TASK => Some(CREATE_TASK),
        READ_TASK => Some(READ_TASK),
        FIND_TASKS => Some(FIND_TASKS),
        _ => None,
    }
}

/// Whether a tool writes. Decides `CallRecord.kind`, and a wrong answer here
/// makes read and write traffic indistinguishable in the roll-ups.
pub fn is_write(name: &str) -> bool {
    name == CREATE_TASK
}

/// The `tools/list` payload.
///
/// `inputSchema` is REQUIRED and must be a valid JSON Schema object — not null,
/// not absent. Clients drive argument collection from it.
pub fn definitions() -> Value {
    json!([
        {
            "name": CREATE_TASK,
            "title": "Create a task",
            "description": "Create a task in the caller's project. \
                            The id, number and version are assigned by the module.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "title": { "type": "string", "description": "Short summary of the task" },
                    "body": { "type": "string", "description": "Full description" },
                    "tags": { "type": "array", "items": { "type": "string" } },
                },
                "required": ["title"],
            },
        },
        {
            "name": READ_TASK,
            "title": "Read a task",
            "description": "Read one task by its id or by its per-project number.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "URN, e.g. yadgar:task:0192..." },
                    "number": { "type": "integer", "description": "Per-project task number" },
                },
            },
        },
        {
            "name": FIND_TASKS,
            "title": "Find tasks",
            "description": "List tasks visible to the caller, newest first.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "page_size": { "type": "integer", "description": "Maximum results" },
                    "page_token": { "type": "string", "description": "Continuation token" },
                },
            },
        },
    ])
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
) -> Result<Value, ToolError> {
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
            Ok(json!({ "id": meta.id, "number": resp.number, "version": meta.version }))
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
            Ok(serde_json::to_value(TaskView::from(resp.task)).unwrap_or(Value::Null))
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
            Ok(json!({
                "tasks": resp.tasks.into_iter().map(|t| TaskView::from(Some(t))).collect::<Vec<_>>(),
                "next_page_token": resp.next_page_token,
            }))
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
mod tests {
    use super::*;

    #[test]
    fn every_advertised_tool_resolves_to_a_bounded_label() {
        // The list a client is told about and the set the metric layer accepts
        // must be the same set, or a tool works and reports under no label.
        for tool in definitions().as_array().unwrap() {
            let name = tool["name"].as_str().unwrap();
            assert!(label_for(name).is_some(), "{name} has no bounded label");
        }
    }

    #[test]
    fn an_unknown_tool_gets_no_label() {
        assert!(label_for("../../etc/passwd").is_none());
        assert!(label_for("").is_none());
    }

    #[test]
    fn every_tool_declares_an_object_input_schema() {
        // Required by the spec, and clients drive argument collection from it.
        for tool in definitions().as_array().unwrap() {
            assert_eq!(tool["inputSchema"]["type"], "object", "{}", tool["name"]);
        }
    }

    #[test]
    fn only_create_is_a_write() {
        assert!(is_write(CREATE_TASK));
        assert!(!is_write(READ_TASK));
        assert!(!is_write(FIND_TASKS));
    }
}
