//! A task as a CLIENT sees it: [`TaskView`], and the status spelling it uses.

use crate::pb::yadgar::task::v1::TaskStatus;

/// A status as a client reads it: the enum's name, lowercased, prefix stripped.
pub(super) fn status_name(status: i32) -> String {
    TaskStatus::try_from(status)
        .map(|s| {
            s.as_str_name()
                .trim_start_matches("TASK_STATUS_")
                .to_ascii_lowercase()
        })
        .unwrap_or_else(|_| "unspecified".to_string())
}

/// The JSON shape of a task as a CLIENT sees it.
///
/// Deliberately not `serde_json::to_value` over the generated protobuf type. The
/// generated struct carries wire-level shapes — `Option` around every message,
/// enums as `i32` — and serialising it directly would leak the transport into the
/// public JSON and change whenever the proto's internal representation did.
///
/// `body`, `tags` and `links` are `None` only in the SUMMARY shape, and are then
/// left out of the JSON rather than sent empty: an empty `body` would claim the
/// task has none.
#[derive(serde::Serialize)]
pub struct TaskView {
    id: String,
    number: u32,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    status: String,
    version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    /// References to other records; a `legacy_ref` given at creation is here.
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<String>>,
}

type ProtoTask = crate::pb::yadgar::task::v1::Task;

impl TaskView {
    /// Every field the response carries.
    pub fn full(task: Option<ProtoTask>) -> Self {
        let task = task.unwrap_or_default();
        let meta = task.meta.unwrap_or_default();
        Self {
            id: meta.id,
            number: task.number,
            title: task.title,
            body: Some(task.body),
            // The enum's own name, lowercased and stripped of its prefix — a
            // number would make the payload unreadable and would silently change
            // meaning if the enum were ever reordered.
            status: status_name(task.status),
            version: meta.version,
            tags: Some(task.tags),
            links: Some(task.links),
        }
    }

    /// The five fields a caller needs to choose a task, and nothing else.
    pub fn summary(task: Option<ProtoTask>) -> Self {
        Self {
            body: None,
            tags: None,
            links: None,
            ..Self::full(task)
        }
    }
}
