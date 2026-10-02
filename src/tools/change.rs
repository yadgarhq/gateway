//! The two tools that change a task that already exists: `edit_task` and
//! `transition_task`.
//!
//! **A SEAM, not a cut at a line count.** Both carry the same pair a create does
//! not — the task's `id` and the `expect_version` its compare-and-set checks —
//! and both are writes the module may refuse as stale. Everything they share
//! lives here; membership, labels and schemas stay with [`super::SERVED`].

use serde_json::{json, Value};

use super::{status_name, Output, ToolError};
use crate::pb::yadgar::common::v1::{Idempotency, Scope};
use crate::pb::yadgar::task::v1::TaskStatus;
use crate::pb::yadgar::taskapi::v1::{
    task_service_client::TaskServiceClient, EditTaskRequest, TransitionTaskRequest,
};

/// The statuses a transition may name, in the spelling [`super::TaskView`] emits.
///
/// `unspecified` is absent: it is the proto's zero value and no task can be
/// moved to it. Which of these is legal FROM a given status is `task`'s rule,
/// not this gateway's, so the list is every target and nothing more.
pub(super) const TARGETS: [&str; 5] = ["open", "in_progress", "blocked", "done", "dropped"];

/// The tool's spelling of a status, to the proto's.
///
/// Through [`TARGETS`] first, so the only spellings accepted are the ones the
/// schema advertises — `from_str_name` alone would also take `unspecified`.
fn target(name: &str) -> Option<TaskStatus> {
    TARGETS
        .contains(&name)
        .then(|| TaskStatus::from_str_name(&format!("TASK_STATUS_{}", name.to_ascii_uppercase())))
        .flatten()
}

/// The `id` and `expect_version` every write to an existing task carries.
///
/// **`expect_version` IS REQUIRED, not defaulted.** Upstream, 0 is a version no
/// row holds rather than a wildcard, so a missing one would come back as an
/// opaque FAILED_PRECONDITION instead of saying what the caller left out.
fn target_task(args: &Value) -> Result<(String, u64), ToolError> {
    let id = required_str(args, "id")?;
    let version = present(args, "expect_version")
        .ok_or_else(|| ToolError::Invalid("`expect_version` is required".into()))?
        .as_u64()
        .ok_or_else(|| {
            ToolError::Invalid("`expect_version` must be a non-negative integer".into())
        })?;
    Ok((id.to_string(), version))
}

/// An argument that was SENT. JSON `null` counts as not sent, as it does for
/// `create_task`: some clients fill every omitted optional argument with null.
fn present<'a>(args: &'a Value, field: &str) -> Option<&'a Value> {
    args.get(field).filter(|v| !v.is_null())
}

/// A required string argument. Missing and mistyped get different answers, so
/// a caller is not sent hunting for a spelling mistake it did not make.
fn required_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, ToolError> {
    present(args, field)
        .ok_or_else(|| ToolError::Invalid(format!("`{field}` is required")))?
        .as_str()
        .ok_or_else(|| ToolError::Invalid(format!("`{field}` must be a string")))
}

/// An optional string argument: absent (or null), or a string. Any other type
/// is refused rather than read as absent, because for `edit_task` absent means
/// "leave it". **Null is absent, never "clear"** — `""` is how a field is
/// cleared, so a null can never wipe a field the caller did not mean to touch.
fn optional_str<'a>(args: &'a Value, field: &str) -> Result<Option<&'a str>, ToolError> {
    present(args, field)
        .map(|v| {
            v.as_str()
                .ok_or_else(|| ToolError::Invalid(format!("`{field}` must be a string")))
        })
        .transpose()
}

/// Keys an edit REFUSES, because a caller sending one means to change status.
///
/// Every other unknown key is ignored, as `create_task` ignores them. These two
/// are the exception because ignoring them turns a status change into a
/// title-only SUCCESS, and the caller would believe the status moved.
const STATUS_KEYS: [&str; 2] = ["status", "to"];

/// Dispatch `edit_task`.
pub(super) async fn edit(
    client: &mut TaskServiceClient<crate::upstream::request_id::Carrying>,
    scope: Scope,
    args: &Value,
) -> Result<Output, ToolError> {
    if let Some(key) = STATUS_KEYS.into_iter().find(|k| present(args, k).is_some()) {
        return Err(ToolError::Invalid(format!(
            "`{key}` cannot be edited; change a task's status with transition_task"
        )));
    }
    let (id, expect_version) = target_task(args)?;
    let title = optional_str(args, "title")?;
    let body = optional_str(args, "body")?;

    // THE MASK IS WHAT THE CALLER SENT, by key presence. `task` reads an
    // EMPTY mask as "every editable field", so omitting it would write the
    // zero value of whatever the caller left out — blanking a body on a
    // title-only edit. An empty string that WAS sent is still written:
    // that is how a body is cleared.
    let paths: Vec<String> = [("title", title), ("body", body)]
        .into_iter()
        .filter(|(_, v)| v.is_some())
        .map(|(p, _)| p.to_string())
        .collect();
    if paths.is_empty() {
        return Err(ToolError::Invalid(
            "send `title`, `body`, or both — there is nothing to edit".into(),
        ));
    }

    let resp = client
        .edit_task(EditTaskRequest {
            idempotency: Some(Idempotency {
                key: crate::idempotency_key(),
            }),
            scope: Some(scope),
            id,
            expect_version,
            title: title.unwrap_or_default().to_string(),
            body: body.unwrap_or_default().to_string(),
            update_mask: Some(prost_types::FieldMask { paths }),
        })
        .await?
        .into_inner();
    let meta = resp.meta.unwrap_or_default();
    Ok(Output {
        content: json!({ "id": meta.id, "version": meta.version }),
        rows: 1,
    })
}

/// Dispatch `transition_task`.
pub(super) async fn transition(
    client: &mut TaskServiceClient<crate::upstream::request_id::Carrying>,
    scope: Scope,
    args: &Value,
) -> Result<Output, ToolError> {
    let (id, expect_version) = target_task(args)?;
    let to = target(required_str(args, "to")?)
        .ok_or_else(|| ToolError::Invalid(format!("`to` must be one of {}", TARGETS.join(", "))))?;

    let resp = client
        .transition_task(TransitionTaskRequest {
            idempotency: Some(Idempotency {
                key: crate::idempotency_key(),
            }),
            scope: Some(scope),
            id,
            expect_version,
            to: to as i32,
        })
        .await?
        .into_inner();
    let meta = resp.meta.unwrap_or_default();
    Ok(Output {
        // `from` as `task` reported it. On a replay of an applied
        // transition it equals the target — a known gap in `task`, not
        // something this gateway can correct. This gateway has no retry
        // layer toward modules, so it never replays a key itself.
        content: json!({
            "id": meta.id,
            "version": meta.version,
            "from": status_name(resp.from),
        }),
        rows: 1,
    })
}
