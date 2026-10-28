//! The two tools that change a task that already exists: `edit_task` and
//! `transition_task`.
//!
//! **A SEAM, not a cut at a line count.** Both carry the same pair a create does
//! not — the task's `id` and the `expect_version` its compare-and-set checks —
//! and both are writes the module may refuse as stale. Everything they share
//! lives here; membership, labels and schemas stay with [`super::SERVED`].

use serde_json::{json, Value};
use sha2::Digest as _;

use super::{status_name, Output, ToolError};
use crate::pb::yadgar::common::v1::{Idempotency, Scope};
use crate::pb::yadgar::task::v1::TaskStatus;
use crate::pb::yadgar::taskapi::v1::{
    task_service_client::TaskServiceClient, BodyPatch, EditTaskRequest, TransitionTaskRequest,
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
pub(super) fn target(name: &str) -> Option<TaskStatus> {
    TARGETS
        .contains(&name)
        .then(|| TaskStatus::from_str_name(&format!("TASK_STATUS_{}", name.to_ascii_uppercase())))
        .flatten()
}

/// The task a write names, and the `expect_version` every write to an existing
/// task carries.
///
/// **EXACTLY ONE OF `id` OR `number`** (yaadgaar #397), as `read_task` already
/// takes. The pair is `(id, number)` in the proto's shape: an empty id or a
/// zero number is the absent one. `task` resolves a number in the caller's
/// exact project, never across projects; this gateway forwards the attested
/// scope and adds nothing to it.
///
/// **`expect_version` IS REQUIRED, not defaulted.** Upstream, 0 is a version no
/// row holds rather than a wildcard, so a missing one would come back as an
/// opaque FAILED_PRECONDITION instead of saying what the caller left out.
fn target_task(args: &Value) -> Result<(String, u32, u64), ToolError> {
    let id = optional_str(args, "id")?;
    let number = present(args, "number")
        .map(|v| {
            v.as_u64()
                .filter(|n| (1..=u64::from(u32::MAX)).contains(n))
                .map(|n| n as u32)
                .ok_or_else(|| ToolError::Invalid("`number` must be a positive integer".into()))
        })
        .transpose()?;
    let (id, number) = match (id, number) {
        (Some(id), None) => (id.to_string(), 0),
        (None, Some(n)) => (String::new(), n),
        (Some(_), Some(_)) => {
            return Err(ToolError::Invalid("give `id` or `number`, not both".into()))
        }
        (None, None) => return Err(ToolError::Invalid("`id` or `number` is required".into())),
    };
    let version = present(args, "expect_version")
        .ok_or_else(|| ToolError::Invalid("`expect_version` is required".into()))?
        .as_u64()
        .ok_or_else(|| {
            ToolError::Invalid("`expect_version` must be a non-negative integer".into())
        })?;
    Ok((id, number, version))
}

/// The digest `expect_body_sha256` names, checked against the body this
/// gateway RECEIVED (yaadgaar #394).
///
/// **CHECKED HERE AS WELL AS IN `task`, and the second check is not
/// redundant.** A model's tool call cut off mid-body reaches this gateway as a
/// well-formed call, and a `task` older than the field ignores it: without this
/// check, the cut body would be stored during any rollout in which this
/// gateway is newer than `task`, and reported as a success. `task` refuses the
/// same mismatch (ADR-0582's third test), and checks it for callers that do
/// not come through here.
///
/// Spelled as 64 lowercase hex characters, which is what `sha256sum` prints;
/// sent upstream as the 32 bytes they encode. The digest is over the exact
/// UTF-8 bytes of `body`: no trimming, and a trailing newline counts.
///
/// **IN PATCH MODE THE DIGEST IS FORWARDED UNCHECKED** (ADR-1008). It is then
/// over the PRE-edit body, which only `task` reads, so only `task` can compare
/// it. A `task` that predates patch mode refuses the whole call on its mask.
fn body_digest(args: &Value, body: Option<&str>, patching: bool) -> Result<Vec<u8>, ToolError> {
    let Some(hex) = optional_str(args, "expect_body_sha256")? else {
        return Ok(Vec::new());
    };
    let digest = decode_sha256_hex(hex).ok_or_else(|| {
        ToolError::Invalid("`expect_body_sha256` must be 64 lowercase hex characters".into())
    })?;
    if patching {
        return Ok(digest);
    }
    let body = body.ok_or_else(|| {
        ToolError::Invalid("`expect_body_sha256` was sent without a `body` to check".into())
    })?;
    if sha2::Sha256::digest(body.as_bytes()).as_slice() != digest.as_slice() {
        return Err(ToolError::Invalid(
            "the body does not match `expect_body_sha256`; it may have been cut off in \
             transit, so nothing was written. Re-send the whole body"
                .into(),
        ));
    }
    Ok(digest)
}

/// The `patch` argument, as the proto's `BodyPatch` (ADR-1008).
///
/// **SHAPE ONLY.** Each field must be present with its type, and
/// `expect_count` must fit 1..=u32::MAX, so a value the proto cannot carry is
/// refused rather than truncated. Whether `old` is empty, how long each side
/// is and how often `old` occurs are `task`'s rules, applied in one place so
/// that no caller path can disagree with another.
fn body_patch(args: &Value) -> Result<Option<BodyPatch>, ToolError> {
    let Some(patch) = present(args, "patch") else {
        return Ok(None);
    };
    let Some(fields) = patch.as_object() else {
        return Err(ToolError::Invalid(
            "`patch` must be an object with `old`, `new` and `expect_count`".into(),
        ));
    };
    // The schema says `additionalProperties: false`, and this holds the call
    // to it: a misspelt or invented key (`regex`, `count`) is refused rather
    // than ignored, so a caller never believes an option took effect.
    if let Some(extra) = fields
        .keys()
        .find(|k| !["old", "new", "expect_count", "expect_new_sha256"].contains(&k.as_str()))
    {
        return Err(ToolError::Invalid(format!(
            "`patch` takes only `old`, `new`, `expect_count` and `expect_new_sha256`, \
             not `{extra}`"
        )));
    }
    let side = |field: &str| -> Result<String, ToolError> {
        Ok(present(patch, field)
            .ok_or_else(|| ToolError::Invalid(format!("`patch.{field}` is required")))?
            .as_str()
            .ok_or_else(|| ToolError::Invalid(format!("`patch.{field}` must be a string")))?
            .to_string())
    };
    let old = side("old")?;
    let new = side("new")?;
    let expect_count = present(patch, "expect_count")
        .and_then(Value::as_u64)
        .filter(|n| (1..=u64::from(u32::MAX)).contains(n))
        .ok_or_else(|| {
            ToolError::Invalid(format!(
                "`patch.expect_count` must be an integer from 1 to {}",
                u32::MAX
            ))
        })? as u32;
    let expect_new_sha256 = new_digest(patch, &new)?;
    Ok(Some(BodyPatch {
        old,
        new,
        expect_count,
        expect_new_sha256,
    }))
}

/// The digest `patch.expect_new_sha256` names, checked against the `new` this
/// gateway RECEIVED (ADR-1042 rule 11, yaadgaar #449).
///
/// **CHECKED HERE AS WELL AS IN `task`**, for the reason [`body_digest`] is: a
/// `task` older than the field ignores it, because the guard is not selected
/// through the mask, so without this check a `new` cut off in transit would
/// be applied during any rollout in which this gateway is newer than `task`.
///
/// Spelled as 64 lowercase hex characters; sent upstream as the 32 bytes they
/// encode. The digest is over the exact UTF-8 bytes of `new`, with no
/// normalisation. Absent or null sends no bytes, which is no guard. The
/// mismatch message starts with the reason token `task` uses for the same
/// refusal, so a caller branches on one token whichever side refused.
fn new_digest(patch: &Value, new: &str) -> Result<Vec<u8>, ToolError> {
    let Some(hex) = present(patch, "expect_new_sha256") else {
        return Ok(Vec::new());
    };
    let digest = hex.as_str().and_then(decode_sha256_hex).ok_or_else(|| {
        ToolError::Invalid("`patch.expect_new_sha256` must be 64 lowercase hex characters".into())
    })?;
    if sha2::Sha256::digest(new.as_bytes()).as_slice() != digest.as_slice() {
        return Err(ToolError::Invalid(
            "PATCH_NEW_SHA256_MISMATCH: `patch.new` does not match \
             `patch.expect_new_sha256`; it may have been cut off in transit, so nothing \
             was written. Re-send the patch"
                .into(),
        ));
    }
    Ok(digest)
}

/// 64 lowercase hex characters as 32 bytes, or `None`.
fn decode_sha256_hex(hex: &str) -> Option<Vec<u8>> {
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    if hex.len() != 64 {
        return None;
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

/// An argument that was SENT. JSON `null` counts as not sent, as it does for
/// `create_task`: some clients fill every omitted optional argument with null.
pub(super) fn present<'a>(args: &'a Value, field: &str) -> Option<&'a Value> {
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
pub(super) fn optional_str<'a>(args: &'a Value, field: &str) -> Result<Option<&'a str>, ToolError> {
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
    task: &crate::upstream::TaskUpstream,
    deadline: yadgar_dial::Deadline,
    scope: Scope,
    args: &Value,
) -> Result<Output, ToolError> {
    if let Some(key) = STATUS_KEYS.into_iter().find(|k| present(args, k).is_some()) {
        return Err(ToolError::Invalid(format!(
            "`{key}` cannot be edited; change a task's status with transition_task"
        )));
    }
    // Unknown top-level keys are ignored, but this one would be ignored into a
    // false belief: the patch is applied with no guard while the caller thinks
    // `new` was checked (ADR-1042).
    if present(args, "expect_new_sha256").is_some() {
        return Err(ToolError::Invalid(
            "`expect_new_sha256` goes inside `patch`, beside the `new` it guards".into(),
        ));
    }
    let (id, number, expect_version) = target_task(args)?;
    let title = optional_str(args, "title")?;
    let body = optional_str(args, "body")?;
    let patch = body_patch(args)?;
    if body.is_some() && patch.is_some() {
        return Err(ToolError::Invalid(
            "send `body` or `patch`, not both".into(),
        ));
    }
    let expect_body_sha256 = body_digest(args, body, patch.is_some())?;

    // THE MASK IS WHAT THE CALLER SENT, by key presence. `task` reads an
    // EMPTY mask as "every editable field", so omitting it would write the
    // zero value of whatever the caller left out — blanking a body on a
    // title-only edit. An empty string that WAS sent is still written:
    // that is how a body is cleared.
    //
    // A PATCH IS NAMED `patch`, NEVER `body` (ADR-1008). `task` turns it into
    // the body write; a `task` that predates the field refuses the path, so
    // a rollout in which this gateway is newer cannot clear a body.
    let paths: Vec<String> = [
        ("title", title.is_some()),
        ("body", body.is_some()),
        ("patch", patch.is_some()),
    ]
    .into_iter()
    .filter(|(_, sent)| *sent)
    .map(|(p, _)| p.to_string())
    .collect();
    if paths.is_empty() {
        return Err(ToolError::Invalid(
            "send `title`, `body` or `patch` — there is nothing to edit".into(),
        ));
    }

    let request = EditTaskRequest {
        idempotency: Some(Idempotency {
            key: crate::idempotency_key(),
        }),
        scope: Some(scope),
        id,
        expect_version,
        title: title.unwrap_or_default().to_string(),
        body: body.unwrap_or_default().to_string(),
        update_mask: Some(prost_types::FieldMask { paths }),
        number,
        expect_body_sha256,
        patch,
    };
    let resp = super::bounded(task, deadline, request, |r| client.edit_task(r))
        .await?
        .into_inner();
    let meta = resp.meta.unwrap_or_default();
    Ok(Output {
        content: json!({ "id": meta.id, "version": meta.version }),
        rows: 1,
    })
}

/// The `edit_task` input schema. Here rather than in [`super::definition`],
/// beside the dispatch that reads the same arguments.
pub(super) fn edit_schema() -> Value {
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
                "description": "The version last read; the edit is refused if it moved",
            },
            "title": {
                "type": "string",
                "maxLength": super::create::TITLE_MAX,
                "description": "Short summary of the task, at most 128 characters (Unicode code points); put detail in the body",
            },
            "body": { "type": "string", "description": "New full description; empty clears it" },
            "patch": {
                "type": "object",
                "description": "Literal replace inside the stored body, instead of `body`",
                "properties": {
                    "old": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Exact text to find; no regex, no normalisation",
                    },
                    "new": { "type": "string", "description": "Replacement; empty deletes" },
                    "expect_count": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "How many times `old` occurs; refused otherwise",
                    },
                    "expect_new_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                        "description": "SHA-256 of the exact bytes of `new`; the \
                                        edit is refused if the `new` that arrives \
                                        does not match, so a cut-off `new` is \
                                        never applied",
                    },
                },
                "required": ["old", "new", "expect_count"],
                "additionalProperties": false,
            },
            "expect_body_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
                "description": "SHA-256 of the exact body bytes (sha256sum of the \
                                file you send); the edit is refused if the body \
                                that arrives does not match, so a cut-off body \
                                is never saved. With `patch`: SHA-256 of the \
                                pre-edit body as read",
            },
        },
        "required": ["expect_version"],
    })
}

/// Dispatch `transition_task`.
pub(super) async fn transition(
    client: &mut TaskServiceClient<crate::upstream::request_id::Carrying>,
    task: &crate::upstream::TaskUpstream,
    deadline: yadgar_dial::Deadline,
    scope: Scope,
    args: &Value,
) -> Result<Output, ToolError> {
    let (id, number, expect_version) = target_task(args)?;
    let to = target(required_str(args, "to")?)
        .ok_or_else(|| ToolError::Invalid(format!("`to` must be one of {}", TARGETS.join(", "))))?;

    let request = TransitionTaskRequest {
        idempotency: Some(Idempotency {
            key: crate::idempotency_key(),
        }),
        scope: Some(scope),
        id,
        expect_version,
        to: to as i32,
        number,
    };
    let resp = super::bounded(task, deadline, request, |r| client.transition_task(r))
        .await?
        .into_inner();
    let meta = resp.meta.unwrap_or_default();
    Ok(Output {
        // `from` as `task` reported it. Since task 0.8.6 it is the
        // recorded previous_status on both paths, the first call and a
        // replay. UNSPECIFIED means unknown: a replay of an old claim
        // that holds no previous_status. This gateway has no retry
        // layer toward modules, so it never replays a key itself.
        content: json!({
            "id": meta.id,
            "version": meta.version,
            "from": status_name(resp.from),
        }),
        rows: 1,
    })
}
