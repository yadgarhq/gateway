//! `create_task`: the request this gateway builds from the caller's arguments.
//!
//! A pure function for the reason [`super::find`] is one: there is no server
//! stub to fake, so the request BUILT is what a test can pin.

use serde_json::{json, Value};

use super::change::{optional_str, present};
use super::ToolError;
use crate::pb::yadgar::common::v1::{Idempotency, Scope};
use crate::pb::yadgar::taskapi::v1::CreateTaskRequest;

/// The longest key `task-db` can hold: `task_write.idem_key` is
/// `VARCHAR(255)`. The proto states no format for `Idempotency.key`, so this
/// bound is the STORE's, and a longer key refused here is one that would
/// otherwise reach the column and fail as a storage error.
pub(super) const IDEMPOTENCY_KEY_MAX: usize = 255;

/// A caller's idempotency key, or the one this gateway mints.
///
/// **AN EMPTY KEY IS REFUSED, NOT TREATED AS ABSENT.** `task-db` reads an empty
/// key as "this caller does not participate" and dedupes nothing, so a caller
/// that sent `""` believing it was protected would be silently unprotected.
///
/// **PRINTABLE ASCII ONLY, NO SPACES.** The column's collation compares
/// strings, not bytes; restricting the alphabet keeps accents, trailing blanks
/// and control characters from making two different-looking keys one key. Case
/// may still fold under that collation — a collision it causes is either a
/// replay of the same payload or a refusal of a different one, never a wrong
/// answer.
fn idempotency_key(args: &Value, mint: impl FnOnce() -> String) -> Result<String, ToolError> {
    let Some(key) = optional_str(args, "idempotency_key")? else {
        return Ok(mint());
    };
    if key.is_empty()
        || key.len() > IDEMPOTENCY_KEY_MAX
        || !key.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(ToolError::Invalid(format!(
            "`idempotency_key` must be 1 to {IDEMPOTENCY_KEY_MAX} printable ASCII characters \
             with no spaces"
        )));
    }
    Ok(key.to_string())
}

/// The legacy reference, stored as the task's only link.
///
/// **VERBATIM.** `Task.links` is the proto's field for references to other
/// records ("URNs — an ADR, a wiki page, a parent task"), and no decision names
/// a URN scheme for a legacy ledger id — so this gateway invents no prefix. A
/// reader gets back exactly the string the creator sent, in `links`.
fn links(args: &Value) -> Result<Vec<String>, ToolError> {
    match optional_str(args, "legacy_ref")? {
        None => Ok(Vec::new()),
        Some(r) if r.trim().is_empty() => Err(ToolError::Invalid(
            "`legacy_ref` must not be empty; omit it instead".into(),
        )),
        Some(r) => Ok(vec![r.to_string()]),
    }
}

/// The upstream request, or the caller's mistake. `mint` is called only when
/// the caller sent no key.
pub(super) fn request(
    scope: Scope,
    args: &Value,
    mint: impl FnOnce() -> String,
) -> Result<CreateTaskRequest, ToolError> {
    let title = present(args, "title")
        .and_then(Value::as_str)
        .ok_or_else(|| ToolError::Invalid("`title` is required".into()))?;
    Ok(CreateTaskRequest {
        idempotency: Some(Idempotency {
            key: idempotency_key(args, mint)?,
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
        links: links(args)?,
    })
}

/// `create_task`'s `inputSchema`, kept beside the parsing that enforces it so the two
/// change together. The catalogue entry itself is [`super::definition`]'s.
pub(super) fn schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "title": { "type": "string", "description": "Short summary of the task" },
            "body": { "type": "string", "description": "Full description" },
            "tags": { "type": "array", "items": { "type": "string" } },
            "legacy_ref": {
                "type": "string",
                "minLength": 1,
                "description": "A reference to this task in another tracker, \
                                e.g. a legacy ledger id. Stored verbatim as the \
                                task's link; returned in `links`",
            },
            "idempotency_key": {
                "type": "string",
                "minLength": 1,
                "maxLength": IDEMPOTENCY_KEY_MAX,
                "pattern": "^[!-~]+$",
                "description": "Makes a retry safe: the same key with the same \
                                arguments returns the first call's task; the same \
                                key with different arguments is refused. Scoped \
                                to the caller and project. Omit it and the \
                                gateway uses a fresh key per call",
            },
        },
        "required": ["title"],
    })
}
