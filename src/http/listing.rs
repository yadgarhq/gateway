//! `list_projects`: the per-user project listing, served by the gateway
//! itself (ADR-0962 ruling 8, ADR-0963 (8), `plans/team-access.md` §8).
//!
//! Split out of [`super::dispatch`] for the file-size ceiling.
//! [`super::dispatch::tools_call`] routes the one tool here BEFORE it attests,
//! because this tool is the one that needs no `X-Yadgar-Project`.
//!
//! **NO NEW RPC.** The answer is computed from the registry this replica has
//! already loaded and the caller's attest: `user_id` for private rows, and
//! `team_ids` for org rows, both from `iam` only.
//!
//! **IT TAKES NO ARGUMENT THAT NAMES A USER.** The only argument is
//! `page_token`; anything else is refused as a tool-level error, so a request
//! naming another user cannot be read as one about them.

use super::call::*;
use super::gate::*;
use super::*;

use crate::project::Listed;

/// The most bytes one page of entries may serialise to (D56: pages by BYTES,
/// as the registry load is).
const PAGE_BYTES: usize = 64 * 1024; // ADR-0569-EXCEPTION(CB): a contract bound on payload size, not a tuning knob.

/// Attest, throttle, list, and answer — recording the call (D67).
pub(super) async fn list_projects(
    state: &Arc<AppState>,
    id: &Value,
    params: &Value,
    headers: &HeaderMap,
    (label, module): (&'static str, &'static str),
    request_id: String,
) -> Response {
    let attested = match attest::attest_unscoped(
        &state.attestation,
        &state.iam,
        &state.credentials,
        header(headers, axum::http::header::AUTHORIZATION.as_str()),
        Claimed {
            user_id: header(headers, "x-yadgar-user"),
            // IGNORED IF SENT: the listing names no project (ADR-0963 (8)).
            project_id: None,
            instance_id: header(headers, "x-yadgar-instance"),
            access: crate::project::Access::Read,
        },
        request_id.clone(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return attest_refusal(&e, id, label, tools::LIST_PROJECTS, request_id),
    };
    let scope = attested.scope;
    if let Some(refusal) = throttled(
        state,
        id,
        &scope,
        label,
        module,
        Kind::Read,
        &attested.limits,
    )
    .await
    {
        record_throttled(label, Kind::Read, observed(request_id, &scope));
        return refusal;
    }

    let call = Call::start(SERVICE, label, Kind::Read, observed(request_id, &scope));
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let outcome = listing(&state.projects, &scope, &args);
    let (status, rows, payload) = shape(id, outcome);
    let rendered = serde_json::to_string(&payload).unwrap_or_default();
    call.finish(Outcome {
        status,
        encoded_bytes: Some(rendered.len() as u64),
        payload: rendered.clone(),
        rows,
        ..Default::default()
    });
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        rendered,
    )
        .into_response()
}

/// The page of entries for this caller, or why there is none.
fn listing(
    projects: &crate::project::Validator,
    scope: &crate::pb::yadgar::common::v1::Scope,
    args: &Value,
) -> Result<tools::Output, tools::ToolError> {
    let after = page_token(args)?;
    let all = projects
        .listing(&scope.user_id, &scope.team_ids)
        .ok_or_else(|| {
            // ADR-0674's condition, and not the caller's fault: retryable.
            tools::ToolError::Upstream(tonic::Status::unavailable(
                "this gateway has not loaded the project registry yet, so it cannot list \
                 your projects. Retry.",
            ))
        })?;
    let (page, next) = paged(all, &after);
    let rows = u32::try_from(page.len()).unwrap_or(u32::MAX);
    let mut content = json!({ "projects": page });
    if let Some(next) = next {
        content["next_page_token"] = json!(next);
    }
    Ok(tools::Output { content, rows })
}

/// The `page_token`, and a refusal for any other argument.
fn page_token(args: &Value) -> Result<String, tools::ToolError> {
    let Some(map) = args.as_object() else {
        return Err(tools::ToolError::Invalid(
            "list_projects takes an object of arguments".into(),
        ));
    };
    // THE NAME IS NOT ECHOED: it is caller-written and may hold anything.
    if map.keys().any(|k| k.as_str() != "page_token") {
        return Err(tools::ToolError::Invalid(
            "list_projects lists the caller's own projects and takes no argument but \
             `page_token`; it cannot be asked about another user"
                .into(),
        ));
    }
    match map.get("page_token") {
        None => Ok(String::new()),
        Some(Value::String(t)) => Ok(t.clone()),
        Some(_) => Err(tools::ToolError::Invalid(
            "`page_token` must be a string".into(),
        )),
    }
}

/// The entries after `after` (folded path order) up to [`PAGE_BYTES`], and
/// the token of the next page when any remain. At least one entry per page,
/// so the walk always advances.
fn paged(all: Vec<Listed>, after: &str) -> (Vec<Listed>, Option<String>) {
    let mut rest = all
        .into_iter()
        .filter(|e| after.is_empty() || e.path.to_ascii_lowercase().as_str() > after)
        .peekable();
    let mut page = Vec::new();
    let mut bytes = 0;
    while let Some(next) = rest.peek() {
        let size = serde_json::to_string(next).map_or(0, |s| s.len());
        if !page.is_empty() && bytes + size > PAGE_BYTES {
            break;
        }
        bytes += size;
        page.extend(rest.next());
    }
    let token = rest
        .peek()
        .and(page.last())
        .map(|last: &Listed| last.path.to_ascii_lowercase());
    (page, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str) -> Listed {
        Listed {
            path: path.to_string(),
            status: "active",
            kind: "project",
            access: "read",
        }
    }

    /// Paging walks every entry exactly once and ends with no token.
    #[test]
    fn red_15_paging_by_bytes_walks_every_entry_once() {
        let pad = "p".repeat(200);
        let all: Vec<Listed> = (0..1000)
            .map(|n| entry(&format!("acme/{n:04}-{pad}")))
            .collect();
        let mut seen = Vec::new();
        let mut token = String::new();
        let mut pages = 0;
        loop {
            let (page, next) = paged(all.clone(), &token);
            assert!(!page.is_empty());
            seen.extend(page.into_iter().map(|e| e.path));
            pages += 1;
            match next {
                Some(t) => token = t,
                None => break,
            }
        }
        assert!(pages > 1, "a page is bounded by bytes");
        assert_eq!(seen, all.into_iter().map(|e| e.path).collect::<Vec<_>>());
    }
}
