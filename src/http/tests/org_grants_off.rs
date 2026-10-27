//! `orgGrants: counting` (the shipped value) changes NO byte of any answer
//! this gateway gave before team access stage 8, except the one addition
//! `plans/team-access.md` §8 makes on purpose: `list_projects` in
//! `tools/list`.
//!
//! **THE GOLDEN FILE WAS CAPTURED ON `origin/main` 4795b01**, before this
//! change, by this file's matrix run against the same registry with no grant
//! field: both ADR-0841 modes, an owner, a stranger with no team, a reader
//! and an administrator, every claim class (granted root, inherited project
//! and deeper, archived org row, ungranted org row, unregistered org path,
//! unregistered root, own private row, another account's archived private
//! row, an unregistered foreign `local/` segment), a read and a write each,
//! and `tools/list`. Here the same registry carries grants and the callers
//! carry teams, which `counting` must only count.
//!
//! **A DELIBERATE CHANGE TO A TOOL DESCRIPTION OR A REFUSAL SENTENCE REDS
//! THIS TEST.** Recapture then: run this file's `golden_lines` on the new
//! `main` against the same registry without grants, and replace the golden
//! file in the same PR as the change, so the diff shows exactly what moved.
//! Recaptured once so far: yaadgaar #449 (ADR-1042) changed the `edit_task`
//! entry of the eight `tools/list` lines, and no other byte.
//!
//! Minted request ids are normalised to `<UUID>`, and the transport error a
//! served call meets at the unserved `task` to `<task unreachable>`; nothing
//! else is.

use axum::body::{to_bytes, Body};
use axum::http::StatusCode;
use serde_json::{json, Value};
use tower::ServiceExt;

use super::{post, state_resolving_to, AppState};
use crate::mcp::{headers, meta_keys, PROTOCOL_VERSION};
use crate::pb::yadgar::iam::v1::ResolveCredentialResponse;
use crate::pb::yadgar::project::v1::{DeclaredGrant, GrantLevel, ProjectStatus, RegisteredPath};
use crate::project::{Mode, OrgGrants, Registry, Validator};
use crate::test_accounts::{id, path};

/// Captured on `origin/main` 4795b01; see the module comment.
const GOLDEN: &str = include_str!("org_grants_off.golden");

fn wire(
    p: &str,
    owner: &str,
    status: ProjectStatus,
    grants: &[(&str, GrantLevel)],
) -> RegisteredPath {
    RegisteredPath {
        path: path(p),
        status: status as i32,
        aliases: Vec::new(),
        owner_user_id: if owner.is_empty() {
            String::new()
        } else {
            id(owner)
        },
        grants: grants
            .iter()
            .map(|(team, level)| DeclaredGrant {
                team_id: (*team).to_string(),
                level: *level as i32,
            })
            .collect(),
    }
}

/// The capture's registry, with grants: the root grants administrators
/// read-write and readers read. The grant on alice's private row cannot be
/// declared (a store fault) and must change nothing either.
fn golden_rows() -> Vec<RegisteredPath> {
    use GrantLevel::{Read, ReadWrite};
    const A: ProjectStatus = ProjectStatus::Active;
    vec![
        wire("yadgarhq", "", A, &[(ADMINS, ReadWrite), (READERS, Read)]),
        wire("yadgarhq/docs", "", A, &[]),
        wire("yadgarhq/old", "", ProjectStatus::Archived, &[]),
        wire("acme/x", "", A, &[]),
        wire("local/alice/notes", "alice", A, &[(ADMINS, ReadWrite)]),
        wire("local/bob/attic", "bob", ProjectStatus::Archived, &[]),
    ]
}

async fn golden_state(user: &str, teams: &[&str], mode: Mode) -> std::sync::Arc<AppState> {
    let answer = ResolveCredentialResponse {
        user_id: id(user),
        team_ids: teams.iter().map(|t| (*t).to_string()).collect(),
        valid_for_seconds: 300,
        ..Default::default()
    };
    let (mut state, _) = state_resolving_to(answer, std::time::Duration::from_secs(60)).await;
    std::sync::Arc::get_mut(&mut state)
        .expect("the state is not shared yet")
        .projects = std::sync::Arc::new(
        Validator::new(
            Registry::loaded_from(golden_rows()),
            mode,
            crate::upstream::Upstream::new(
                tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
                std::time::Duration::from_secs(30),
            ),
        )
        .with_org_grants(OrgGrants::Counting),
    );
    state
}
const ADMINS: &str = "yadgar:team:administrators";
const READERS: &str = "yadgar:team:readers";

/// The callers: an owner, a stranger with no team, a reader, an administrator.
const CALLERS: [(&str, &[&str]); 4] = [
    ("alice", &[]),
    ("bob", &[]),
    ("carol", &[READERS]),
    ("max", &[ADMINS]),
];

/// Every class of claim the validator tells apart.
const CLAIMS: [&str; 10] = [
    "yadgarhq",
    "yadgarhq/docs",
    "yadgarhq/docs/deep/er",
    "yadgarhq/old",
    "acme/x",
    "acme/nope",
    "nope-root",
    "local/alice/notes",
    "local/bob/attic",
    "local/0192f0a0-0000-7000-8000-0000000fffff/z",
];

/// One `tools/call` (or `tools/list` when `tool` is empty).
async fn golden_call(
    state: std::sync::Arc<AppState>,
    tool: &str,
    project: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let (method, params) = if tool.is_empty() {
        (
            "tools/list",
            json!({
                "_meta": {
                    meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
                    meta_keys::CLIENT_CAPABILITIES: {},
                },
            }),
        )
    } else {
        let arguments = if tool == "create_task" {
            json!({ "title": "t" })
        } else {
            json!({})
        };
        (
            "tools/call",
            json!({
                "_meta": {
                    meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
                    meta_keys::CLIENT_CAPABILITIES: {},
                },
                "name": tool,
                "arguments": arguments,
            }),
        )
    };
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let mut req = post()
        .header(headers::METHOD, method)
        .header(axum::http::header::AUTHORIZATION, "Bearer a-token");
    if !tool.is_empty() {
        req = req.header(headers::NAME, tool);
    }
    if let Some(project) = project {
        req = req.header("x-yadgar-project", path(project));
    }
    let resp = crate::http::router(state)
        .oneshot(req.body(Body::from(body.to_string())).expect("request"))
        .await
        .expect("the router answers");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read the body")
        .to_vec();
    (status, bytes)
}

/// Every 8-4-4-4-12 hex run (a minted request id) replaced by a fixed token,
/// so two runs compare by everything else.
fn normalised(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes).into_owned();
    let b = s.as_bytes();
    let shape = [8usize, 4, 4, 4, 12];
    let total = 36;
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if i + total <= b.len() && {
            let mut j = i;
            shape.iter().enumerate().all(|(k, n)| {
                let ok =
                    b[j..j + n].iter().all(u8::is_ascii_hexdigit) && (k == 4 || b[j + n] == b'-');
                j += n + 1;
                ok
            })
        } {
            out.push_str("<UUID>");
            i += total;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// A call that passed attestation reaches `task`, which nothing serves here,
/// so its content is the transport error's text, which is OS- and
/// dependency-specific and is not the gateway's answer. That one text is
/// replaced; every other byte (status, `_meta` stamp, `isError`, every
/// refusal body) is kept.
fn served_or(bytes: &[u8]) -> String {
    let body = normalised(bytes);
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&body) else {
        return body;
    };
    let Some(items) = v
        .pointer_mut("/result/content")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return body;
    };
    for item in items {
        let unreachable = item["text"]
            .as_str()
            .is_some_and(|t| t.contains("tcp connect error"));
        if unreachable {
            item["text"] = serde_json::Value::String("<task unreachable>".into());
        }
    }
    v.to_string()
}

/// The whole matrix, one line per case: `case<TAB>status<TAB>body`.
async fn golden_lines() -> Vec<String> {
    let mut lines = Vec::new();
    for mode in [Mode::Counting, Mode::Enforcing] {
        for (user, teams) in CALLERS {
            let state = golden_state(user, teams, mode).await;
            let (status, body) = golden_call(state, "", None).await;
            lines.push(format!(
                "{mode:?} {user} tools/list\t{}\t{}",
                status.as_u16(),
                normalised(&body)
            ));
            for claim in CLAIMS {
                for tool in ["find_tasks", "create_task"] {
                    let state = golden_state(user, teams, mode).await;
                    let (status, body) = golden_call(state, tool, Some(claim)).await;
                    lines.push(format!(
                        "{mode:?} {user} {tool} {claim}\t{}\t{}",
                        status.as_u16(),
                        served_or(&body)
                    ));
                }
            }
        }
    }
    lines
}

/// `tools/list`'s body with the `list_projects` entry taken out, re-rendered
/// the way the capture rendered it.
fn without_list_projects(body: &str) -> String {
    let mut v: Value = serde_json::from_str(body).expect("tools/list is JSON");
    v["result"]["tools"]
        .as_array_mut()
        .expect("a tools array")
        .retain(|t| t["name"] != json!("list_projects"));
    v.to_string()
}

#[tokio::test]
async fn counting_answers_every_pre_existing_call_byte_for_byte_as_main_did() {
    let golden: Vec<&str> = GOLDEN.lines().collect();
    let now = golden_lines().await;
    assert_eq!(now.len(), golden.len(), "the matrix itself changed");
    let mut lists = 0;
    for (now, then) in now.iter().zip(&golden) {
        let (case, rest) = now.split_once('\t').expect("case");
        let (then_case, then_rest) = then.split_once('\t').expect("case");
        assert_eq!(case, then_case);
        if case.ends_with("tools/list") {
            lists += 1;
            let (status, body) = rest.split_once('\t').expect("status");
            let (then_status, then_body) = then_rest.split_once('\t').expect("status");
            assert_eq!(status, then_status, "{case}");
            assert_ne!(body, then_body, "{case}: list_projects is the one addition");
            assert_eq!(
                without_list_projects(body),
                then_body,
                "{case}: tools/list differs from main ONLY by list_projects"
            );
            continue;
        }
        assert_eq!(rest, then_rest, "{case}");
    }
    assert_eq!(lists, 8);
}
