//! Team grants through the real router (`plans/team-access.md` stage 8):
//! the teams iam attests reach the check, the two 403s, the trusted-header
//! path, and `list_projects`.
//!
//! **WHY THIS IS NOT LEFT TO `crate::project::tests::grants`.** Those tests
//! hand `Validator::check` its teams directly, so they stay green for an
//! `attest` that passed no teams at all. Here the teams come from a stub
//! `iam`'s `ResolveCredentialResponse.team_ids`, as in production.

use axum::body::{to_bytes, Body};
use axum::http::StatusCode;
use serde_json::{json, Value};
use tower::ServiceExt;

use super::{post, state_resolving_to, state_with, AppState};
use crate::attest::{AttestError, Attestation};
use crate::http::answer::attest_answer;
use crate::mcp::{headers, meta_keys, PROTOCOL_VERSION};
use crate::pb::yadgar::iam::v1::ResolveCredentialResponse;
use crate::pb::yadgar::project::v1::{DeclaredGrant, GrantLevel, ProjectStatus, RegisteredPath};
use crate::project::{Denied, Mode, OrgGrants, Reason, Registry, Validator};
use crate::test_accounts::{id, path};

const ADMINS: &str = "yadgar:team:administrators";
const READERS: &str = "yadgar:team:readers";

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

/// `yadgarhq` grants administrators read-write and readers read;
/// `yadgarhq/docs` and the archived `yadgarhq/old` inherit; `acme/x` is granted
/// to nobody; alice and bob each own a private row, bob's archived.
fn rows() -> Vec<RegisteredPath> {
    use GrantLevel::{Read, ReadWrite};
    const A: ProjectStatus = ProjectStatus::Active;
    vec![
        wire("yadgarhq", "", A, &[(ADMINS, ReadWrite), (READERS, Read)]),
        wire("yadgarhq/docs", "", A, &[]),
        wire("yadgarhq/old", "", ProjectStatus::Archived, &[]),
        wire("acme/x", "", A, &[]),
        wire("local/alice/notes", "alice", A, &[]),
        wire("local/bob/attic", "bob", ProjectStatus::Archived, &[]),
    ]
}

fn validating(state: &mut std::sync::Arc<AppState>, org_grants: OrgGrants) {
    std::sync::Arc::get_mut(state)
        .expect("the state is not shared yet")
        .projects = std::sync::Arc::new(
        Validator::new(
            Registry::loaded_from(rows()),
            Mode::Enforcing,
            tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        )
        .with_org_grants(org_grants),
    );
}

/// A gateway whose stub `iam` attests `user` as a member of `teams`.
async fn as_member(user: &str, teams: &[&str], org_grants: OrgGrants) -> std::sync::Arc<AppState> {
    let answer = ResolveCredentialResponse {
        user_id: id(user),
        team_ids: teams.iter().map(|t| (*t).to_string()).collect(),
        valid_for_seconds: 300,
        ..Default::default()
    };
    let (mut state, _) = state_resolving_to(answer, std::time::Duration::from_secs(60)).await;
    validating(&mut state, org_grants);
    state
}

/// One `tools/call`, with the project header only when `project` is `Some`.
async fn call(
    state: std::sync::Arc<AppState>,
    tool: &str,
    arguments: Value,
    project: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "_meta": {
                meta_keys::PROTOCOL_VERSION: PROTOCOL_VERSION,
                meta_keys::CLIENT_CAPABILITIES: {},
            },
            "name": tool,
            "arguments": arguments,
        }
    });
    let mut req = post()
        .header(headers::METHOD, "tools/call")
        .header(headers::NAME, tool)
        .header(axum::http::header::AUTHORIZATION, "Bearer a-token")
        .header("x-yadgar-user", id("max"));
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

fn reason(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(bytes)
        .ok()?
        .pointer("/error/data/reason")
        .cloned()
}

#[tokio::test]
async fn red_02_an_org_non_member_gets_the_private_non_owners_bytes() {
    let state = as_member("bob", &[], OrgGrants::Enforcing).await;
    let args = json!({ "title": "t" });
    let (org_status, org) = call(
        state.clone(),
        "create_task",
        args.clone(),
        Some("yadgarhq/docs"),
    )
    .await;
    let (private_status, private) =
        call(state, "create_task", args, Some("local/alice/notes")).await;
    assert_eq!(org_status, StatusCode::FORBIDDEN);
    assert_eq!(reason(&org), Some(json!("PROJECT_NOT_MEMBER")));
    assert_eq!(private_status, StatusCode::FORBIDDEN);
    assert_eq!(org, private, "byte-identical");
    // AND IT IS THE ENFORCING SENTENCE, which names the org remedy: the
    // counting sentence ("belongs to another account") would be byte-identical
    // across the two as well, and false for the org caller.
    let message = serde_json::from_slice::<Value>(&org).expect("JSON")["error"]["message"]
        .as_str()
        .expect("a message")
        .to_string();
    assert!(
        message.contains("team grant") && !message.contains("belongs to another account"),
        "{message}"
    );

    let answer = attest_answer(&AttestError::Project(Denied {
        reason: Reason::NotMember,
        prose: String::new(),
    }));
    assert_eq!(answer.label, "PERMISSION_DENIED");
}

#[tokio::test]
async fn red_02_counting_serves_the_same_org_non_member() {
    let state = as_member("bob", &[], OrgGrants::Counting).await;
    let (_, body) = call(state, "find_tasks", json!({}), Some("yadgarhq/docs")).await;
    assert_eq!(
        reason(&body),
        None,
        "served past attestation: {}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
async fn red_03_a_read_only_member_writing_is_a_403_read_only() {
    let state = as_member("rita", &[READERS], OrgGrants::Enforcing).await;
    let (status, body) = call(
        state.clone(),
        "create_task",
        json!({ "title": "t" }),
        Some("yadgarhq/docs"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(reason(&body), Some(json!("PROJECT_READ_ONLY")));
    let (_, body) = call(state, "find_tasks", json!({}), Some("yadgarhq/docs")).await;
    assert_eq!(reason(&body), None, "a read is served");

    let answer = attest_answer(&AttestError::Project(Denied {
        reason: Reason::ReadOnly,
        prose: String::new(),
    }));
    assert_eq!(
        (answer.status, answer.label),
        (StatusCode::FORBIDDEN, "PERMISSION_DENIED")
    );
}

/// The teams iam attests are what the check reads: the same credential with
/// the administrators team writes.
/// Red 8 through the router, the existence lens: under `orgGrants: enforcing`
/// a stranger (no team) gets ONE body for every registered org row it is not
/// granted — active or archived, project or deeper, a read or a write —
/// and that body is the private non-owner's. So the refusal tells it nothing
/// about the row's status, depth or class. (A path with NO registered row
/// answers an unregistered class instead; `plans/team-access.md` §8 accepts
/// that `check()` does not hide org-path existence.)
#[tokio::test]
async fn red_08_a_stranger_gets_one_body_for_every_ungranted_org_row() {
    let state = as_member("bob", &[], OrgGrants::Enforcing).await;
    let mut bodies = Vec::new();
    // Not the root itself: a namespace anchor is resolved through and never
    // worked in (ADR-0673), for every caller alike, before any grant is read.
    for claim in [
        "yadgarhq/docs",
        "yadgarhq/docs/deep/er",
        "yadgarhq/old",
        "acme/x",
        "local/alice/notes",
    ] {
        for (tool, args) in [
            ("find_tasks", json!({})),
            ("create_task", json!({ "title": "t" })),
        ] {
            let (status, body) = call(state.clone(), tool, args, Some(claim)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{tool} {claim}");
            bodies.push((format!("{tool} {claim}"), body));
        }
    }
    let (first_case, first) = &bodies[0];
    assert_eq!(reason(first), Some(json!("PROJECT_NOT_MEMBER")));
    for (case, body) in &bodies {
        assert_eq!(
            body,
            first,
            "{case} differs from {first_case}: {}",
            String::from_utf8_lossy(body)
        );
    }

    // A member is told more, and only about what it may reach: the reader's
    // write to the archived row is PROJECT_READ_ONLY, decided before the
    // archive state too.
    let reader = as_member("carol", &[READERS], OrgGrants::Enforcing).await;
    let (_, body) = call(
        reader,
        "create_task",
        json!({ "title": "t" }),
        Some("yadgarhq/old"),
    )
    .await;
    assert_eq!(reason(&body), Some(json!("PROJECT_READ_ONLY")));
}

#[tokio::test]
async fn the_teams_iam_attests_reach_the_check() {
    let state = as_member("max", &[ADMINS], OrgGrants::Enforcing).await;
    let (_, body) = call(
        state,
        "create_task",
        json!({ "title": "t" }),
        Some("yadgarhq/docs"),
    )
    .await;
    assert_eq!(reason(&body), None, "{}", String::from_utf8_lossy(&body));
}

#[tokio::test]
async fn red_13_a_trusted_header_caller_is_denied_every_org_row() {
    let mut state = state_with(Attestation::TrustedHeaders, Vec::new());
    validating(&mut state, OrgGrants::Enforcing);
    for project in ["yadgarhq/docs", "yadgarhq/old", "acme/x"] {
        let (status, body) = call(state.clone(), "find_tasks", json!({}), Some(project)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{project}");
        assert_eq!(
            reason(&body),
            Some(json!("PROJECT_NOT_MEMBER")),
            "{project}"
        );
    }
}

fn listed(bytes: &[u8]) -> Value {
    let body: Value = serde_json::from_slice(bytes).expect("JSON");
    body.pointer("/result/structuredContent/projects")
        .cloned()
        .unwrap_or_else(|| panic!("a listing: {body}"))
}

#[tokio::test]
async fn red_15_list_projects_needs_no_project_header_and_lists_only_what_the_caller_reaches() {
    for knob in [OrgGrants::Counting, OrgGrants::Enforcing] {
        let state = as_member("alice", &[READERS], knob).await;
        let (status, body) = call(state, "list_projects", json!({}), None).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            listed(&body),
            json!([
                { "path": path("local/alice/notes"), "status": "active", "kind": "private", "access": "owner" },
                { "path": "yadgarhq", "status": "active", "kind": "root", "access": "read" },
                { "path": "yadgarhq/docs", "status": "active", "kind": "project", "access": "read" },
                { "path": "yadgarhq/old", "status": "archived", "kind": "project", "access": "read" },
            ]),
            "{knob:?}: acme/x (ungranted) and bob's private row are absent"
        );
    }

    let state = as_member("bob", &[ADMINS], OrgGrants::Counting).await;
    let (_, body) = call(state, "list_projects", json!({}), Some("yadgarhq/docs")).await;
    let paths: Vec<Value> = listed(&body)
        .as_array()
        .expect("an array")
        .iter()
        .map(|e| json!([e["path"], e["status"], e["access"]]))
        .collect();
    assert_eq!(
        paths,
        vec![
            json!([path("local/bob/attic"), "archived", "owner"]),
            json!(["yadgarhq", "active", "readWrite"]),
            json!(["yadgarhq/docs", "active", "readWrite"]),
            json!(["yadgarhq/old", "archived", "readWrite"]),
        ],
        "a header sent anyway is ignored; alice's private row is absent"
    );
}

#[tokio::test]
async fn red_15_list_projects_refuses_an_argument_naming_another_user() {
    let state = as_member("alice", &[READERS], OrgGrants::Counting).await;
    for args in [json!({ "user_id": id("bob") }), json!({ "user": "bob" })] {
        let (status, body) = call(state.clone(), "list_projects", args.clone(), None).await;
        let body: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(status, StatusCode::OK, "a tool-level refusal: {args}");
        assert_eq!(
            body.pointer("/result/isError"),
            Some(&json!(true)),
            "{args}: {body}"
        );
        assert!(
            body.pointer("/result/structuredContent").is_none(),
            "{body}"
        );
    }
}

/// `list_projects` names no project, so it moves neither project counter.
#[tokio::test]
async fn list_projects_counts_nothing_on_the_project_series() {
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let state = as_member("alice", &[READERS], OrgGrants::Counting).await;
    let guard = metrics::set_default_local_recorder(&recorder);
    let _ = call(state, "list_projects", json!({}), None).await;
    drop(guard);
    let moved: Vec<String> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(key, ..)| key.key().name().to_string())
        .filter(|name| name.starts_with("yadgar_gateway_project_"))
        .collect();
    assert!(moved.is_empty(), "{moved:?}");
}
