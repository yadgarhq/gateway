//! What bounds `/auth/login` and `/auth/enrol` (task 497, ADR-0491).
//!
//! # The assertion that matters, and the one that does not
//!
//! "A second request was throttled" passes against an implementation keyed on the
//! LEFTMOST `X-Forwarded-For` entry — right up until an attacker rotates that
//! entry, which costs them one string per request. `limit.rs` already records
//! that residual for user ids: a caller rotating its key "still mints one bucket
//! per id and is still not throttled". A limiter keyed on something the caller
//! writes has exactly that defect and looks exactly like a working one.
//!
//! So the load-bearing test here sends requests whose forged leftmost entries are
//! ALL DIFFERENT and whose trusted rightmost entry is the same, and asserts they
//! shared one bucket. Against the naive implementation every request mints a
//! fresh bucket and nothing is ever refused.
//!
//! # No Valkey, on purpose
//!
//! `throttle_http.rs` needs a real one; CI has supplied one since `yadgarhq/actions`
//! PR #30 (`b92944f`), so that file now runs there too. This file points
//! the limiter at a closed port, so every call takes D74's degraded path and is
//! held to this replica's own in-process floor — which is deterministic, needs no
//! server, and exercises the same `guard` wiring. What is measured is WHICH
//! BUCKET a request lands in, and that is decided in `source.rs` and `http.rs`
//! before the store is reached at all.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;
use yadgar_gateway::attest::{Attestation, Credentials};
use yadgar_gateway::http::{router, AppState, CredentialLimits};
use yadgar_gateway::limit::{Bucket, Limiter, Limits};
use yadgar_gateway::source::TrustBoundary;

/// The socket address every request in this file arrives on.
///
/// ONE PEER FOR EVERY TEST, because that is the situation behind an ingress and
/// it is the situation the interesting failures need: if the peer were what
/// distinguished callers, none of the assertions below would mean anything.
const PROXY: &str = "10.244.3.11:41000";

/// What a single trusted proxy appends. RFC 5737 documentation space, so it
/// cannot have come from the implementation.
const REAL_CLIENT: &str = "198.51.100.9";

/// The bootstrap token this file's gateway holds. A literal, so nothing here
/// depends on how a deployment mints one.
const BOOTSTRAP: &str = "a-bootstrap-token-for-this-file";
const OTHER_CLIENT: &str = "198.51.100.42";

/// A bucket holding exactly one token, refilling slowly enough that a test never
/// waits for it.
fn one_token() -> Bucket {
    Bucket {
        rate: 0.05,
        burst: 1.0,
    }
}

/// The two unauthenticated endpoints' buckets, wide enough not to interfere.
fn wide() -> CredentialLimits {
    CredentialLimits {
        attributed: Bucket {
            rate: 600.0,
            burst: 600.0,
        },
        unattributed: Bucket {
            rate: 600.0,
            burst: 600.0,
        },
    }
}

/// A state whose ADMIN buckets are wide, for every test that is not about them.
fn state(trust: TrustBoundary, credential_limits: CredentialLimits) -> Arc<AppState> {
    state_with_admin(trust, credential_limits, wide())
}

fn state_with_admin(
    trust: TrustBoundary,
    credential_limits: CredentialLimits,
    admin_limits: CredentialLimits,
) -> Arc<AppState> {
    Arc::new(AppState {
        attestation: Attestation::Iam,
        task: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        // UNREACHABLE, AND REACHED ON PURPOSE. A request that spends a token goes
        // on to `iam` and comes back 503; a request that is throttled never gets
        // there and comes back 429. The two are therefore distinguishable by
        // status alone, with no stub server to keep in step.
        iam: tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        credentials: Credentials::new(Duration::from_secs(30)),
        limiter: Limiter::new(
            // Nothing listens on port 1, so every call degrades onto the local
            // floor. See this file's module comment.
            "127.0.0.1:1",
            None,
            Limits::parse("task.write=600:600", "600:600").expect("the limits parse"),
            Duration::from_millis(200),
            // ONE, so the floor is the configured bucket rather than a fraction
            // of it: the floor divides by `max_replicas`, and a divisor here
            // would make what these tests assert depend on arithmetic they are
            // not about.
            1,
        )
        .expect("the limiter opens"),
        allowed_origins: Vec::new(),
        trust,
        credential_limits,
        admin_limits,
        // CONFIGURED, so the bootstrap tests below reach the THROTTLE rather than
        // stopping at the disabled-path refusal. `guard` runs before any
        // authority is judged, so a throttled request is a 429 either way — but a
        // test that could not tell the two apart would be measuring nothing.
        bootstrap: yadgar_gateway::admin::BootstrapToken::from_secret(BOOTSTRAP),
        // NOT WHAT THIS FILE MEASURES — the shipped value, unused by any assertion here.
        tools_poll_interval: std::time::Duration::from_secs(600),
    })
}

/// One `POST /auth/login` from [`PROXY`], carrying `forwarded` if given.
async fn login(state: Arc<AppState>, forwarded: Option<&str>) -> StatusCode {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/auth/login")
        .header("content-type", "application/json");
    if let Some(value) = forwarded {
        request = request.header("x-forwarded-for", value);
    }
    let mut request = request
        .body(Body::from(r#"{"username":"ada","password":"hunter2"}"#))
        .expect("the request builds");
    // WHAT `into_make_service_with_connect_info` DOES IN THE REAL SERVER. `oneshot`
    // drives the router directly and populates nothing, so the peer address is
    // inserted here — the same extension, in the same place `PeerAddr` reads it.
    request.extensions_mut().insert(ConnectInfo(
        PROXY
            .parse::<SocketAddr>()
            .expect("the peer address parses"),
    ));
    router(state)
        .oneshot(request)
        .await
        .expect("the router answers")
        .status()
}

// ---- The test the naive implementation fails --------------------------------

#[tokio::test]
async fn forged_leftmost_entries_all_land_in_the_trusted_hop_s_one_bucket() {
    let limits = CredentialLimits {
        attributed: one_token(),
        // WIDE, so that if the request were mis-classified as unattributable it
        // would be ALLOWED rather than throttled — and this test would fail by
        // seeing a 503 where it expects a 429, rather than passing for the wrong
        // reason.
        unattributed: Bucket {
            rate: 600.0,
            burst: 600.0,
        },
    };
    let state = state(TrustBoundary::Hops(1), limits);

    // Both requests come from the same real client through the same single
    // trusted proxy: the RIGHTMOST entry is identical. The leftmost entries are
    // the attacker's, and they differ — which is the whole cost of evading a
    // limiter keyed on the value the caller wrote.
    let first = login(
        Arc::clone(&state),
        Some(&format!("203.0.113.1, {REAL_CLIENT}")),
    )
    .await;
    let second = login(
        Arc::clone(&state),
        Some(&format!("203.0.113.2, {REAL_CLIENT}")),
    )
    .await;

    assert_eq!(
        first,
        StatusCode::SERVICE_UNAVAILABLE,
        "the first request spends the only token and reaches an unreachable iam"
    );
    assert_eq!(
        second,
        StatusCode::TOO_MANY_REQUESTS,
        "the second request must spend from the SAME bucket as the first. A limiter keyed on \
         the leftmost X-Forwarded-For entry mints a fresh bucket here and allows it, which is \
         the defect this test exists to catch"
    );
}

#[tokio::test]
async fn two_genuinely_different_clients_do_not_share_a_bucket() {
    // The other half of the pair. Without this the test above is satisfied by an
    // implementation that throttles everything, which bounds login by breaking it.
    let state = state(
        TrustBoundary::Hops(1),
        CredentialLimits {
            attributed: one_token(),
            unattributed: Bucket {
                rate: 600.0,
                burst: 600.0,
            },
        },
    );

    let first = login(
        Arc::clone(&state),
        Some(&format!("203.0.113.1, {REAL_CLIENT}")),
    )
    .await;
    let second = login(
        Arc::clone(&state),
        Some(&format!("203.0.113.1, {OTHER_CLIENT}")),
    )
    .await;

    assert_eq!(first, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        second,
        StatusCode::SERVICE_UNAVAILABLE,
        "a different client, appended by the same trusted proxy, has its own bucket"
    );
}

// ---- The refusing default, at the HTTP seam ---------------------------------

#[tokio::test]
async fn an_undeclared_boundary_keys_on_the_hop_rather_than_the_header() {
    // NO TRUST BOUNDARY. Whatever `X-Forwarded-For` says, this deployment cannot
    // attribute the request — so the two calls below key on the peer, which is
    // the same for both, and share a bucket even though their headers name
    // different clients.
    let state = state(
        TrustBoundary::Undeclared,
        CredentialLimits {
            // WIDE, so a request wrongly treated as attributable would be allowed
            // and this test would fail rather than pass by accident.
            attributed: Bucket {
                rate: 600.0,
                burst: 600.0,
            },
            unattributed: one_token(),
        },
    );

    let first = login(Arc::clone(&state), Some(REAL_CLIENT)).await;
    let second = login(Arc::clone(&state), Some(OTHER_CLIENT)).await;

    assert_eq!(first, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        second,
        StatusCode::TOO_MANY_REQUESTS,
        "with no declared boundary the header names nobody this gateway believes, so both \
         calls key on the hop it actually saw"
    );
}

#[tokio::test]
async fn stripping_the_forwarded_header_does_not_buy_an_unthrottled_login() {
    // A declared boundary and NO header at all. Falling back to "unknown, so no
    // key, so no bucket" would make the limiter optional at the caller's choice.
    let state = state(
        TrustBoundary::Hops(1),
        CredentialLimits {
            attributed: Bucket {
                rate: 600.0,
                burst: 600.0,
            },
            unattributed: one_token(),
        },
    );

    let first = login(Arc::clone(&state), None).await;
    let second = login(Arc::clone(&state), None).await;

    assert_eq!(first, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        second,
        StatusCode::TOO_MANY_REQUESTS,
        "a request that cannot be attributed is still bounded, on the hop this process saw"
    );
}

#[tokio::test]
async fn enrol_is_bounded_by_its_own_bucket_and_not_login_s() {
    // The two endpoints pass the same guard, and `endpoint` is part of the key —
    // so emptying one must not refuse the other. Otherwise a person redeeming an
    // enrolment is locked out by whoever last mistyped a password from the same
    // address.
    let state = state(
        TrustBoundary::Hops(1),
        CredentialLimits {
            attributed: one_token(),
            unattributed: Bucket {
                rate: 600.0,
                burst: 600.0,
            },
        },
    );
    let forwarded = format!("203.0.113.1, {REAL_CLIENT}");

    assert_eq!(
        login(Arc::clone(&state), Some(&forwarded)).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        login(Arc::clone(&state), Some(&forwarded)).await,
        StatusCode::TOO_MANY_REQUESTS,
        "login's bucket is now empty"
    );

    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/auth/enrol")
        .header("content-type", "application/json")
        .header("x-forwarded-for", &forwarded)
        .body(Body::from(r#"{"secret":"s","password":"p"}"#))
        .expect("the request builds");
    request.extensions_mut().insert(ConnectInfo(
        PROXY
            .parse::<SocketAddr>()
            .expect("the peer address parses"),
    ));
    let enrol = router(Arc::clone(&state))
        .oneshot(request)
        .await
        .expect("the router answers")
        .status();
    assert_ne!(
        enrol,
        StatusCode::TOO_MANY_REQUESTS,
        "enrolment has its own bucket; login's empty one must not refuse it"
    );
}

// ---- The browser vector -----------------------------------------------------

#[tokio::test]
async fn a_cross_origin_browser_request_is_refused_before_it_costs_iam_anything() {
    // WHY THIS IS HERE AND NOT IN AN ORIGIN TEST FILE. What an attacker's page
    // buys is not volume — curl gives them that — it is SOURCE-ADDRESS DIVERSITY:
    // every visitor becomes a distinct address, and a limiter keyed on an address
    // is worth nothing against that. The bucket above depends on this refusal.
    let state = state(
        TrustBoundary::Hops(1),
        CredentialLimits {
            attributed: Bucket {
                rate: 600.0,
                burst: 600.0,
            },
            unattributed: Bucket {
                rate: 600.0,
                burst: 600.0,
            },
        },
    );
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/auth/login")
        // A CORS *simple* request: `text/plain` takes no preflight, and axum's
        // `Bytes` extractor checks no content type, so the body is parsed anyway.
        .header("content-type", "text/plain")
        .header("origin", "https://attacker.example")
        .header("x-forwarded-for", format!("203.0.113.1, {REAL_CLIENT}"))
        .body(Body::from(r#"{"username":"ada","password":"hunter2"}"#))
        .expect("the request builds");
    request.extensions_mut().insert(ConnectInfo(
        PROXY
            .parse::<SocketAddr>()
            .expect("the peer address parses"),
    ));
    let status = router(state)
        .oneshot(request)
        .await
        .expect("the router answers")
        .status();
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an unknown browser origin must not reach iam. A 503 here means the RPC fired and iam \
         spent a full Argon2id verification for a page the caller never visited"
    );
}

#[tokio::test]
async fn a_client_that_sends_no_origin_is_unaffected() {
    // The cost of the check above, measured rather than asserted in prose: a
    // non-browser client sends no `Origin`, and an absent one is allowed. Every
    // other test in this file sends none, so this states the property directly.
    let state = state(
        TrustBoundary::Hops(1),
        CredentialLimits {
            attributed: Bucket {
                rate: 600.0,
                burst: 600.0,
            },
            unattributed: Bucket {
                rate: 600.0,
                burst: 600.0,
            },
        },
    );
    assert_eq!(
        login(state, Some(&format!("203.0.113.1, {REAL_CLIENT}"))).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "no Origin means a non-browser client, which reaches iam as it always did"
    );
}

// ---- The administrative surface (ADR-0492, D73, ledger 638) -----------------
//
// §3.2: an `/admin` handler inherits NOTHING. The body limit is the gateway's
// one shared layer and everything else — the `Origin` check, the throttle — is
// an explicit call inside a handler. These two files' worth of shapes are copied
// onto the admin paths because the estate has already shipped the omission once,
// on `/auth/*`, and `guard`'s own comment records it.

/// One POST to an `/admin` path from [`PROXY`], carrying `forwarded` if given.
async fn admin(
    state: Arc<AppState>,
    path: &str,
    body: &str,
    origin: Option<&str>,
    forwarded: Option<&str>,
) -> StatusCode {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .header("x-yadgar-bootstrap-token", BOOTSTRAP);
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    if let Some(forwarded) = forwarded {
        request = request.header("x-forwarded-for", forwarded);
    }
    let mut request = request
        .body(Body::from(body.to_string()))
        .expect("the request builds");
    request.extensions_mut().insert(ConnectInfo(
        PROXY
            .parse::<SocketAddr>()
            .expect("the peer address parses"),
    ));
    router(state)
        .oneshot(request)
        .await
        .expect("the router answers")
        .status()
}

/// A body the bootstrap token is granted: create an ADMINISTRATOR.
const CREATE_ADMIN: &str = r#"{"external_id":"ada","display_name":"Ada","is_admin":true}"#;

#[tokio::test]
async fn the_admin_surface_is_bounded_by_its_own_bucket_and_not_login_s() {
    // §3.2: "Sharing them would make an administrator's ordinary work consume a
    // bucket sized for password attempts, and would make a bootstrap-token brute
    // force spend a bucket an operator reads as 'login pressure'."
    //
    // Both directions are asserted, because either alone passes against a shared
    // bucket in one of the two orders.
    let state = state_with_admin(
        TrustBoundary::Hops(1),
        CredentialLimits {
            attributed: one_token(),
            unattributed: Bucket {
                rate: 600.0,
                burst: 600.0,
            },
        },
        CredentialLimits {
            attributed: one_token(),
            unattributed: Bucket {
                rate: 600.0,
                burst: 600.0,
            },
        },
    );
    let forwarded = format!("203.0.113.1, {REAL_CLIENT}");

    // Empty LOGIN's bucket.
    assert_eq!(
        login(Arc::clone(&state), Some(&forwarded)).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        login(Arc::clone(&state), Some(&forwarded)).await,
        StatusCode::TOO_MANY_REQUESTS,
        "login's bucket is now empty"
    );

    // The admin path still has its own token.
    let first = admin(
        Arc::clone(&state),
        "/admin/create-user",
        CREATE_ADMIN,
        None,
        Some(&forwarded),
    )
    .await;
    assert_ne!(
        first,
        StatusCode::TOO_MANY_REQUESTS,
        "the admin surface has its own bucket; login's empty one must not refuse it"
    );

    // AND IT IS BOUNDED. Without this the test passes against an admin path with
    // no throttle at all, which is exactly the omission §3.2 exists to prevent.
    let second = admin(
        Arc::clone(&state),
        "/admin/create-user",
        CREATE_ADMIN,
        None,
        Some(&forwarded),
    )
    .await;
    assert_eq!(
        second,
        StatusCode::TOO_MANY_REQUESTS,
        "the admin surface must call guard(): an unthrottled one is a bootstrap-token brute force \
         with no bound at all"
    );
}

#[tokio::test]
async fn each_admin_verb_has_its_own_throttle_key() {
    // §3.2 again, one level down: `guard` passes `endpoint` into the bucket key,
    // so three labels are three buckets. A shared key would let an administrator
    // creating users be refused an enrolment they have spent nothing on.
    let state = state_with_admin(
        TrustBoundary::Hops(1),
        wide(),
        CredentialLimits {
            attributed: one_token(),
            unattributed: Bucket {
                rate: 600.0,
                burst: 600.0,
            },
        },
    );
    let forwarded = format!("203.0.113.1, {REAL_CLIENT}");

    assert_ne!(
        admin(
            Arc::clone(&state),
            "/admin/create-user",
            CREATE_ADMIN,
            None,
            Some(&forwarded)
        )
        .await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        admin(
            Arc::clone(&state),
            "/admin/create-user",
            CREATE_ADMIN,
            None,
            Some(&forwarded)
        )
        .await,
        StatusCode::TOO_MANY_REQUESTS,
        "create-user's own bucket is now empty"
    );
    assert_ne!(
        admin(
            Arc::clone(&state),
            "/admin/set-user-admin",
            r#"{"user_id":"yadgar:user:x","is_admin":true}"#,
            None,
            Some(&forwarded)
        )
        .await,
        StatusCode::TOO_MANY_REQUESTS,
        "a second admin verb has its own key; emptying one must not refuse the other"
    );
}

#[tokio::test]
async fn a_cross_origin_browser_request_is_refused_on_every_admin_path() {
    // §3.2: "An `/admin` route that does not call `guard()` reproduces that bug
    // on the one surface where the prize is an admin account. The admin path is
    // more attractive to a cross-origin POST than login is, not less: a
    // browser-driven request to `/admin/users` carrying a stolen or guessed
    // bootstrap token creates an administrator, and the attacker never needs to
    // read the response to benefit."
    //
    // ALL THREE PATHS, because the check is a per-handler call and the compiler
    // cannot notice one is missing.
    let state = state_with_admin(TrustBoundary::Hops(1), wide(), wide());
    let forwarded = format!("203.0.113.1, {REAL_CLIENT}");

    for (path, body) in [
        ("/admin/create-user", CREATE_ADMIN),
        ("/admin/issue-enrolment", r#"{"user_id":"yadgar:user:x"}"#),
        (
            "/admin/set-user-admin",
            r#"{"user_id":"yadgar:user:x","is_admin":true}"#,
        ),
    ] {
        assert_eq!(
            admin(
                Arc::clone(&state),
                path,
                body,
                Some("https://attacker.example"),
                Some(&forwarded)
            )
            .await,
            StatusCode::FORBIDDEN,
            "{path} must refuse an unknown browser origin before it reaches iam"
        );
    }
}

#[tokio::test]
async fn an_admin_client_that_sends_no_origin_is_unaffected() {
    // The cost of the check above, stated directly rather than left implicit in
    // the tests that send no Origin.
    let state = state_with_admin(TrustBoundary::Hops(1), wide(), wide());
    assert_ne!(
        admin(
            state,
            "/admin/create-user",
            CREATE_ADMIN,
            None,
            Some(&format!("203.0.113.1, {REAL_CLIENT}"))
        )
        .await,
        StatusCode::FORBIDDEN,
        "no Origin means a non-browser client, which must reach iam"
    );
}
