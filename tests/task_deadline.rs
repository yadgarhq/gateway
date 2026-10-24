//! yaadgaar #361: a task that accepts the connection and never answers must not
//! hold a `tools/call` open past the configured task bound.

use std::time::{Duration, Instant};

use serde_json::json;
use tokio::net::TcpListener;
use tonic::transport::Channel;
use yadgar_gateway::pb::yadgar::common::v1::Scope;
use yadgar_gateway::tools::call;
use yadgar_gateway::upstream::TaskUpstream;

/// Short on purpose: the channel under test has no timeout of its own, so only the
/// wrapper can stop the wait.
const BOUND: Duration = Duration::from_secs(1);

/// The tools the test below drives, by name.
const EXERCISED: [&str; 5] = [
    "create_task",
    "read_task",
    "find_tasks",
    "edit_task",
    "transition_task",
];

/// A server that accepts every connection and then says nothing, so the HTTP/2
/// handshake never completes.
async fn silent_task() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    addr
}

#[tokio::test]
async fn every_task_tool_returns_within_the_bound_when_task_never_answers() {
    let addr = silent_task().await;
    for (name, args) in [
        ("create_task", json!({ "title": "t" })),
        ("read_task", json!({ "number": 1 })),
        ("find_tasks", json!({})),
        (
            "edit_task",
            json!({ "id": "yadgar:task:x", "expect_version": 1, "title": "t" }),
        ),
        (
            "transition_task",
            json!({ "id": "yadgar:task:x", "expect_version": 1, "to": "done" }),
        ),
    ] {
        let channel = TaskUpstream::new(
            Channel::from_shared(format!("http://{addr}"))
                .unwrap()
                .connect_lazy(),
            BOUND,
        );
        let started = Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            call(&channel, Scope::default(), name, &args),
        )
        .await;
        let outcome = outcome.unwrap_or_else(|_| panic!("{name} hung past the test's 5 s guard"));
        assert!(
            started.elapsed() < BOUND + Duration::from_secs(1),
            "{name} took {:?}",
            started.elapsed()
        );
        match outcome {
            Err(yadgar_gateway::tools::ToolError::Upstream(s)) => {
                assert_eq!(s.code(), tonic::Code::DeadlineExceeded, "{name}: {s}")
            }
            Err(e) => panic!("{name}: expected an upstream deadline, got {e:?}"),
            Ok(_) => panic!("{name} cannot succeed against a silent server"),
        }
    }
}

/// A sixth task RPC added to `SERVED` without a case above, and so without the
/// `bounded` wrap check, turns this red.
#[test]
fn the_tools_exercised_are_exactly_the_served_task_tools() {
    let mut exercised = EXERCISED.to_vec();
    exercised.sort_unstable();
    let mut served = yadgar_gateway::tools::SERVED.to_vec();
    served.sort_unstable();
    assert_eq!(exercised, served);
}
