//! A failed registry poll names the `x-yadgar-request-id` it sent (yaadgaar 275).
//!
//! The poll mints its own id per load (D67) and sends it so `project` and
//! `project-db` can join their records for it. When the load FAILS, the id is
//! the only thing that joins this replica's log line to those records, and the
//! line used to carry the error and the retry delay but not the id.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;

/// A `project` whose `ListProjects` always fails, and which records the id it
/// was sent.
struct FailingProject {
    request_ids: Arc<Mutex<Vec<String>>>,
}

#[tonic::async_trait]
impl crate::pb::yadgar::project::v1::project_service_server::ProjectService for FailingProject {
    async fn resolve_project(
        &self,
        _: tonic::Request<crate::pb::yadgar::project::v1::ProjectServiceResolveProjectRequest>,
    ) -> Result<
        tonic::Response<crate::pb::yadgar::project::v1::ProjectServiceResolveProjectResponse>,
        tonic::Status,
    > {
        Err(tonic::Status::unimplemented("ListProjects only"))
    }

    async fn list_projects(
        &self,
        req: tonic::Request<crate::pb::yadgar::project::v1::ProjectServiceListProjectsRequest>,
    ) -> Result<
        tonic::Response<crate::pb::yadgar::project::v1::ProjectServiceListProjectsResponse>,
        tonic::Status,
    > {
        let id = req
            .metadata()
            .get(crate::upstream::request_id::HEADER)
            .map(|v| v.to_str().expect("an ASCII header").to_string())
            .unwrap_or_default();
        self.request_ids.lock().unwrap().push(id);
        Err(tonic::Status::unavailable("project is not ready"))
    }

    async fn sync_projects(
        &self,
        _: tonic::Request<crate::pb::yadgar::project::v1::ProjectServiceSyncProjectsRequest>,
    ) -> Result<
        tonic::Response<crate::pb::yadgar::project::v1::ProjectServiceSyncProjectsResponse>,
        tonic::Status,
    > {
        Err(tonic::Status::unimplemented("ListProjects only"))
    }
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// THE FAILURE LINE CARRIES THE ID THE FAILED LOAD SENT.
///
/// Mutations this reds: `load` returns the bare status (no id on it), `report`
/// stops reading it, or the id logged is a second mint instead of the one sent.
#[tokio::test]
async fn a_failed_poll_logs_the_request_id_it_sent() {
    retry::listen_for_logs();
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(captured.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let request_ids = Arc::new(Mutex::new(Vec::new()));
    let served = Arc::clone(&request_ids);
    let incoming = tonic::transport::server::TcpIncoming::bind(
        "127.0.0.1:0".parse().expect("a loopback address"),
    )
    .expect("the stub binds");
    let addr = incoming.local_addr().expect("a bound port");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(
                crate::pb::yadgar::project::v1::project_service_server::ProjectServiceServer::new(
                    FailingProject {
                        request_ids: served,
                    },
                ),
            )
            .serve_with_incoming(incoming)
            .await
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("a URI")
        .connect_lazy();

    // Same runtime thread as the spawned poll, so this thread's subscriber sees it.
    let _registry = Registry::start(
        crate::upstream::Upstream::new(channel, Duration::from_secs(30)),
        Duration::from_secs(3600),
    );
    for _ in 0..200 {
        let logged = String::from_utf8(captured.0.lock().expect("log buffer").clone())
            .expect("utf8")
            .contains("NEVER loaded");
        if logged {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let sent = request_ids
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("a poll arrived");
    assert!(!sent.is_empty(), "the poll sent an id");
    let text = String::from_utf8(captured.0.lock().expect("log buffer").clone()).expect("utf8");
    let line = text
        .lines()
        .find(|l| l.contains("NEVER loaded"))
        .expect("the failure is logged");
    let event: serde_json::Value = serde_json::from_str(line).expect("a JSON log line");
    assert_eq!(event["fields"]["request_id"], sent.as_str(), "{line}");
}
