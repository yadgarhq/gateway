//! A test upstream that accepts every RPC and never answers it (ADR-1019).
//!
//! It records, per arrival, the gRPC path and the `grpc-timeout` the request
//! was sent with, read off the raw headers before tonic's server sees them. A
//! raw `Service` rather than a generated `*Server` impl, because what it answers
//! is nothing, for every method alike: one type per service name, and no
//! method bodies for a test to keep in step with the proto.
//!
//! It is served by `tonic::transport::Server`, the same server the stubs in
//! `http::tests` and `project::tests` use, so the header it reads is the one a
//! real upstream's tonic server reads.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tonic::body::Body;
use tonic::codegen::{http, Service};
use tonic::metadata::MetadataMap;
use tonic::server::NamedService;
use tonic::transport::Channel;

/// One RPC as it arrived: its path, and the time its `grpc-timeout` left at
/// arrival (`None` when the request carried no header).
#[derive(Debug, Clone)]
pub struct Arrival {
    pub path: String,
    pub timeout: Option<Duration>,
}

/// Every arrival, in order.
#[derive(Default)]
pub struct Seen(Mutex<Vec<Arrival>>);

impl Seen {
    pub fn arrivals(&self) -> Vec<Arrival> {
        self.0.lock().expect("the arrival log").clone()
    }
}

type BoxFut = Pin<Box<dyn Future<Output = Result<http::Response<Body>, Infallible>> + Send>>;

macro_rules! hanging {
    ($name:ident, $service:literal) => {
        /// An upstream serving this name that never answers.
        #[derive(Clone)]
        pub struct $name(pub Arc<Seen>);

        impl NamedService for $name {
            const NAME: &'static str = $service;
        }

        impl Service<http::Request<Body>> for $name {
            type Response = http::Response<Body>;
            type Error = Infallible;
            type Future = BoxFut;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, req: http::Request<Body>) -> Self::Future {
                let timeout = yadgar_dial::Deadline::from_metadata(&MetadataMap::from_headers(
                    req.headers().clone(),
                ))
                .remaining();
                self.0 .0.lock().expect("the arrival log").push(Arrival {
                    path: req.uri().path().to_string(),
                    timeout,
                });
                Box::pin(std::future::pending())
            }
        }
    };
}

hanging!(Iam, "yadgar.iam.v1.IamService");
hanging!(Task, "yadgar.taskapi.v1.TaskService");
hanging!(Project, "yadgar.project.v1.ProjectService");

/// Serve `service` on an ephemeral loopback port and return a channel to it.
///
/// `TcpIncoming::bind` on port 0 keeps the listener, so there is no window
/// between learning the port and serving on it.
pub async fn serve<S>(service: S) -> Channel
where
    S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
        + NamedService
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    let incoming =
        tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().expect("addr"))
            .expect("the hanging upstream binds");
    let addr = incoming.local_addr().expect("a bound port");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await
    });
    tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("a URI")
        .connect_lazy()
}
