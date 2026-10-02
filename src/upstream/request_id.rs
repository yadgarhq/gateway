//! D67's join key, carried to every upstream as `x-yadgar-request-id`.
//!
//! **THE ID WAS MINTED AND NEVER SENT** (ledger 1248). [`crate::request_id`]
//! put it on this gateway's own `CallRecord` and nowhere else, so `iam` had no
//! header to forward to `iam-db`, and every record past this hop joined on `""`.
//! `task` was joined only by accident of its contract: its requests carry a
//! `Scope`, and field 5 of that is the id.
//!
//! **A CLIENT, NOT A CALL SITE, CARRIES IT.** [`carrying`] wraps the channel a
//! generated client is built over, so every RPC that client makes is stamped and
//! no RPC can be added that forgets to be. A per-call helper would have to be
//! remembered at each of a dozen call sites; this one has to be remembered once
//! per client, and the type says whether it was.
//!
//! **METADATA, NOT A CONTRACT CHANGE**, for the reason `iam` and `iam-db` already
//! give: `ResolveCredential`, `Login` and the rest run before a caller has a
//! `Scope`, so the field that would carry the id does not exist on them. The
//! header is the one shape every hop reads, and `iam`'s `forward_request_id`
//! already passes it on to `iam-db`.

use tonic::metadata::AsciiMetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

/// The metadata key every hop reads D67's id from.
pub const HEADER: &str = "x-yadgar-request-id";

/// A channel whose every request carries one call's request id.
pub type Carrying = InterceptedService<Channel, Stamp>;

/// Build a client over `channel` with `request_id` on every request it sends.
///
/// `request_id` is the id ALREADY ON this call's `CallRecord` — never a fresh
/// mint. A second id here would be a well-formed UUIDv7 that joins to nothing,
/// which breaks D67 exactly as badly as sending none and looks fine doing it.
pub fn carrying(channel: Channel, request_id: &str) -> Carrying {
    InterceptedService::new(channel, Stamp::new(request_id))
}

/// The interceptor behind [`carrying`].
#[derive(Clone, Debug)]
pub struct Stamp(Option<AsciiMetadataValue>);

impl Stamp {
    /// **AN ID THAT CANNOT BE A HEADER IS DROPPED, NOT AN ERROR.** Telemetry
    /// never fails a call (D25). The gateway mints every id as a UUIDv7, which
    /// is always a valid header value, so this arm is unreachable from
    /// [`crate::request_id`] and exists so that no other input can fail a call.
    fn new(request_id: &str) -> Self {
        Self(request_id.parse().ok())
    }
}

impl tonic::service::Interceptor for Stamp {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(id) = &self.0 {
            req.metadata_mut().insert(HEADER, id.clone());
        }
        Ok(req)
    }
}
