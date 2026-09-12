//! `yadgar-gateway` — the bilingual edge (D16).
//!
//! MCP over HTTP outward to clients, gRPC inward to the module services. It is
//! the only service in the system that speaks anything but gRPC, and the only one
//! that can measure the number D67 exists for: **bytes and words returned to the
//! caller**. Every other hop sees protobuf on the wrong side of the boundary.
//!
//! It holds nothing (D47). No database, no store SDK, no session — so any replica
//! serves any request and the autoscaler adds capacity rather than idle pods.

#![forbid(unsafe_code)]

pub mod admin;
pub mod attest;
pub mod http;
pub mod invalidate;
pub mod limit;
pub mod mcp;
pub mod project;
pub mod rotate;
pub mod source;
pub mod tools;
pub mod upstream;

/// What this binary answers `server/discover` with, stamped at build time.
///
/// **NOT `CARGO_PKG_VERSION`.** Nothing has ever written a version into
/// `Cargo.toml` — a module's version in this organisation is its release tag
/// (D65), derived at merge from the `## Changelog` bullets and never typed into a
/// manifest. So the manifest said `0.1.0` while the tags ran to `v0.8.1`, and the
/// handshake every MCP client reads to learn what it is talking to answered
/// `0.1.0`. That is a wrong answer in a protocol response, not untidiness.
///
/// The manifest now says `0.0.0`, so anything still reading it gets an obviously
/// wrong answer rather than a plausible one. `build.rs` resolves the real number
/// from `YADGAR_GATEWAY_VERSION`, which the `Containerfile` sets from the release
/// tag; the reasoning for why the resolution lives in the image build rather than
/// in the build script is in `build.rs`.
pub const VERSION: &str = env!("YADGAR_GATEWAY_VERSION");

/// Generated from the vendored contract (D16, D70).
pub mod pb {
    pub mod yadgar {
        pub mod common {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/yadgar.common.v1.rs"));
            }
        }
        pub mod task {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/yadgar.task.v1.rs"));
            }
        }
        pub mod taskapi {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/yadgar.taskapi.v1.rs"));
            }
        }
        pub mod iam {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/yadgar.iam.v1.rs"));
            }
        }
        pub mod project {
            /// **THE LINT IS ALLOWED FOR THE GENERATED FILE AND FOR NOTHING
            /// ELSE.** `project.proto` documents its two tiers with bulleted
            /// lists whose items wrap, and `prost` re-emits each comment line as
            /// `///  ` with a single leading space — which `clippy::doc_lazy_continuation`
            /// reads as an unindented continuation and refuses, 26 times, in a
            /// file no hand can edit. The alternatives are worse than the allow:
            /// `disable_comments` would drop the contract's own prose out of the
            /// generated types, where it is the only documentation a reader of
            /// this crate has for them, and re-indenting the lists in
            /// `yadgarhq/proto` would shape another repository's contract around
            /// one style lint in this one. Nothing hand-written is covered — the
            /// attribute sits on the module that holds only the `include!`.
            #[allow(clippy::doc_lazy_continuation)]
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/yadgar.project.v1.rs"));
            }
        }
    }
}

/// Mint the correlation id for one call (D67).
///
/// **Minted here and nowhere else, and a caller-supplied one is discarded.** This
/// is the join key that makes the gateway, logic and `-db` records for one call
/// sum to one call. A client that could set it could make two unrelated calls
/// collide on purpose, and every roll-up built on it would be quietly wrong with
/// no error anywhere. So the gateway overwrites whatever arrived.
///
/// UUIDv7 rather than v4: it is time-ordered, so records land in insertion order
/// in whatever eventually stores them, and a human reading two ids can tell which
/// call came first.
pub fn request_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Mint the idempotency key for one upstream write (D9).
///
/// MCP has no idempotency concept, so there is nothing to propagate — this is
/// minted per inbound request.
///
/// **What this does and does not buy.** It makes the gateway's own retries to a
/// module safe: the same key replayed returns the original outcome instead of
/// writing twice. It does NOT deduplicate a CLIENT's retry — a client that sends
/// `tools/call` twice is two inbound requests, two keys, two writes. Making that
/// idempotent would need a key the client supplies and keeps stable, which the
/// protocol gives no place for. Stated here because the opposite is easy to
/// assume from the field's name.
pub fn idempotency_key() -> String {
    uuid::Uuid::now_v7().to_string()
}
