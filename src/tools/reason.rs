//! How an upstream answer reads to the caller, and the reason-token shape
//! (ADR-1042).
//!
//! **A SEAM, not a cut at a line count.** [`super::ToolError`] renders an
//! upstream status through [`upstream_text`]; nothing else here touches a
//! tool's arguments or its dispatch.

/// The text a caller reads for an upstream answer.
///
/// **A REASON-TOKEN REFUSAL IS PASSED THROUGH AS THE MODULE WROTE IT**
/// (ADR-1042): a FAILED_PRECONDITION or INVALID_ARGUMENT whose message starts
/// with one of the proto's five [`REASON_TOKENS`] and a colon
/// (`VERSION_MISMATCH: ...`) is the bare message, byte for byte, so a program can branch on the prefix before the
/// first colon. tonic's own rendering, `code: '...', message: "..."`, puts the
/// code first and Debug-escapes the message, so no token could be read off
/// it. The gRPC code is not lost: the telemetry label is taken from the
/// status itself, and the token implies the code.
///
/// Every other answer keeps tonic's rendering, which names the code. A token
/// shape on any other code (UNAVAILABLE, say) is not a refusal and gets no
/// pass-through.
///
/// **A STATUS WITH A `source` IS A TRANSPORT FAILURE, AND ITS WORDS STAY HERE**
/// (yaadgaar #452). tonic sets a source only on a status it built from a local
/// error (connect, hyper, h2); one decoded off the wire never has one. tonic's
/// Display appends that source Debug-formatted, which named the upstream's
/// address and the OS error, and the message is that error's own text. Such a
/// status renders as its code and [`TRANSPORT_FAILED`].
pub(super) fn upstream_text(status: &tonic::Status) -> String {
    let refusal = matches!(
        status.code(),
        tonic::Code::FailedPrecondition | tonic::Code::InvalidArgument
    );
    if refusal && has_reason_token(status.message()) {
        status.message().to_string()
    } else if std::error::Error::source(status).is_some() {
        tonic::Status::new(status.code(), TRANSPORT_FAILED).to_string()
    } else {
        status.to_string()
    }
}

/// What a caller reads in place of a transport failure's own words (yaadgaar
/// #452). The detail is in the gateway's log, written by `super::bounded`.
pub(super) const TRANSPORT_FAILED: &str =
    "the call to the upstream failed below gRPC; the detail is in the gateway's log";

/// The reason tokens a refusal may start with.
///
/// **THIS LIST MUST MATCH the REASON TOKENS list on `EditTaskRequest.patch` in
/// `proto/yadgar/taskapi/v1/taskapi.proto`.** The proto says a refusal not
/// listed there carries no token, so a token-shaped prefix that is not on this
/// list is prose and keeps tonic's rendering. When a proto bump adds a token,
/// extend this list in the same change.
const REASON_TOKENS: [&str; 5] = [
    "VERSION_MISMATCH",
    "PATCH_COUNT_MISMATCH",
    "PATCH_RESULT_TOO_LARGE",
    "BODY_SHA256_MISMATCH",
    "PATCH_NEW_SHA256_MISMATCH",
];

/// Whether `message` starts with one of [`REASON_TOKENS`] and a colon.
pub(super) fn has_reason_token(message: &str) -> bool {
    message
        .split_once(':')
        .is_some_and(|(token, _)| REASON_TOKENS.contains(&token))
}
