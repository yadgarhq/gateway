//! Turning one request's headers into an attested identity.
//!
//! Split out of [`super`] for the file-size ceiling. This is the decision path:
//! it reads what the caller claimed, resolves it through [`super::cache`] when
//! the source is `iam`, and builds the [`super::Attested`] scope. The rules it
//! applies are written down in [`super`]'s module comment.

use tonic::transport::Channel;
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::limit::{kind_str, Bucket, ConfigError, Overrides};
use crate::pb::yadgar::common::v1::{InheritedSetting, Scope};
use crate::pb::yadgar::iam::v1::{
    iam_service_client::IamServiceClient, RateLimitOverride, ResolveCredentialRequest,
    ResolveCredentialResponse,
};

use super::cache::{is_live, resolve_through, Credentials};
use super::{AttestError, Attestation, Attested, Claimed, RESOLVE_DEADLINE};

/// Build the attested scope for one request.
///
/// `credential` is the `Authorization` header verbatim, and `request_id` is passed
/// in rather than read from the caller — see [`crate::request_id`].
///
/// The `iam` channel is borrowed rather than held on [`Attestation`] so the enum
/// stays a decision and not a resource. It is the same lazy channel `/auth/login`
/// uses; an `iam` that is not deployed yet costs a bounded failure per call rather
/// than a boot that never completes.
///
/// **`cache` IS ONLY REACHED ON THE `Iam` PATH**, because it is the only path that
/// resolves anything. A trusted header is not a credential and there is nothing to
/// remember about it.
pub async fn attest(
    how: &Attestation,
    iam: &Channel,
    cache: &Credentials,
    credential: Option<&str>,
    claimed: Claimed<'_>,
    request_id: String,
) -> Result<Attested, AttestError> {
    match how {
        Attestation::TrustedHeaders => Ok(Attested {
            limits: Overrides::default(),
            // FALSE, and the field's own comment carries the argument: no
            // credential was resolved here, so there is nothing that could have
            // said otherwise, and a header saying so would be a caller naming its
            // own authority.
            is_admin: false,
            scope: scope(
                claimed
                    .user_id
                    .ok_or(AttestError::MissingIdentity("X-Yadgar-User"))?
                    .to_string(),
                claimed
                    .project_id
                    .ok_or(AttestError::MissingWorkspace("X-Yadgar-Project"))?
                    .to_string(),
                claimed.instance_id.unwrap_or_default().to_string(),
                // Team membership comes from iam. Empty means "no team
                // visibility", which is the restrictive answer and the right
                // default while the only identity source is a header the caller
                // wrote.
                Vec::new(),
                request_id,
                // ABSENT, for the reason the two lines above are what they are:
                // nothing was resolved, and no header can carry ADR-0522's
                // setting. A development gateway inventing one would be stating an
                // organisation's read policy from a process that has never spoken
                // to `iam` — and an enforcing -db REFUSES an absent setting, so
                // this fails loudly instead of quietly applying a policy nobody
                // wrote.
                None,
            ),
        }),

        Attestation::Iam => {
            let token = bearer(credential).ok_or(AttestError::MissingCredential)?;
            // THROUGH THE CACHE, which is D72's "on a cache miss, never per
            // request". Everything below the closure runs on a MISS only.
            let resolved = resolve_through(cache, token, || async {
                let mut client = IamServiceClient::new(iam.clone());
                let rpc = client.resolve_credential(ResolveCredentialRequest {
                    // As PRESENTED, never hashed here. The contract is explicit
                    // that hashing is `iam`'s job: a caller that hashed first would
                    // have to agree on the algorithm forever, and changing it would
                    // then be a breaking change to every caller rather than an
                    // implementation detail there. The CACHE key is a hash of the
                    // same token and is unrelated to it — that one never leaves
                    // this process, so nothing has to agree about it.
                    token: token.to_string(),
                });
                match tokio::time::timeout(RESOLVE_DEADLINE, rpc).await {
                    Ok(Ok(r)) => Ok(r.into_inner()),
                    // `e.code()` is kept and `e` is dropped. The message belongs in
                    // the log line `http` writes, not in an answer to a caller
                    // whose credential has just failed to resolve.
                    Ok(Err(e)) => Err(AttestError::Upstream(e.code())),
                    // Through the SAME variant as any other upstream problem, so a
                    // stall is not a third answer somebody has to remember to keep
                    // opaque.
                    Err(_elapsed) => Err(AttestError::Upstream(tonic::Code::DeadlineExceeded)),
                }
            })
            .await?;
            // ON EVERY REQUEST, hit or miss. The cache holds what `iam` ANSWERED,
            // and this is what turns that answer into an attestation — including
            // the refusal at the top of it. A cached refusal is re-refused here
            // rather than being remembered as an error, so the guard cannot be
            // skipped by a cache hit.
            from_resolved(
                resolved,
                claimed.project_id,
                claimed.instance_id,
                request_id,
            )
        }
    }
}

/// The attested identity, from a credential `iam` has already resolved.
///
/// **THERE IS NO CLAIMED-USER PARAMETER, and that is the security property.** The
/// user id can only come from `resolved`, so no later edit to [`attest`] can route
/// a header into it without changing this signature — a visible act, rather than a
/// line that looks like the two beside it. A rule saying "do not trust the header"
/// would have been as true and as easy to break.
///
/// `project_id` and `instance_id` ARE claimed, and stay so: a workspace is not a
/// fact about a credential, and the token cannot carry it.
///
/// **`iam` ANSWERS `Ok` FOR A CREDENTIAL THAT DOES NOT RESOLVE, and reading that
/// as a success is an authentication bypass.** `iam-db` returns an empty response
/// for a token that is unknown, revoked, expired, or belongs to a soft-deleted
/// person, and `iamdb.proto` says why in as many words:
///
/// > Empty user_id means no live credential matched. NOT an error: "no such
/// > credential" and "the store is broken" are different outcomes and a caller
/// > must be able to tell them apart — one is a 401, the other is a 503.
///
/// **THIS GATEWAY IS THE CALLER THAT OWES THE 401**, and nothing downstream would
/// catch a miss: no service checks for an empty `user_id` on a read path, and
/// every bypasser would share `user_id: ""`, collapsing D12's per-user scoping
/// into a single namespace. Revocation and expiry would both be inert. The check
/// belongs at this boundary because this is the last place the distinction still
/// exists.
///
/// **The rule is not in the proto this crate vendors**, which is how it was
/// missed: `yadgar/iam/v1/iam.proto` describes `user_id` only as "Identity and
/// AUTHORITY" and never documents the negative answer. Only `yadgar/iamdb/v1`
/// states it, and the gateway deliberately does not vendor that file — it is
/// `iam`'s own upstream, not this one's. So the rule is written down HERE, beside
/// the code that depends on it.
///
/// **TWO SIGNALS, and either one refuses.** `iam` sets
/// `valid_for_seconds: if resolved { 300 } else { 0 }`, so a negative answer
/// carries both an empty user and a zero lifetime. Checking both means an `iam`
/// that regresses on one of them is still refused rather than believed. The cost
/// of the second check, stated so that changing it stays deliberate: an `iam` that
/// later returned `valid_for_seconds: 0` on a VALID credential, to mean "do not
/// cache this one", would be refused here. Fail-closed is the right direction for
/// an identity check that has been bypassed once, and a gateway with no cache has
/// no use for a zero it cannot tell from a refusal.
pub(super) fn from_resolved(
    resolved: ResolveCredentialResponse,
    claimed_project: Option<&str>,
    claimed_instance: Option<&str>,
    request_id: String,
) -> Result<Attested, AttestError> {
    if !is_live(&resolved) {
        // THROUGH THE UPSTREAM VARIANT, carrying the code `iam` would have used
        // had this outcome been an error, so it reaches `opaque_status` and
        // becomes the same 401 as any other refusal — no new variant, and no
        // answer that tells a caller working through stolen tokens which of them
        // exists.
        return Err(AttestError::Upstream(tonic::Code::Unauthenticated));
    }
    Ok(Attested {
        limits: overrides_from(resolved.rate_limit_overrides)?,
        // D73'S FLAG, ARRIVING AT LAST. It has been on the wire since
        // `ResolveCredentialResponse` grew it and was discarded here, so the
        // gateway held an identity that could not say whether it was an
        // administrator. `false` is the safe default and `iam` populates the
        // field with the same comment on its own side.
        is_admin: resolved.is_admin,
        scope: scope(
            resolved.user_id,
            claimed_project
                .ok_or(AttestError::MissingWorkspace("X-Yadgar-Project"))?
                .to_string(),
            claimed_instance.unwrap_or_default().to_string(),
            // FROM THE RESPONSE, and reachable no other way. Teams decide what a
            // TEAM-visible record is readable by (D12), so a caller that could
            // name its own teams could read other people's records.
            resolved.team_ids,
            request_id,
            // FROM THE RESPONSE for the same reason, and unexamined: it is a
            // policy an organisation states, so a caller able to name its own
            // would name the permissive one.
            resolved.owner_reads_own_record,
        ),
    })
}

/// D74's per-user buckets, as this gateway's limiter keys them.
///
/// **An override that cannot be enforced REFUSES THE CREDENTIAL** rather than
/// being dropped — [`Overrides::from_pairs`] states the argument: skipping a
/// bucket silently applies the configured default instead, and for an override
/// that TIGHTENS a limit that is the limit-nobody-notices-is-gone shape.
///
/// **A deliberate `rate = 0, burst = 0` is the contract's way of saying DENY this
/// bucket, and it refuses the credential too.** That is broader than the contract
/// asks — the person loses every bucket rather than one — and it is the honest
/// answer available here: `limit::Bucket` has no representation for a denial, and
/// `limit::validate` refuses a zero rate because the script turns it into a
/// permanent lockout with a 24-hour `Retry-After`. Refusing loudly fails in the
/// direction the admin intended; applying the default would silently undo them. A
/// narrower denial needs a `Decision::Denied` in `limit.rs`, which is a change to
/// the script rather than to this mapping.
///
/// An entry whose `limit` is UNSET is skipped, on the contract's own instruction:
/// an unset limit is how an override is CLEARED, so one still in the list is a
/// server bug that "must be read as no override for that bucket rather than as a
/// denial". `unwrap_or_default()` is the plausible-looking line that reads it as
/// exactly the denial the contract says it is not.
pub(super) fn overrides_from(list: Vec<RateLimitOverride>) -> Result<Overrides, ConfigError> {
    let mut pairs = Vec::with_capacity(list.len());
    for entry in list {
        // FIRST, BEFORE ANY OTHER CHECK ON THE ENTRY. A cleared override is not an
        // override at all, so nothing else about it can be wrong — and reaching a
        // refusal on its `kind` or its `module` first would turn "no override for
        // that bucket" into a denial of the whole credential, which is precisely
        // the reading the contract forbids.
        let Some(limit) = entry.limit else {
            continue;
        };
        let kind = Kind::try_from(entry.kind)
            .map_err(|_| ConfigError::UnknownKind(entry.kind.to_string()))?;
        // `kind_str` names all five and only three of them are buckets. D74 puts
        // KIND_JOB outside this mechanism and KIND_UNSPECIFIED is a zero value
        // nothing should construct, so either is a server bug rather than a
        // configuration this gateway can honour. Accepting one would mint a key
        // `Limits::effective` is never asked for — an override that looks applied
        // and is not.
        if !matches!(kind, Kind::Read | Kind::Write | Kind::Generate) {
            return Err(ConfigError::UnknownKind(kind_str(kind).to_string()));
        }
        if entry.module.is_empty() {
            return Err(ConfigError::Shape(format!(".{}", kind_str(kind))));
        }
        // The key `Limits::effective` looks a bucket up by, built exactly as
        // `Limits::parse` builds it. A key in any other shape is an override
        // nothing ever reads.
        pairs.push((
            format!("{}.{}", entry.module, kind_str(kind)),
            Bucket {
                rate: limit.rate,
                burst: f64::from(limit.burst),
            },
        ));
    }
    Overrides::from_pairs(pairs)
}

/// The ONE place a [`Scope`] is constructed.
///
/// Private, and it takes strings rather than headers or a response: everything
/// that decides WHERE a value came from has already happened by the time control
/// reaches here, so this function cannot be the place a claim is mistaken for a
/// fact. `grep 'Scope {' src/` returning one hit is what makes the contract's
/// claim checkable, and that grep points at this body.
///
/// **THE SETTING IS TAKEN AS AN `Option` AND WRITTEN AS ONE.** Every other
/// parameter here is already the value it becomes, and this one is too: absence
/// is a state the contract gives a meaning to, so there is nothing for this
/// function to decide about it.
pub(super) fn scope(
    user_id: String,
    project_id: String,
    instance_id: String,
    team_ids: Vec<String>,
    request_id: String,
    owner_reads_own_record: Option<InheritedSetting>,
) -> Scope {
    Scope {
        user_id,
        project_id,
        // A session identifier, not an identity — D46 throttles on it and D39
        // addresses notices with it. Absent is legitimate: a one-shot client has
        // no session.
        instance_id,
        team_ids,
        request_id,
        // MOVED WHOLE, AND RESOLVED NOWHERE ON THIS HOP (ADR-0522). These are the
        // INPUTS to the resolution — an organisation's value, its lock, and every
        // team's override — and the answer depends on the team of the ROW being
        // read, which no caller upstream of the query knows. `common.proto` states
        // the rule once and says where it runs: where the reach is computed, in a
        // -db. A gateway that resolved it here would hand down a decision made
        // against the wrong team, and nothing about the answer would look wrong.
        //
        // NO DEFAULT IS SUPPLIED FOR AN ABSENT ONE, and that is the whole of this
        // field's contribution. An absent message and a present one holding
        // SETTING_VALUE_UNSPECIFIED mean the same thing to a reader — "the sender
        // named no policy" — and an enforcing -db REFUSES both. Substituting
        // ADR-0522's shipped default here would state a policy the deployment
        // never wrote, in a message that looks exactly like one it did.
        owner_reads_own_record,
    }
}

/// The token out of an `Authorization` header, or nothing.
///
/// The scheme is compared case-insensitively because RFC 9110 says it is, and a
/// client sending `bearer` would otherwise be refused for a reason no error
/// message explains. An empty token after the scheme is no credential at all, and
/// is treated as one missing rather than sent upstream to be refused.
pub(super) fn bearer(header: Option<&str>) -> Option<&str> {
    let (scheme, token) = header?.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}
