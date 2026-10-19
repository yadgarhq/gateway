//! Which `local/<account>` segment is the caller's own (ADR-0954).
//!
//! Split out of [`super`] for the file-size ceiling. ADR-0954 settles the
//! rendering ADR-0605 left open: the account segment is the caller's
//! `user_id` with its `yadgar:user:` prefix stripped — the lowercase uuidv7
//! `iam-db` minted. It is derived from the `user_id` alone, so there is no
//! lookup, no new field and nothing to cache.
//!
//! **A NON-CANONICAL `user_id` HAS NO SEGMENT AT ALL.** `iam` answers the id
//! it stores, which is canonical; a trusted-headers deployment takes
//! `X-Yadgar-User` as sent. Either way, an id this module cannot read as
//! `iam-db`'s exact spelling names no account, so every `local/<seg>/…` claim
//! is FOREIGN to it and refused (see [`super::member`]). Failing closed here
//! never guesses an account for anybody.

/// The prefix `iam-db` mints every user id with: `yadgar:user:<uuidv7>`.
const USER_ID_PREFIX: &str = "yadgar:user:";

/// Whether `id` is spelt EXACTLY as `iam-db` stores it.
///
/// # Why a spelling check
///
/// `iam-db` mints `format!("yadgar:user:{}", Uuid::now_v7())`: the prefix, then
/// a lowercase, hyphenated 8-4-4-4-12 uuid of version 7 and RFC 4122 variant.
/// Its `id` column compares case- and accent-insensitively, so a variant
/// spelling still finds the row and revokes it. The cache eviction does not:
/// `forget_user` compares bytes against the id `iam` resolved, and `iam`
/// publishes the id it was SENT. A variant spelling would revoke every row and
/// evict nothing, and each token would keep resolving from a replica's cache
/// for the credential TTL.
///
/// The same reasoning orders the checks on `/admin/revoke-credentials`. The
/// self-target check is also a byte compare, so the caller's own id in upper
/// case would pass it, and the caller would revoke their own credentials.
/// Refusing every non-canonical spelling first makes the byte compare exact.
///
/// It is ALSO what [`account_segment`] reads (ADR-0954), so one definition of
/// "the id as `iam-db` spells it" serves both.
///
/// ASCII only: an accented or padded spelling fails the length or the
/// character test.
pub fn is_canonical_user_id(id: &str) -> bool {
    let Some(uuid) = id.strip_prefix(USER_ID_PREFIX) else {
        return false;
    };
    let bytes = uuid.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    let shape_ok = bytes.iter().enumerate().all(|(i, &b)| match i {
        8 | 13 | 18 | 23 => b == b'-',
        _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
    });
    // VERSION 7 AND THE RFC 4122 VARIANT, which every id `iam-db` has minted
    // carries: `Uuid::now_v7` is the only minting site in its history.
    shape_ok && bytes[14] == b'7' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// The caller's own `local/` account segment, or `None` when `user_id` is not
/// canonical (ADR-0954).
pub fn account_segment(user_id: &str) -> Option<&str> {
    if !is_canonical_user_id(user_id) {
        return None;
    }
    user_id.strip_prefix(USER_ID_PREFIX)
}
