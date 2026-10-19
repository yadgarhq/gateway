//! Test accounts named by short handles, rendered as ADR-0954 requires.
//!
//! The membership suites name accounts `alice`, `bob`, `mallory`, `max` and
//! `carol` because a table of literal paths reads better than a table of
//! uuids. Under ADR-0954 a caller's `local/` segment is its canonical
//! `user_id` without the `yadgar:user:` prefix, so these helpers render each
//! handle as a canonical id ([`id`]) and each `local/<handle>/…` path as
//! `local/<uuid>/…` ([`path`]). Anything that is not a known handle passes
//! through unchanged, so a test can still state an empty, non-canonical or
//! foreign value exactly.

/// The handles, and the uuidv7 each one's id carries.
const ACCOUNTS: [(&str, &str); 5] = [
    ("alice", "0192f0a0-0000-7000-8000-00000000a11c"),
    ("bob", "0192f0a0-0000-7000-9000-000000000b0b"),
    ("mallory", "0192f0a0-0000-7000-a000-0000000ba11e"),
    ("max", "0192f0a0-0000-7000-b000-000000000aac"),
    ("carol", "0192f0a0-0000-7000-8000-0000000ca201"),
];

fn uuid_of(handle: &str) -> Option<&'static str> {
    ACCOUNTS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(handle))
        .map(|(_, uuid)| *uuid)
}

/// The canonical `user_id` for a handle; anything else unchanged.
pub fn id(handle: &str) -> String {
    match uuid_of(handle) {
        Some(uuid) if handle == handle.to_ascii_lowercase() => format!("yadgar:user:{uuid}"),
        _ => handle.to_string(),
    }
}

/// `local/<handle>/…` with the handle replaced by its segment. The `local`
/// spelling is kept as written, so a fold test still folds; a handle written
/// in another case renders as the segment in that case.
pub fn path(p: &str) -> String {
    let mut parts: Vec<String> = p.split('/').map(str::to_string).collect();
    if parts.len() >= 2 && parts[0].eq_ignore_ascii_case("local") {
        if let Some(uuid) = uuid_of(&parts[1]) {
            parts[1] = if parts[1] == parts[1].to_ascii_lowercase() {
                uuid.to_string()
            } else {
                uuid.to_ascii_uppercase()
            };
        }
    }
    parts.join("/")
}
