//! The Lua that makes the token bucket's read-compute-write atomic, and the
//! classification of what a client error from running it actually means.
//!
//! Split out of [`super::valkey`] for the file-size ceiling: this is the ONE
//! round trip's contract — what the script computes, and what an error back
//! from it is called — which [`super::valkey::Limiter`] is the connection and
//! retry policy wrapped around, not this.

use super::Degrade;

/// The atomic read-compute-write.
///
/// KEYS[1] the bucket. ARGV: rate, burst, cost, ttl seconds.
/// Returns `{allowed, tokens, retry_after_seconds}`.
///
/// **`tokens` and `retry_after` come back as STRINGS.** Lua-to-Redis conversion
/// truncates a number to an integer, so returning them as numbers would report
/// every fractional wait as `0` and make `retry-after` a lie in the common case.
pub(super) const SCRIPT: &str = r#"
local key   = KEYS[1]
local rate  = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local cost  = tonumber(ARGV[3])
local ttl   = tonumber(ARGV[4])

-- Valkey's clock, not the caller's: one clock for every replica.
local t   = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000

local state  = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts     = tonumber(state[2])
if tokens == nil or ts == nil then
  -- An absent bucket is a FULL one. That is sound only while the key outlives
  -- the refill window of the bucket READING it, which is what a TTL fixed for
  -- the whole deployment buys -- see KEY_TTL_SECONDS in this file.
  tokens = burst
  ts     = now
end

-- Clamped at zero. Valkey's clock is one clock, but it is not guaranteed
-- monotonic across a restart, and a negative elapsed would DRAIN the bucket.
local elapsed = now - ts
if elapsed < 0 then elapsed = 0 end
tokens = math.min(burst, tokens + elapsed * rate)

local allowed = 0
local retry   = 0
if tokens >= cost then
  tokens  = tokens - cost
  allowed = 1
else
  retry = (cost - tokens) / rate
end

redis.call('HSET', key, 'tokens', tokens, 'ts', now)
-- EXTEND ONLY, NEVER SHORTEN. Two processes may hold different configurations
-- during a rolling deploy, and the shorter TTL must not win: a key whose life
-- is cut expires while its bucket is still empty, and the next read treats
-- absent as full. TTL returns -2 for an absent key and -1 for one with no
-- expiry, and both compare below any real ttl, so both set it.
--
-- Not `EXPIRE key ttl GT`: GT treats a key with no TTL as having an infinite
-- one and refuses to set the first expiry at all, which is exactly the call
-- that must not be skipped.
local current = redis.call('TTL', key)
if current < ttl then
  redis.call('EXPIRE', key, ttl)
end

return {allowed, tostring(tokens), tostring(retry)}
"#;

/// Which degradation a client error actually is.
///
/// **The distinction the counter is for.** A connection this process HAD and then
/// lost reaches here as a command error, not as a failed init — so without this
/// the reconnect case would be filed under `error` and an operator would look for
/// a broken script rather than an absent server.
pub(super) fn classify(e: redis::RedisError) -> Degrade {
    // FIRST, and before the connection arms, because the two overlap. A wrong
    // password is refused during the handshake, and `redis` reports that as a
    // failed connection attempt — so an auth arm placed after those would never
    // be reached for the case an operator is most likely to create.
    //
    // TWO SHAPES, because `redis` 1.6 produces two. A password this process sent
    // and the server rejected fails inside the handshake and arrives as
    // `ErrorKind::AuthenticationFailed` with no code (`connection.rs`, the AUTH
    // reply check). A password this process never sent, against a server that
    // wanted one, is not a handshake failure at all — the connection is
    // established and the FIRST COMMAND comes back `-NOAUTH`, which `redis` has
    // no known kind for and surfaces as an extension code. Matching only the kind
    // would leave the missing-credential case, which is the whole point of this
    // arm, filed as an ordinary error and failed open.
    if e.kind() == redis::ErrorKind::AuthenticationFailed
        || matches!(e.code(), Some("NOAUTH" | "WRONGPASS" | "NOPERM"))
    {
        Degrade::Unauthenticated
    } else if e.is_connection_refusal() || e.is_connection_dropped() {
        Degrade::Unreachable
    } else if e.is_timeout() {
        // A server that ANSWERS SLOWLY, which is a different thing to look at
        // from one that is not there. This arm is reachable only because the
        // inner response budget is smaller than the outer one.
        Degrade::Timeout
    } else {
        Degrade::Error
    }
}
