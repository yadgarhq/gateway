# gateway — the bilingual edge

MCP over HTTP outward to clients, gRPC inward to the module services. The only
service in the system that speaks anything but gRPC (D16), and the only one that
can measure what D67 exists to measure.

Decisions are recorded in [`yadgarhq/docs`](https://github.com/yadgarhq/docs) —
D16 (transport), D47 (holds nothing), D67 (telemetry), D71 (the TLS edge in front
of it). ADR-0487 and ADR-0488 carry the protocol and attestation arguments.

## Why it exists

Three reasons, and the third is the one that is easy to miss.

- **Clients speak MCP, modules speak gRPC.** Something has to translate, and D16
  puts that in exactly one place rather than in every module.
- **It mints `request_id`.** One logical call fans out gateway → logic → `-db`,
  each hop emitting its own record. Without a shared key those are three
  unrelated rows and "bytes returned" gets counted three times.
- **It is the only hop that can see the answer.** D67 asks how much of a caller's
  context a response consumes. That is a fact about the JSON sent to the client —
  every other hop sees protobuf, which is a different size and answers a
  different question. Measuring it anywhere else would quietly measure the wrong
  thing.

## Protocol

**MCP spec revision `2026-07-28`**, and the revision matters more than usual.
That revision removed protocol sessions, the `initialize` handshake, the GET/SSE
stream and `Last-Event-ID` resumability. Anything you remember about
`Mcp-Session-Id` describes a superseded revision — see the wiki page
`mcp-spec-2026-07-28-shape`, verified against the specification twice, the second
time adversarially, because this revision post-dates the assistant knowledge
cutoff.

Consequences here:

|                   |                                                                                                                                                              |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Statelessness     | No session is minted or echoed. Any replica serves any request; no affinity, which is what D47 assumed.                                                      |
| One MCP endpoint  | `POST /`. GET and DELETE get `405` — there is no stream in this revision for a GET to open. `POST /auth/login` and `POST /auth/enrol` are the non-MCP paths. |
| `server/discover` | Implemented, because the spec says servers MUST. It replaces the handshake a stateless protocol has nowhere to keep.                                         |
| Three headers     | `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` mirror the body's `_meta` and are cross-checked. Disagreement is `-32020 HeaderMismatch`.                |
| `resultType`      | Required on every result. This server only returns `complete`.                                                                                               |
| Origin            | Validated; an invalid one gets `403`. **This is not authentication** — it stops a browser page, not a client that sets its own headers.                      |

## Identity

`Scope` is constructed in **exactly one function**, `attest::scope`. Everything
else receives one; nothing else builds one. `grep 'Scope {' src/` returns a single
hit, which is what makes the contract's claim — "attested by the gateway… never
supplied by the caller itself" — checkable rather than merely asserted. Two
identity sources did not become two literals: both call that one function.

**The user is RESOLVED; the project and the instance are CLAIMED.** ADR-0488
requires a scope to be minted here and never supplied, and the three fields are
not alike:

| field                    | where it comes from                            | why                                                                                                                                                                                                                                      |
| ------------------------ | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `user_id`                | `iam.ResolveCredential`, from the bearer token | a self-asserted username is forgeable by anyone holding any valid token                                                                                                                                                                  |
| `project_id`             | `X-Yadgar-Project`                             | a workspace fact. It changes as a person moves between checkouts, and a token cannot carry it                                                                                                                                            |
| `instance_id`            | `X-Yadgar-Instance`                            | a session marker rather than an identity (D46 throttles on it, D39 addresses notices with it)                                                                                                                                            |
| `team_ids`               | `iam.ResolveCredential`                        | teams decide what a TEAM-visible record is readable by (D12), so a caller naming its own would read other people's records                                                                                                               |
| `owner_reads_own_record` | `iam.ResolveCredential`                        | ADR-0522's inheritable setting. The gateway carries it and resolves NONE of it — the answer depends on the team of the ROW being read, so it is resolved where the reach is computed. An absent one is forwarded absent, never defaulted |

`X-Yadgar-User` is **ignored** on the `iam` path rather than refused: clients
already in flight send it, an ignored forged header is inert, and refusing one
would add a rollout failure that buys nothing. The function that builds a scope
from a resolved credential takes no claimed user at all — the property is in the
signature, not in a rule.

**A credential that does not resolve is a `401`, and `iam` reports that as `Ok`.**
`iam-db` answers an unknown, revoked, expired or soft-deleted credential with an
EMPTY response rather than an error — `iamdb.proto`: _"Empty user_id means no live
credential matched. NOT an error… one is a 401, the other is a 503."_ **The gateway
is the caller that owes the 401**, and nothing downstream would catch a miss: no
service checks for an empty `user_id` on a read path, and every bypasser would
share `user_id: ""`, collapsing D12's scoping into one namespace. `from_resolved`
refuses on either half of the negative answer — an empty `user_id` or a
`valid_for_seconds` of zero, which `iam` sets together — and the refusal goes
through the same `opaque_status` as any other.

The rule is **not** in the proto this crate vendors: `yadgar/iam/v1/iam.proto`
describes `user_id` only as "Identity and AUTHORITY". Only `yadgar/iamdb/v1` states
it, and the gateway deliberately does not vendor that file, so the rule is written
down beside the code that depends on it.

**The secure source is the DEFAULT.** An unset environment resolves the bearer
token against `iam`. `YADGAR_TRUST_UNAUTHENTICATED_HEADERS=1` is an explicit,
named opt-OUT for development, and the service logs a warning on every boot under
it. The process used to refuse to start unless one of two variables was set,
because the only available default was trusting the caller; that gate is gone
along with the reason for it, which is a stronger reading of D69 than the gate was
— a deployment can no longer reach the trusting path by forgetting something.

**The lookup runs on a cache miss, never per request** — D72's words, and this
paragraph used to say the cache did not exist. It does: each replica holds what
`iam` answered, keyed on a SHA-256 of the token, in its own memory. The lookup
carries a 5s deadline; a stall answers through the same opaque status as any other
upstream problem.

**What clears that cache is a broker event, not the TTL.** `gateway` subscribes to
`yadgar.iam.credential.revoked` and `yadgar.iam.user.teams-changed`, and both evict
every entry for the named person — `iam` holds a credential id on a revoke and
never sees the token this cache is keyed on, so the person is the only unit an
event can address. The subscription carries no queue group, because every replica
holds its own map and must receive every message. A broker it cannot reach does
not stop this service starting: it says so at every boot, retries, and
`YADGAR_CREDENTIAL_TTL_SECONDS` is the bound meanwhile.

**Three ways that connection fails, and the log says which.** UNREACHABLE is an
outage and is retried every 5 seconds. REFUSED — a wrong password, or no password
against a broker whose `authorization` block demands one — does not end by itself,
so it is logged as a deployment error and retried a minute apart. FORBIDDEN is the
one with no other symptom: a subject this account may not subscribe to leaves the
connection OPEN and answers an asynchronous `-ERR`, which `async-nats` logs at
`debug!`. `gateway` registers an event callback for it, logs it at ERROR, and ENDS
the subscription so the redial reports it again. NATS acknowledges no `SUB` and
`async-nats`' `flush` is a local socket flush, so the boot line is best-effort:
a broker slower than the short window `gateway` waits gets a boot line that the
ERROR then contradicts — alert on the ERROR. With
`YADGAR_CREDENTIAL_TTL_SECONDS=0` there is no cache to evict from, so the broker
is not dialled at all and the boot warning says so.

`request_id` is minted here and **overwrites anything the client sent**. A caller
that could set it could make two unrelated calls collide, and every roll-up built
on it would be wrong with no error anywhere.

### `POST /auth/login`

One of two unauthenticated paths (D75). `yaadgaar login` posts
`{"username", "password", "label"}` and reads `{"token"}` back; the gateway
translates that to `iam.Login` and drops `credential_id`, which nothing reads.

**Two statuses, and that is the security property.** `UNAUTHENTICATED` is `401`;
**every** other gRPC code is one opaque `503` with a constant body.

Some of those other codes are raised only after the password has verified —
`Internal` when the token cannot be minted, and whatever `create_credential`
propagates from `iam-db` after that — so a caller able to pick one out would learn
from the status alone that its password was right. The gateway **cannot tell which
side of the check a code came from**: the same `Unavailable` arrives from
`get_password_hash`, which runs before any password is checked, and from
`create_credential`, which runs after, and `upstream_failed` preserves the
upstream code either way. Having nothing to distinguish them by, it collapses all
of them. Mapping everything to `401` closes the same leak and was rejected: it
tells a person with the right password that it is wrong every time `iam-db` is
down.

`http::login_answer` decides both the status and the body from a `tonic::Code` —
**not** a `tonic::Status`, so no upstream message is in scope to be interpolated
into a body the client never reads. `login_failure` builds the whole response from
it, and its test walks all 17 codes asserting one refusal, one identical
`(status, body)` for everything else, no `WWW-Authenticate` (D72 — this deployment
implements no discovery flow) and `application/json` throughout.

The RPC carries a 10s deadline; a stall answers through the same `login_failure`
as every other problem, so it is not a third thing to keep opaque.

No rate limit and no audit record. Both are absent org-wide rather than skipped
here; D74's buckets key on a user and a login has none yet.

### `POST /auth/enrol`

The other unauthenticated path (D73). An admin creates the account and hands over
an enrolment token; the PERSON chooses their own password here, so the admin never
learns it. `yaadgaar` posts `{"secret", "password", "label"}` and reads
`{"token", "username"}` back.

`username` is returned and `credential_id` is dropped. The contract returns the
username because a person enrolling on their first machine would otherwise have to
be told it separately — "a second artefact to lose, which is the exact failure the
token's design exists to remove". `LoginResponse` can omit it because its caller
had to know it to call.

**The same status rule as `/auth/login`, through the same function.**
`http::opaque_status` is the rule — `UNAUTHENTICATED` is `401`, every other code is
one opaque `503` — and all three paths that have one call it, because it is the
security property rather than a mapping table. The **bodies** are per-endpoint:
telling a person redeeming an enrolment that their "username or password" was
invalid sends them looking for an account they do not have yet.

The reason to collapse is sharper here than on login. The contract calls
`RedeemEnrolment` "UNAUTHENTICATED BY CONSTRUCTION" and mandates **one failure, not
three** — unknown, spent and expired are one answer, and "the server tells them
apart and records which; the caller cannot". `InvalidArgument` is the code that
looks safest to pass through, because VALIDATION BEFORE LOOKUP means a
password-policy refusal arrives without the secret having been checked; it is also
what a replayed idempotency key with a different password returns, and that check
runs only once the store has confirmed the secret was good. One code, both sides of
the lookup, nothing to tell them apart — `login`'s problem exactly.

The idempotency key is **minted per inbound request**, which makes this gateway's
own retry to `iam` safe and does **not** deduplicate a client's retry: a client
that POSTs twice is two requests and two keys, so the second presents a spent
secret and is refused. See `## Risk` on the pull request that added this, and
`lib::idempotency_key`.

No rate limit and no audit record, exactly as `/auth/login` — and this endpoint
does Argon2id work for anyone who can reach the port.

## Configuration

| Variable                               | Default          |                                                                                                                                                        |
| -------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `LISTEN`                               | `0.0.0.0:8080`   | MCP endpoint                                                                                                                                           |
| `METRICS_LISTEN`                       | `0.0.0.0:9090`   | Prometheus                                                                                                                                             |
| `TASK_HOST` / `TASK_PORT`              | `task` / `50052` | the upstream module                                                                                                                                    |
| `IAM_HOST` / `IAM_PORT`                | `iam` / `50052`  | the whole credential lifecycle: `/auth/login`, `/auth/enrol` and attestation                                                                           |
| `YADGAR_TRUST_UNAUTHENTICATED_HEADERS` | unset            | `1` trusts caller identity — development only. Unset resolves the bearer token against `iam`                                                           |
| `YADGAR_ALLOWED_ORIGINS`               | empty            | comma-separated. Empty rejects every browser origin, which is right for a server whose clients are agents                                              |
| `YADGAR_VALKEY_ADDR`                   | **required**     | the shared cache holding D74's token buckets. Unset EXITS at boot                                                                                      |
| `YADGAR_RATE_LIMITS`                   | empty            | `<module>.<kind>=<rate>:<burst>`, comma-separated. e.g. `task.write=2:120`                                                                             |
| `YADGAR_RATE_LIMIT_DEFAULT`            | `10:100`         | the bucket for a `(module, kind)` nobody named                                                                                                         |
| `YADGAR_RATE_LIMIT_TIMEOUT_MS`         | `20`             | how long one bucket lookup may take before the call falls back to the local floor                                                                      |
| `YADGAR_MAX_REPLICAS`                  | **required**     | the autoscaler's ceiling, and the divisor of the degraded floor. Unset EXITS at boot                                                                   |
| `YADGAR_VALKEY_PASSWORD_FILE`          | unset            | a FILE holding the cache's `requirepass`. Unset dials the cache unauthenticated and WARNs; set-but-unreadable or empty EXITS at boot                   |
| `YADGAR_CREDENTIAL_TTL_SECONDS`        | `30`             | how long one resolved credential is reused. The backstop for a missed invalidation event; `0` disables the cache; above `300` EXITS at boot            |
| `NATS_URL`                             | unset            | the broker carrying D72's cache invalidation. Unset consumes NOTHING and WARNs at every boot; unreachable or REFUSED is loud and retried               |
| `NATS_USER`                            | unset            | the broker account this gateway authenticates as. It is NOT `iam`'s. Set without `NATS_PASSWORD_FILE` EXITS at boot                                    |
| `NATS_PASSWORD_FILE`                   | unset            | a FILE holding that account's password. Unset is REFUSED by a broker that demands one, and says so; set-but-unreadable, empty, or without a user EXITS |
| `YADGAR_TRUSTED_PROXY_HOPS`            | unset            | how many proxies append to `X-Forwarded-For` in front. Unset RECORDS NO SOURCE ADDRESS; a non-number EXITS at boot                                     |
| `YADGAR_LOGIN_RATE_LIMIT`              | `0.2:10`         | `<rate>:<burst>` for `/auth/login` and `/auth/enrol`, per ATTRIBUTABLE client address                                                                  |
| `YADGAR_LOGIN_UNATTRIBUTED_RATE_LIMIT` | `10:100`         | the same, per OBSERVED HOP, which is what applies while no trust boundary is declared                                                                  |
| `RUST_LOG`                             | `info`           | a default, because an unset `RUST_LOG` enables nothing at all                                                                                          |

## The source address, and what bounds login

`POST /auth/login` and `POST /auth/enrol` are the only surfaces a stranger
reaches with no credential, and each costs `iam` a full Argon2id verification
whether or not the username exists. D74's buckets cannot cover them: those key on
`(user, module, kind)`, and a login has no user until it succeeds. So they bucket
on the SOURCE ADDRESS instead, in their own key space, at their own rates.

Which needs an address the caller cannot choose, and that is what
`YADGAR_TRUSTED_PROXY_HOPS` declares. Each proxy APPENDS the address it saw to
`X-Forwarded-For`, so the gateway reads the entry that many places from the
RIGHT. Everything to the left of that index is text the caller could have written.

**The default refuses.** Unset means unknown, and an unknown address is recorded
as nothing rather than guessed — because the naive guess is the LEFTMOST entry,
which is exactly the one the caller controls. An audit record carrying a forged
address is worse than one carrying none: the empty field is honestly empty, the
forged one reads as evidence (ADR-0491).

A hop count rather than an ingress-specific resource, per D80: yadgar runs on
EKS, AKS and GKE and behind NGINX, Traefik, HAProxy, an ALB or an Application
Gateway. Every one of them appends to this header; only the depth differs, and
the depth is what an operator declares once.

Leaving it unset costs two things and neither is an outage. Authentication events
carry no source address. And the two endpoints are bounded per OBSERVED HOP —
behind an ingress, one bucket for everybody — so `YADGAR_LOGIN_UNATTRIBUTED_RATE_LIMIT`
applies rather than `YADGAR_LOGIN_RATE_LIMIT`. Those two numbers are different
CONTROLS rather than two strengths of one. The attributable one prevents guessing.
The shared one bounds the Argon2id CPU a stranger can spend, and is deliberately
loose: a guess-prevention rate on a key everybody shares would let one attacker
refuse every login in the installation.

**There is no lockout.** A per-username lockout answers a question about a
USERNAME, so refusing early on a locked account tells a stranger which usernames
exist — reopening the timing oracle `iam`'s `LOGIN_RESPONSE_FLOOR_MS` exists to
close. It is also an availability weapon: anyone who can guess at a name can lock
the person behind it out. Any lockout has to be paid BEHIND the floor, inside
`iam`, and it needs a durable failed-attempt counter that the contract has no
field for.

The throttle above does not have that problem, and the reason is structural
rather than argued: it runs BEFORE the request body is parsed, so at the point the
decision is made no username is in scope that the outcome could depend on. A 429
is fast, a real attempt is floored, and the difference names an address's budget
rather than an account's existence.

## Rate limiting

Every user-attributed call spends a token from a bucket keyed on
`(user, module, kind)` (D74). An empty bucket is `429` with an exact
`Retry-After`. Nothing runs on a timer: the refill is computed from elapsed time
on each request.

**The buckets live in Valkey, and the read-compute-write is one Lua script.** This
is the whole reason the module is not a `HashMap`. The gateway runs at least two
replicas and scales to six; done as a read then a write, two replicas both see one
token left, both allow, and the configured limit is quietly multiplied by the
replica count — under exactly the load the limit exists for. `tests/rate_limit.rs`
measures both: 200 concurrent callers against a bucket of 20 were granted **200**
by a read-then-write and exactly **20** by the script.

The script reads Valkey's own clock rather than taking one from the caller, so
replica clock skew cannot buy anybody extra tokens.

**A key's lifetime is a property of the deployment, not of the bucket that wrote
it.** An absent key is read as a full bucket, so a key must outlive the refill
window of whichever bucket READS it — and the writer's window is the same number
only while nobody changes a limit. Every key therefore gets one hour, and a bucket
that would take longer than an hour to refill is refused at boot.

**The user id reaches the key hashed.** It is caller-supplied under
`YADGAR_TRUST_UNAUTHENTICATED_HEADERS`, and the key lands in the one Valkey D21
shares with four other subsystems under `allkeys-lru`. Hashing bounds the size of
a key; it does not bound how many a caller can mint, and that half is inside D74's
posture — capacity protection, not authorisation.

**If Valkey cannot answer, the call PROCEEDS under a local floor** — each replica
holds callers to `rate / YADGAR_MAX_REPLICAS` in process, so six replicas sum to
the configured rate and never more. It is loud:
`yadgar_gateway_rate_limit_degraded_total` counts every degraded call under
`unreachable`, `timeout`, `error` or `unauthenticated`, and under whether the
outcome was `allowed`, `throttled` or `refused`, and a warning is logged. The argument is on `limit::Decision::Degraded`; the
short form is that D74 calls this capacity protection rather than authorisation,
and this Valkey is one replica with no persistence, so failing closed would make
it a hard dependency of every call at the one hop all traffic already passes
through — while failing open with no floor at all would leave the number
unenforced for the length of the outage.

**A cache that REFUSES this gateway's credential is the one case that does not
proceed.** `YADGAR_VALKEY_PASSWORD_FILE` names a file holding the cache's
`requirepass`; unset means the cache asks for none, and gateway warns at every
boot that the hop is unauthenticated. Set with nothing readable behind it, the
pod exits at boot naming the path — it never falls back to an unauthenticated
connection. And if the cache demands a password this process cannot satisfy, the
call is REFUSED with a `503`, counted under `unauthenticated` / `refused`, rather
than held to the floor above.

The floor is for an OUTAGE, and every clause of the argument for it depends on
the failure being transient. A rejected credential is not: it is a deployment
somebody assembled wrong, it will still be wrong on the next call, and failing
open onto the floor for ever would be a rate limiter that reads healthy while
enforcing a sixth of what it says. Nothing dials the cache at boot, deliberately,
so this cannot be caught earlier than the first call.

**Per-user overrides are wired.** D74 puts them on `ResolveCredentialResponse`,
`attest` maps them into `limit::Overrides`, and `Limits::effective` merges them
over the configured defaults — one lookup answering both "who are you" and "what
may you spend". On the trusted-header path they stay empty, because no credential
is resolved and no header could carry a limit; empty means the configured default
applies.

An override this gateway **cannot enforce refuses the whole credential** rather
than being dropped, because dropping it applies the default instead and silently
undoes whoever set it. That includes the contract's DENY — an entry with
`rate = 0, burst = 0`: `limit::Bucket` has no representation for a denial, and
`validate` refuses a zero rate because the Lua script turns it into a permanent
lockout with a 24-hour `Retry-After`.

**Be clear about what that costs, because it is not a throttle.** A refused
credential fails ATTESTATION, so the person loses reads as well as writes, on every
call, until an admin clears the row — an admin who denied `task.write` takes away
much more than they asked for. It answers `500` with its own body and its own
`FAILED_PRECONDITION` metric label, deliberately distinct from the `503` and
`UNAVAILABLE` of an `iam` outage: the two were byte-identical at first, which would
have sent an operator hunting an outage that was not happening. A narrower answer
needs a `Decision::Denied` in `limit.rs`.

An entry with `limit` unset is skipped rather than read as a denial, on the
contract's own instruction — and it is skipped **before** its `kind` or `module` is
judged, so a cleared override carrying a nonsense kind stays "no override for that
bucket" instead of becoming a refusal.

## Balancing

The gateway balances across `task`'s replicas rather than pinning to one.

This was a real defect until `task`'s Service became headless: gRPC holds one
long-lived HTTP/2 connection, so against a virtual IP every request reached the
same upstream pod while the other sat idle looking healthy. The balancing itself
lives in `yadgar-dial`, shared with `task` rather than copied, because two
services holding their own copy is how they come to disagree about how they find
their peers.

## Development

```bash
make proto    # refresh vendored protos from the pin in PROTO_VERSION
make test
```

The rate-limit tests need a real Valkey — a bucket's only interesting property
is what concurrent callers get, and nothing but a real server can answer that.
**CI runs them**: the shared workflow supplies a Valkey beside its MariaDB
(`yadgarhq/actions#30`). Locally they skip loudly without one, and **on a runner
they FAIL rather than skip** (`CI=true` with `YADGAR_TEST_VALKEY` unset is a
panic), so they cannot silently stop running if that service is ever removed.

```bash
podman run -d --rm --name valkey-test -p 16379:6379 \
    docker.io/valkey/valkey:9.1.1 --save "" --appendonly no
YADGAR_TEST_VALKEY=127.0.0.1:16379 cargo test --all-features -- --nocapture
```

`protoc` must be on `PATH` with its well-known types available — `build.rs`
honours `PROTOC_INCLUDE` and otherwise looks in `/usr/include`.
