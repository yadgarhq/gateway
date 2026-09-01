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

|                   |                                                                                                                                               |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Statelessness     | No session is minted or echoed. Any replica serves any request; no affinity, which is what D47 assumed.                                       |
| One MCP endpoint  | `POST /`. GET and DELETE get `405` — there is no stream in this revision for a GET to open. `POST /auth/login` is the one non-MCP path.       |
| `server/discover` | Implemented, because the spec says servers MUST. It replaces the handshake a stateless protocol has nowhere to keep.                          |
| Three headers     | `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` mirror the body's `_meta` and are cross-checked. Disagreement is `-32020 HeaderMismatch`. |
| `resultType`      | Required on every result. This server only returns `complete`.                                                                                |
| Origin            | Validated; an invalid one gets `403`. **This is not authentication** — it stops a browser page, not a client that sets its own headers.       |

## Identity

`Scope` is constructed in **exactly one function**, `attest::attest`. Everything
else receives one; nothing else builds one. `grep 'Scope {' src/` returns a single
hit, which is what makes the contract's claim — "attested by the gateway… never
supplied by the caller itself" — checkable rather than merely asserted.

**The process refuses to start unless a source of identity is configured.**
Either `YADGAR_IAM_ADDR` or `YADGAR_TRUST_UNAUTHENTICATED_HEADERS=1`. There is no
default, because the only available default would be trusting the caller — a
gateway that attests nothing while its contract says it does, going green in a
development cluster and staying green. D69's rule for capabilities, applied to
identity.

Until `iam` ships (ledger 452), development uses the trusted-header path and the
service logs a warning naming it on every boot.

`request_id` is minted here and **overwrites anything the client sent**. A caller
that could set it could make two unrelated calls collide, and every roll-up built
on it would be wrong with no error anywhere.

### `POST /auth/login`

The one unauthenticated path (D75). `yaadgaar login` posts
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

## Configuration

| Variable                               | Default          |                                                                                                           |
| -------------------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------- |
| `LISTEN`                               | `0.0.0.0:8080`   | MCP endpoint                                                                                              |
| `METRICS_LISTEN`                       | `0.0.0.0:9090`   | Prometheus                                                                                                |
| `TASK_HOST` / `TASK_PORT`              | `task` / `50052` | the upstream module                                                                                       |
| `IAM_HOST` / `IAM_PORT`                | `iam` / `50052`  | where `POST /auth/login` is sent — **not** attestation, and not `YADGAR_IAM_ADDR`                         |
| `YADGAR_TRUST_UNAUTHENTICATED_HEADERS` | unset            | `1` trusts caller identity — development only                                                             |
| `YADGAR_IAM_ADDR`                      | unset            | real attestation, not yet implemented                                                                     |
| `YADGAR_ALLOWED_ORIGINS`               | empty            | comma-separated. Empty rejects every browser origin, which is right for a server whose clients are agents |
| `YADGAR_VALKEY_ADDR`                   | **required**     | the shared cache holding D74's token buckets. Unset EXITS at boot                                         |
| `YADGAR_RATE_LIMITS`                   | empty            | `<module>.<kind>=<rate>:<burst>`, comma-separated. e.g. `task.write=2:120`                                |
| `YADGAR_RATE_LIMIT_DEFAULT`            | `10:100`         | the bucket for a `(module, kind)` nobody named                                                            |
| `YADGAR_RATE_LIMIT_TIMEOUT_MS`         | `20`             | how long one bucket lookup may take before the call falls back to the local floor                         |
| `YADGAR_MAX_REPLICAS`                  | **required**     | the autoscaler's ceiling, and the divisor of the degraded floor. Unset EXITS at boot                      |
| `RUST_LOG`                             | `info`           | a default, because an unset `RUST_LOG` enables nothing at all                                             |

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
`unreachable`, `timeout` or `error` and under whether the floor allowed or refused
it, and a warning is logged. The argument is on `limit::Decision::Degraded`; the
short form is that D74 calls this capacity protection rather than authorisation,
and this Valkey is one replica with no persistence, so failing closed would make
it a hard dependency of every call at the one hop all traffic already passes
through — while failing open with no floor at all would leave the number
unenforced for the length of the outage.

**Per-user overrides are not wired yet.** D74 puts them on
`ResolveCredentialResponse`, which does not carry them and which this service does
not call at all while `iam` attestation is unimplemented. `limit::Overrides` is
the shape they will fill; it is empty on every call today, and empty means the
configured default applies.

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
