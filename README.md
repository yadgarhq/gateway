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
| One endpoint      | `POST /`. GET and DELETE get `405` — there is no stream in this revision for a GET to open.                                                   |
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

## Configuration

| Variable                               | Default          |                                                                                                           |
| -------------------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------- |
| `LISTEN`                               | `0.0.0.0:8080`   | MCP endpoint                                                                                              |
| `METRICS_LISTEN`                       | `0.0.0.0:9090`   | Prometheus                                                                                                |
| `TASK_HOST` / `TASK_PORT`              | `task` / `50052` | the upstream module                                                                                       |
| `YADGAR_TRUST_UNAUTHENTICATED_HEADERS` | unset            | `1` trusts caller identity — development only                                                             |
| `YADGAR_IAM_ADDR`                      | unset            | real attestation, not yet implemented                                                                     |
| `YADGAR_ALLOWED_ORIGINS`               | empty            | comma-separated. Empty rejects every browser origin, which is right for a server whose clients are agents |
| `RUST_LOG`                             | `info`           | a default, because an unset `RUST_LOG` enables nothing at all                                             |

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

`protoc` must be on `PATH` with its well-known types available — `build.rs`
honours `PROTOC_INCLUDE` and otherwise looks in `/usr/include`.
