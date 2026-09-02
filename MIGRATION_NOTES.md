# Migration notes

## iam-backed attestation — DONE, and here is what it cost

**The switch is thrown.** `trustUnauthenticatedHeaders` is `false` in the chart, so
`gateway` resolves a caller's identity from the request's bearer token through
`iam.ResolveCredential` and ignores `x-yadgar-user`. Until this change the running
cluster had `YADGAR_TRUST_UNAUTHENTICATED_HEADERS=1`, which meant any caller who
wrote `x-yadgar-user: someone` was attested as that person with no credential at
all. That is what ended here.

**Reverting is one value.** Setting it back to `true` restores the old behaviour
without touching the image, which is the whole reason this was a separate change
from the code that made it possible.

The four preconditions below were the pre-flight, and all four were checked before
the flip. They are kept because a revert has to re-check them:

- `iam` is deployed and reachable at `iam.host` / `iam.port`. It is not a secondary
  upstream any more: **an `iam` outage degrades all MCP traffic**, not just
  `/auth/login`. Every `tools/call` was one round trip when this was written; the
  cache D72 asks for — "on a cache miss, never per request" — is built now, so the
  outage costs the callers whose entries expire during it rather than every call in
  flight. See "The credential cache" below.
- **A token `iam` does not recognise is actually refused.** Check this one by hand,
  because a broken deployment passes the others silently: `iam` reports "no live
  credential" as `Ok` with an empty `user_id` rather than as an error, so a gateway
  that reads it as a success accepts `Bearer <anything>`, makes revocation and
  expiry inert, and attests every bypasser as `user_id: ""` — one D12 namespace for
  all of them. Send a `tools/call` with a junk token and confirm a `401`. A `200`
  means the running image predates this fix: do not throw the switch.

  **This check now passes against the live cluster**: the junk token below returns
  `401` with `"the credential could not be verified"`. Run 2026-09-02.

  ```
  curl -sS -o /dev/null -w '%{http_code}\n' -XPOST http://<gateway>/ \
    -H 'content-type: application/json' \
    -H 'mcp-protocol-version: 2026-07-28' \
    -H 'mcp-method: tools/call' -H 'mcp-name: find_tasks' \
    -H 'x-yadgar-project: acme/demo' \
    -H 'authorization: Bearer definitely-not-a-real-token' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
          "_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}
          },
          "name":"find_tasks","arguments":{}}}'
  ```

  **`params._meta` IS NOT OPTIONAL AND THIS COMMAND USED TO OMIT IT.** As written
  before, the gateway answered `400` with `-32602` — "params._meta[...] is
  required" — before attestation ran at all, so the check reported a failure that
  had nothing to do with the credential and never reached the 401-versus-200
  distinction it exists to make. `protocolVersion` and `clientCapabilities` are
  required fields under the `io.modelcontextprotocol` namespace (ADR-0489), and
  `mcp-protocol-version` must carry the same value the body declares because the
  server cross-validates the two. A literal `<version>` fails that check as well.

- Every client sends `Authorization: Bearer <token>`. A request without one is
  `401`, and `x-yadgar-user` will not stand in for it.
- Clients still send `x-yadgar-project`. It stays caller-supplied — a workspace
  fact a token cannot carry — and a request without it is refused. `x-yadgar-user`
  is IGNORED rather than refused, so a client that keeps sending it is not broken
  by the switch.

`YADGAR_IAM_ADDR` is **deleted**. Nothing can have been setting it: it was a
boot-killer, so a pod given it never started, and this chart never set it. Nothing
to remove from a manifest, and nothing to run against the cluster.

## The credential cache — one value, and it is a security bound

`gateway` now holds what `iam` answered for each bearer token it has seen, keyed
on a SHA-256 of the token, in **each replica's own memory**. `tools/call` resolves
against `iam` on a miss instead of on every request (D72, ADR-0491).

**`credentialCache.ttlSeconds` is the only bound on revocation, and it defaults to 30.** ADR-0491 decides that revocation publishes a broker event the cache is
cleared by, and records in its own consequences that nothing publishes one yet —
ledger 457, with 467 as the `iam` side. Until that lands, **a credential revoked in
`iam` keeps working at the gateway for up to this many seconds.** `gateway` logs a
warning saying so at every boot, and refuses any value above 300 at boot rather
than clamping it.

Nothing to run against the cluster. The chart sets the variable, so an ordinary
GitOps sync carries it. Rolling the image without the chart is safe here — the
binary's own default is the same 30 — which is the opposite of the `YADGAR_VALKEY_ADDR`
case below, and it is deliberate: a cache is an optimisation with a safe default,
and a missing rate limit is not.

**To turn it off**, set `credentialCache.ttlSeconds: 0`. Every `tools/call` goes
back to a round trip against `iam`. That is the revert and it needs no new image,
the same shape as `trustUnauthenticatedHeaders`.

`yadgar_gateway_credential_cache_total{outcome="hit"|"miss"}` is how you tell
whether it is working. A miss rate near 100% with steady traffic means tokens are
rotating, or the TTL is shorter than the gap between one client's calls.

## D74 token buckets — the chart and the image must move together

`gateway` now **exits at boot** without `YADGAR_VALKEY_ADDR` or without
`YADGAR_MAX_REPLICAS`. A gateway with nowhere to keep its buckets enforces no
capacity limit at all, and one that cannot say how far it scales cannot compute a
correct degraded-mode floor — `rate / max_replicas` per replica, whose aggregate
bound is the whole reason the floor is acceptable. Both are deployment mistakes
rather than outages, so D69's fail-at-boot rule applies to them. An unreachable
Valkey at runtime is the other case entirely: there the call proceeds under that
floor and the degradation is counted.

`YADGAR_MAX_REPLICAS` comes from `autoscaling.maxReplicas` when autoscaling is
enabled and from `replicaCount` when it is not. **Raising either without rolling
the pods leaves the floor computed from the old number** — too loose by the ratio,
and only while Valkey is unreachable. Roll the Deployment after changing it.

The chart in this repository sets the variable, so an ordinary GitOps sync needs
nothing done by hand. **The ordering matters only if the image and the chart are
rolled separately**: a new image under an old chart crash-loops with the message
naming the variable. Roll the chart first, or roll both.

Nothing to run against the cluster. The Valkey the variable points at already
exists — it is the one shared cache from D21, deployed by
`yadgarhq/deploy/infra/valkey/`.

## The Valkey these tests need is in the shared workflow

`tests/rate_limit.rs` and `tests/throttle_http.rs` need a real Valkey. The shared
workflow (`yadgarhq/actions`, `.github/workflows/ci-pr.yaml`) supplies one beside
its MariaDB, digest-pinned, so they run on every pull request. Nothing to do
here.

That was added by `yadgarhq/actions#30` and proved on a real runner before it
merged, by pointing this repository's caller at the branch and watching the
eight live-Valkey tests go from failing to passing.
