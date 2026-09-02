# Migration notes

## iam-backed attestation — the image changes nothing until the chart does

`gateway` resolves a caller's identity from the request's bearer token through
`iam.ResolveCredential` now, instead of reading `x-yadgar-user`. **Deploying this
image changes no runtime behaviour on its own**, and the reason is worth stating
rather than assuming: every gateway currently running has
`YADGAR_TRUST_UNAUTHENTICATED_HEADERS=1` set, because the alternatives all exited
at boot. That setting still selects the header path, so a rolled pod attests
exactly as it did.

**The cut-over is `trustUnauthenticatedHeaders: false` in the chart**, and it is a
separate change on purpose — one lever, revertible on its own, not entangled with
the code that made it possible. Before throwing it, check that:

- `iam` is deployed and reachable at `iam.host` / `iam.port`. It is not a secondary
  upstream any more: **an `iam` outage degrades all MCP traffic**, not just
  `/auth/login`. There is no cache in front of the lookup yet, so every
  `tools/call` is one round trip — D72 says the gateway should resolve "on a cache
  miss, never per request", and that cache is not built.
- **A token `iam` does not recognise is actually refused.** Check this one by hand,
  because a broken deployment passes the others silently: `iam` reports "no live
  credential" as `Ok` with an empty `user_id` rather than as an error, so a gateway
  that reads it as a success accepts `Bearer <anything>`, makes revocation and
  expiry inert, and attests every bypasser as `user_id: ""` — one D12 namespace for
  all of them. Send a `tools/call` with a junk token and confirm a `401`. A `200`
  means the running image predates this fix: do not throw the switch.

  ```
  curl -sS -o /dev/null -w '%{http_code}\n' -XPOST http://<gateway>/ \
    -H 'content-type: application/json' \
    -H 'mcp-protocol-version: <version>' \
    -H 'mcp-method: tools/call' -H 'mcp-name: find_tasks' \
    -H 'x-yadgar-project: acme/demo' \
    -H 'authorization: Bearer definitely-not-a-real-token' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"find_tasks","arguments":{}}}'
  ```

- Every client sends `Authorization: Bearer <token>`. A request without one is
  `401`, and `x-yadgar-user` will not stand in for it.
- Clients still send `x-yadgar-project`. It stays caller-supplied — a workspace
  fact a token cannot carry — and a request without it is refused. `x-yadgar-user`
  is IGNORED rather than refused, so a client that keeps sending it is not broken
  by the switch.

`YADGAR_IAM_ADDR` is **deleted**. Nothing can have been setting it: it was a
boot-killer, so a pod given it never started, and this chart never set it. Nothing
to remove from a manifest, and nothing to run against the cluster.

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
