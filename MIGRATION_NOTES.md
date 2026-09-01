# Migration notes

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
