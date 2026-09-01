# Migration notes

## D74 token buckets — the chart and the image must move together

`gateway` now **exits at boot** without `YADGAR_VALKEY_ADDR`. A gateway with
nowhere to keep its buckets enforces no capacity limit at all, and that is a
deployment mistake rather than an outage, so D69's fail-at-boot rule applies to
it. An unreachable Valkey at runtime is the other case entirely: there the call
proceeds and the degradation is counted.

The chart in this repository sets the variable, so an ordinary GitOps sync needs
nothing done by hand. **The ordering matters only if the image and the chart are
rolled separately**: a new image under an old chart crash-loops with the message
naming the variable. Roll the chart first, or roll both.

Nothing to run against the cluster. The Valkey the variable points at already
exists — it is the one shared cache from D21, deployed by
`yadgarhq/deploy/infra/valkey/`.

## Follow-up in another repository, not done here

`tests/rate_limit.rs` and `tests/throttle_http.rs` need a real Valkey and skip
loudly without one, so **they do not run in CI**. The shared workflow
(`yadgarhq/actions`, `.github/workflows/ci-pr.yaml`) supplies MariaDB to every
Rust repository and no Valkey. Adding one beside it, and setting
`YADGAR_TEST_VALKEY` in the same `env:` block, is what makes these run:

```yaml
valkey:
  image: valkey/valkey@sha256:<digest> # 9.1.1, pinned by digest per D61
  ports:
    - 6379:6379
  options: >-
    --health-cmd="valkey-cli ping"
    --health-interval=5s --health-timeout=5s --health-retries=12
```

That workflow's own comment already argues for running such a service in every
Rust repository rather than detecting which need it — the detection signal is
what goes stale silently.
