# Migration notes

## The Valkey password — this image first, the cache second (ledger 518)

`gateway` can now present a password to the shared cache. **Nothing to run
against the cluster from here**, and nothing in this repository changes what the
running deployment does until `yadgarhq/deploy` gives the cache a `requirepass`.

**The ordering is not symmetric, and getting it backwards is an outage.** Merge
this repository first and `yadgarhq/deploy` second:

- **This image under a cache with no password**: unchanged behaviour.
  `rateLimit.passwordSecret` is empty by default, so the chart sets no password
  variable, and gateway dials the cache exactly as it always did. It logs a
  warning at every boot saying the hop is unauthenticated, which is true and is
  the point.
- **The cache with a password, under an image that predates this**: every
  user-attributed call gets `NOAUTH` from the cache, the old code files that
  under `error`, and every call falls open onto the degraded floor —
  `rate / maxReplicas` on each replica, for as long as the mistake stands. The
  gateway keeps serving, which is why nobody would notice.

So the cache must not gain a password before this image is running everywhere.
Argo auto-syncs `yadgarhq/deploy`, so that ordering is decided by which pull
request merges first.

**The two failure modes, and they are deliberately different.**
`YADGAR_VALKEY_PASSWORD_FILE` set with no readable, non-empty file behind it
**exits at boot** naming the path — the same rule `TASK_TLS_CA_FILE` already
applies, and it is what stops a missing Secret from silently becoming an
unauthenticated connection. A cache that demands a password this process cannot
satisfy is **refused at the first call** with a `503`, not held to the floor. It
cannot be caught at boot, because nothing dials the cache at boot: `Limiter`'s
connection is built on first use so a slow cache cannot stop this pod binding its
listener, and that decision is unchanged.

**To revert**, clear `rateLimit.passwordSecret` in the chart. That is one value
and no new image, the same shape as `trustUnauthenticatedHeaders` — but it is
only the revert while the cache still accepts an unauthenticated client, so
revert `yadgarhq/deploy` first if `requirepass` has already landed.

`yadgar_gateway_rate_limit_degraded_total{reason="unauthenticated"}` is how you
tell. Any value above zero is a deployment error rather than an outage: it does
not recover on its own.

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

**`credentialCache.ttlSeconds` is the backstop for a missed invalidation event, and
it defaults to 30.** The event itself is consumed from the broker — see the section
below. Whenever `gateway` is not consuming, **a credential revoked in `iam` keeps
working at the gateway for up to this many seconds**, and `gateway` logs a warning
saying exactly that at every boot. Any value above 300 is refused at boot rather
than clamped.

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

## The invalidation consumer — the broker needs an account for `gateway`

`gateway` now subscribes to `yadgar.iam.credential.revoked` and
`yadgar.iam.user.teams-changed`, which `iam` has published all along, and evicts
every cached entry for the named user (D72). The subscription carries **no queue
group**, so every replica receives every message — a queue group would evict one
pod and leave the rest serving the revoked credential.

**Nothing to run against the cluster from this repository.** `nats.url` is set to
`nats://nats:4222` and the chart carries the credential, so an ordinary GitOps
sync starts the consumer.

**Both halves are in place.** `yadgarhq/deploy#15` merged on 2026-09-02 at
20:51:33Z. Verified live, read-only, on the reference cluster: `cm/nats-config` in
namespace `yadgar` declares a `gateway` user whose `subscribe.allow` names exactly
`yadgar.iam.credential.revoked` and `yadgar.iam.user.teams-changed`, with
`publish.deny: ">"`, and Secret `nats-auth-gateway` exists carrying key
`password`.

**Why the order mattered.** A NATS server with an `authorization` block REFUSES a
credential-less `CONNECT` — `-ERR 'Authorization Violation'`, connection closed,
exactly as for a wrong password. Before deploy#15 that block declared only `iam`,
so a chart pointing at this broker would have put every gateway pod in a state
where it is refused, consumes nothing, and redials for ever. That is not "connects
unauthenticated", and it is why the url waited for the account rather than
shipping ahead of it.

The chart sets `nats.passwordSecret: nats-auth-gateway`, `nats.user: gateway` and
the mount. Those are inert whenever `nats.url` is empty, because the binary reads
the url first and returns "no broker configured" before it looks at a credential
at all.

**Now that `nats.url` is set, the Secret is a hard prerequisite of the chart's
defaults.** The volume is `optional: true`, so a cluster without
`nats-auth-gateway` mounts an empty directory, `NATS_PASSWORD_FILE` names a file
that is not there, and **the pod exits at boot naming that path**. It is the
designed failure — gateway never falls back to presenting no credential — but it
is a boot failure, not a degraded start, and it is new: while the url was empty
the same missing Secret was inert. Deploying these defaults into a cluster that
has not applied `yadgarhq/deploy#15` crash-loops the gateway. Clear `nats.url`
there instead.

**What `yadgarhq/deploy` owns, and now carries.** In its `infra/nats.yaml`:

- a second user, `gateway`, in `config.merge.authorization.users`, with its
  password from a **new** Secret — `nats-auth-gateway`, key `password`. A new
  Secret rather than a second key in `nats-auth`, because `infra/bootstrap/`
  creates Secrets with `create`-only RBAC and treats the `409 AlreadyExists` on
  every later run as success: a key added to an existing Secret would never
  materialise on a running cluster.
- **subscribe-only permissions** on exactly those two subjects, and publish denied.
  This service has no business publishing on a subject `iam` owns, and no
  request/reply, so it needs no `_INBOX.>` either.
- `gateway` added to the `nats-ingress` NetworkPolicy in
  `infra/network-policies/shared-infrastructure.yaml`, whose 4222 rule named only
  `app: iam`. Nothing enforces NetworkPolicy on the reference cluster's CNI, so
  this is for the day one does.

Both, or neither: the pod exits at boot naming `/var/run/secrets/nats/password` if
only one of `nats.passwordSecret` and `nats.user` is set, in either direction.

**A FORBIDDEN SUBSCRIPTION IS THE FAILURE TO WATCH FOR after the cut-over**, and
it is the quiet one. A wrong password closes the connection and is impossible to
miss. A subject missing from the `subscribe.allow` list does not: the broker
leaves the connection open and answers an asynchronous
`-ERR 'Permissions Violation for Subscription to ...'`. `gateway` registers an
event callback for exactly that, logs it at ERROR, and ENDS the subscription so
the redial reports it again for as long as it stands.

**The boot line can still be wrong for one cycle, and that is a real limit rather
than an oversight.** NATS acknowledges no `SUB`, and `async-nats`' `flush` is a
local socket flush that enqueues no `PING` — so nothing in the client can wait for
the server's verdict. `gateway` gives a refusal a short window before it writes its
boot line; a broker slower than that window gets a boot line saying "consuming"
which the ERROR and the redial then contradict. **Alert on the ERROR, not on the
boot line.**

The subjects are now written in three places — `iam`'s publisher, `gateway`'s
constants, and the broker's `subscribe.allow` list — and only the first two are
pinned by a test. A typo in the third shows up solely in that ERROR.

**To revert**, clear `nats.url`. One value, no new image: no broker is dialled and
`credentialCache.ttlSeconds` is the bound again. Setting
`credentialCache.ttlSeconds: 0` also stops the consumer, because with no cache
there is nothing for an event to evict — the binary skips the broker entirely and
says so at boot.

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

## ADR-0522's setting — no manual step, but the DEPLOY ORDER is part of the contract

This image populates `Scope.owner_reads_own_record` from what `iam` answers. It
resolves none of it: the answer depends on the team of the ROW being read, which
this hop does not know, so a `-db` computes it where it computes the reach.

**Populate, deploy, then enforce, and the order is not a preference.** A `-db`
that reads the field REFUSES an unset `org_value` rather than choosing a value —
`task-db`'s `src/setting.rs:113` answers `INVALID_ARGUMENT` with "a store may not
choose one on its behalf". So a `-db` that read the field ahead of the modules
supplying it would refuse every read. That is an outage rather than a wrong
answer, which is the better failure of the two and is still one.

**No `-db` reads the field today, and that is what makes the order achievable.**
`task-db` v0.4.1 adds `resolve()` and calls it from nowhere: on v0.4.2
`grep -rn 'setting::' src/ tests/` outside `src/setting.rs` returns nothing, and
so does `owner_reads_own_record`. `task-db#28` says so in as many words —
"IT IS DELIBERATELY NOT CALLED FROM THE REQUEST PATH, AND THAT IS THE WHOLE
POINT OF THIS CAR" — and names the wiring as the next car, a change to
`src/sql.rs`. Until that change is made and released, `task-db` is in the
pre-enforcement state and behaves exactly as it always has. **Do not read a
`task-db` version number, or the presence of `setting.rs`, as enforcement.**

**The chain has five links, not three, and the store is the first of them.**

| link      | version  | what it does                                                                                     |
| --------- | -------- | ------------------------------------------------------------------------------------------------ |
| `iam-db`  | ≥ v0.5.1 | creates `iam_org_setting` and `iam_team_setting_override`, and seeds the shipped default         |
| `iam`     | ≥ v0.7.2 | validates `SetInheritedSetting` and forwards it, and carries the setting out beside the identity |
| `gateway` | ≥ v0.8.3 | populates `Scope.owner_reads_own_record` from what `iam` answers                                 |
| `task`    | ≥ v0.4.3 | takes proto v1.9.0, so the field survives the hop to `task-db`                                   |
| `task-db` | ≥ v0.4.1 | CARRIES the resolver (`src/setting.rs`), deliberately unwired — enforcement is a later change    |

**An earlier revision of this note said `iam` v0.7.2 already stores ADR-0522's
shipped default. It does not, and the enforcement car is the one that would pay
for it.** `iam` commit `1b21bcc`, first tagged v0.7.2, validates and forwards; it
stores nothing. The tables and the seed row are in `iam-db` commit `13f997f`,
first tagged **v0.5.1** — migrations 10, 11 and 12 of its `src/schema.rs`. An
operator who confirmed `iam` alone, concluded the chain was populated, and then
released and rolled the wiring change would find `iam_org_setting` absent and
every read refused. That is why the store is named here as the first link.

**Nothing to run BY HAND against the cluster — but there is a rollout.** No new
variable, no new secret, no chart change, and no manual SQL. The seed is a
migration, not an operator step: `seed_owner_reads_own_record()` inserts
`owner_reads_own_record` as `SETTING_VALUE_ON` with the lock engaged, and it
applies at `iam-db` boot like every other migration. **Nobody has to call
`SetInheritedSetting` to get the shipped default.** An operator who wants a value
other than ON does call it, under the TTL bound described below. So the
prerequisite is a rollout list — and the next section is how to check it, because
a merge does not deploy.

**A change to the setting binds by the credential cache's TTL, and nothing
shortens that.** `YADGAR_CREDENTIAL_TTL_SECONDS` defaults to 30, and the setting
rides the cached credential because it arrives on the same response as the
identity. No invalidation event closes the window at either level:
`SetInheritedSetting` publishes nothing at all, and the two subjects `iam` does
publish are keyed on a `user_id` — which an organisation-level write does not
have. So after changing the policy, expect up to the TTL before every replica
honours it, and treat that as the bound rather than watching for an event that
is not coming.

## A merge is not a deploy — every Deployment pins `latest`

Measured read-only against the kind cluster on 2026-09-03.

Every yadgar Deployment sets `image: ghcr.io/yadgarhq/<module>:latest` with
`imagePullPolicy: Always`. Merging moves the `latest` tag and publishes an image.
It restarts nothing. A running pod keeps the digest it started with until
something unrelated restarts it, so a merged and published change is not a
deployed change.

**Two things that look like evidence and are not.** Argo CD's `Synced/Healthy` is
not evidence: every Application reported Synced and Healthy while four of the
five modules ran stale binaries. The pod's image TAG is not evidence either,
because every one of them reads `latest`. What is evidence is the pod's
`imageID` DIGEST, compared against the GHCR version list.

### How to check what is actually running

**Both flags are mandatory, on every command in this section and the next.**
`$CLAUDE_JOB_DIR` below is an agent-session path and will be unset for you:
substitute the path to your own kubeconfig. What must not change is that the
kubeconfig holds the kind cluster ONLY and that the context is `kind-yadgar`.
Those two together are what stop a copy-paste reaching production, because the
default context on a workstation here is production.

```bash
kubectl --kubeconfig "$CLAUDE_JOB_DIR/tmp/kubeconfig-kind-only.yaml" --context kind-yadgar \
  -n yadgar get pods -o custom-columns='POD:.metadata.name,DIGEST:.status.containerStatuses[*].imageID'
```

Then name the digest. GHCR holds the tag the digest was published under:

```bash
gh api --paginate /orgs/yadgarhq/packages/container/iam-db/versions \
  --jq '.[] | select(.name == "sha256:<digest from above>") | .metadata.container.tags'
```

For a `-db` there is a second, independent check that needs no database session:
the module logs its schema position at boot.

```bash
kubectl --kubeconfig "$CLAUDE_JOB_DIR/tmp/kubeconfig-kind-only.yaml" --context kind-yadgar \
  -n yadgar logs deployment/iam-db | grep 'schema at migration'
```

`iam-db` v0.5.1 carries twelve migrations. A line reading `schema at migration 9`
means migrations 10, 11 and 12 have not run, so `iam_org_setting` does not exist
and the seed row is absent.

### What was running on 2026-09-03

| module    | running | `latest` published | ADR-0522 needs |
| --------- | ------- | ------------------ | -------------- |
| `iam-db`  | 0.5.0   | 0.6.0              | ≥ 0.5.1        |
| `iam`     | 0.7.0   | 0.7.3              | ≥ 0.7.2        |
| `gateway` | 0.8.4   | 0.8.4              | ≥ 0.8.3        |
| `task`    | 0.4.2   | 0.4.3              | ≥ 0.4.3        |
| `task-db` | 0.3.0   | 0.4.2              | ≥ 0.4.1        |

`gateway` already satisfies its link, and only because an unrelated pod-spec
change restarted it. The other four are behind.

**There is no armed outage here, and the last row is why.** `task-db:latest`
resolves to 0.4.2, which carries `setting.rs` and calls it from nowhere, so a
`task-db` restart today changes no behaviour. Roll `iam-db` first all the same:
it is the prerequisite the enforcement car will need in place before it can be
released, and `iam-db` is the link furthest behind. The order below is what makes
that car safe to cut later, not a response to a hazard running now.

### Rolling the stale modules, in prerequisite order

**Check the preconditions first. They hold as of 2026-09-03.** The only boot
gate any of these jumps crosses is `fix!: refuse DB_SSL_MODE=verify_ca`, which
arrives in `iam-db` v0.6.0 and `task-db` v0.4.2. Both Deployments set
`DB_SSL_MODE=required`, so neither refusal fires — but re-read the value before
rolling, because a `-db` that refuses at boot turns this runbook into the outage
it exists to prevent:

```bash
kubectl --kubeconfig "$CLAUDE_JOB_DIR/tmp/kubeconfig-kind-only.yaml" --context kind-yadgar \
  -n yadgar get deploy iam-db task-db \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.template.spec.containers[*].env}{"\n"}{end}'
```

Nothing else across `iam-db` v0.5.0..v0.6.0, `iam` v0.7.0..v0.7.3, `task`
v0.4.2..v0.4.3 or `task-db` v0.3.0..v0.4.2 adds a required variable. `iam`
v0.7.3 mounts a client certificate for `iam-db`, and that is opt-in rather than
a gate: `clientCertSecret` defaults to empty and is empty here.

Then run these yourself, in this order, and wait for each before starting the
next.

```bash
kubectl --kubeconfig "$CLAUDE_JOB_DIR/tmp/kubeconfig-kind-only.yaml" --context kind-yadgar \
  -n yadgar rollout restart deployment/iam-db
kubectl --kubeconfig "$CLAUDE_JOB_DIR/tmp/kubeconfig-kind-only.yaml" --context kind-yadgar \
  -n yadgar rollout status deployment/iam-db

kubectl --kubeconfig "$CLAUDE_JOB_DIR/tmp/kubeconfig-kind-only.yaml" --context kind-yadgar \
  -n yadgar rollout restart deployment/iam
kubectl --kubeconfig "$CLAUDE_JOB_DIR/tmp/kubeconfig-kind-only.yaml" --context kind-yadgar \
  -n yadgar rollout status deployment/iam

kubectl --kubeconfig "$CLAUDE_JOB_DIR/tmp/kubeconfig-kind-only.yaml" --context kind-yadgar \
  -n yadgar rollout restart deployment/task
kubectl --kubeconfig "$CLAUDE_JOB_DIR/tmp/kubeconfig-kind-only.yaml" --context kind-yadgar \
  -n yadgar rollout status deployment/task

kubectl --kubeconfig "$CLAUDE_JOB_DIR/tmp/kubeconfig-kind-only.yaml" --context kind-yadgar \
  -n yadgar rollout restart deployment/task-db
kubectl --kubeconfig "$CLAUDE_JOB_DIR/tmp/kubeconfig-kind-only.yaml" --context kind-yadgar \
  -n yadgar rollout status deployment/task-db
```

After `iam-db` reports ready, confirm the migration line reads `schema at
migration 12` before starting `iam`. That is the check that the seed row now
exists, and it is the one the rest of the chain depends on.

`gateway` needs no restart today: it is already at 0.8.4.

**Expect a second rollout of each Deployment.** All four Applications set
`syncPolicy.automated.selfHeal: true` and none sets `ignoreDifferences`, so Argo
reverts the `kubectl.kubernetes.io/restartedAt` annotation that
`rollout restart` writes into the pod template. Both rollouts pull the same
`latest` digest, so the result is the same either way.
