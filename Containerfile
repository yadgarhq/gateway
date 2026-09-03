# Two shared bases (D63): build fat, ship distroless. The build stage is
# discarded once the binary is copied out, so its size is not a runtime concern.
# `:latest` here is deliberate and is the point of having shared bases. Pinning a
# digest in every Containerfile would mean editing ~61 of them each time a base
# is rebuilt for a CVE — which is how bases stop being rebuilt. The base images
# are themselves built, scanned, signed and digest-pinned by the base-images
# workflow (D61, D63); this is where that indirection is spent.
#
# The ignore must sit IMMEDIATELY before the instruction — a comment in between
# and hadolint does not see it.
# hadolint ignore=DL3007
FROM ghcr.io/yadgarhq/rust-build:latest AS chef
WORKDIR /app

# cargo-chef splits dependency compilation from source compilation, so a
# source-only change does not rebuild the dependency graph.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
COPY . .

# THE VERSION THE BINARY REPORTS OVER MCP, resolved here and nowhere else.
#
# `Cargo.toml` is a placeholder: a module's version in this organisation is its
# release tag (D65), so the tag is the only thing that knows the answer. This is
# the one step in the build that can see it — `ci-release.yaml` builds from a `v*`
# tag, and the checkout it hands to buildkit carries that tag in `.git`.
#
# **IT REFUSES RATHER THAN GUESSES**, and that asymmetry is the reason the
# resolution is here instead of in `build.rs`. A build script cannot tell a release
# build from a local one, so it can only ever fall back silently — and a published
# image reporting a placeholder over a protocol is the state D81 describes: nothing
# red, the wrong thing running. This stage knows it is building an image, so an
# absent tag is a failed build. `ci-pr.yaml` runs hadolint over this file and never
# builds it, so no pull request meets this line.
#
# `ARG VERSION` is the seam for the better fix, which belongs in the shared
# workflow rather than here: `ci-release.yaml` already normalises the tag as
# `needs.detect.outputs.version` and could pass it as a build argument, at which
# point this stops depending on `.git` reaching the build context at all.
#
# DECLARED AFTER `cargo chef cook`, deliberately. An `ARG` before that layer joins
# its cache key, so every release would rebuild the whole dependency graph — the
# one thing cargo-chef is in this file to prevent.
ARG VERSION=""
# musl, so the runtime can be distroless/static rather than distroless/cc — a
# base ten times larger carrying a libc nothing here calls (D63).
RUN set -eu; \
    if [ -z "$VERSION" ]; then \
      VERSION="$(git describe --tags --exact-match HEAD 2>/dev/null)" || { \
        echo "No VERSION build argument and no tag on HEAD. This image would report a placeholder version in its MCP handshake, so the build stops here. Build from a v* tag, or pass --build-arg VERSION=x.y.z." >&2; \
        exit 1; \
      }; \
    fi; \
    YADGAR_GATEWAY_VERSION="$VERSION" \
      cargo build --release --target x86_64-unknown-linux-musl

# hadolint ignore=DL3007
FROM ghcr.io/yadgarhq/runtime:latest
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/yadgar-gateway /yadgar-gateway

# The runtime base already declares this (D63). Repeating it is deliberate: a
# static scanner reads THIS file and cannot follow the base image, so without the
# line the image looks like it runs as root. Stating it also means a future change
# of base cannot silently drop the guarantee.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/yadgar-gateway"]
