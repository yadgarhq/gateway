// Types are GENERATED from the vendored contract, never hand-written (D16). The
// protos come from proto/, vendored at the tag in PROTO_VERSION (D70), so this
// build reaches no network and needs no credentials.
use std::path::Path;

/// Where `google/protobuf/*.proto` lives.
///
/// `buf export` deliberately does not emit the well-known types — protoc is
/// expected to supply them — but a SYSTEM protoc only finds them if its include
/// directory is on the path, and where that is depends on how protoc was
/// installed. Debian's `protobuf-compiler` puts them under `/usr/include`; a nix
/// or Homebrew protoc carries its own and needs nothing added.
///
/// So: honour `PROTOC_INCLUDE` when set, otherwise add `/usr/include` if it
/// actually contains them, otherwise add nothing and let protoc use its own.
/// Adding a directory that does not exist makes protoc fail with a worse message
/// than the one this avoids.
fn well_known_include() -> Option<String> {
    if let Ok(dir) = std::env::var("PROTOC_INCLUDE") {
        return Some(dir);
    }
    Path::new("/usr/include/google/protobuf/timestamp.proto")
        .exists()
        .then(|| "/usr/include".to_string())
}

/// What a build with no version reports, and it is deliberately not a number
/// anyone could mistake for a release.
///
/// `Cargo.toml` says `0.0.0` for the same reason: nothing has ever written a
/// version into that manifest, so any plausible-looking number in it is a lie a
/// client would believe. A placeholder that is obviously a placeholder is the
/// whole point — `0.1.0` sat there while the tags ran to `v0.8.1`, and every MCP
/// client was told `0.1.0` over `server/discover`.
const DEV_VERSION: &str = "0.0.0-dev";

/// The version this binary reports in `server/discover`.
///
/// **The tag is the version (D65), and this build script is told it rather than
/// deriving it.** `YADGAR_GATEWAY_VERSION` is the whole input; the `Containerfile`
/// resolves it from the release tag immediately before `cargo build` and FAILS the
/// build if it cannot. That split is not tidiness:
///
/// * A build script cannot tell a release build from a local one, so it can only
///   ever fall back silently. The `Containerfile` knows, so it can refuse — and a
///   release that reports a placeholder over a protocol is exactly the silent
///   wrong state D81 describes.
/// * `cargo:rerun-if-env-changed` is EXACT. Reading git here instead would mean
///   naming the files a tag can arrive in — `HEAD`, the ref HEAD points at,
///   `packed-refs`, `refs/tags` — and a missed one caches a stale version into the
///   binary, which is the same defect as the one this fixes.
///
/// A leading `v` is stripped so a caller may pass a tag name unchanged, exactly as
/// `ci-release.yaml` already normalises `github.ref_name` for the image tag.
fn version() -> String {
    match std::env::var("YADGAR_GATEWAY_VERSION") {
        Ok(v) if !v.trim().is_empty() => v.trim().trim_start_matches('v').to_string(),
        _ => DEV_VERSION.to_string(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");

    // BOTH LINES ARE LOAD-BEARING, and the first one is the easy half to forget.
    // This script already emits `rerun-if-changed`, which switches OFF cargo's
    // default "re-run when anything in the package changes" — so without an
    // explicit declaration a changed version would never re-run this script and
    // the previous number would stay compiled into the binary.
    //
    // `CARGO_PKG_VERSION` is NOT usable at the call site: `env!` reads the
    // manifest's value and cargo does not let a build script override it, which is
    // why this emits a differently named variable.
    println!("cargo:rerun-if-env-changed=YADGAR_GATEWAY_VERSION");
    println!("cargo:rustc-env=YADGAR_GATEWAY_VERSION={}", version());

    let mut includes = vec!["proto".to_string()];
    includes.extend(well_known_include());
    let includes: Vec<&str> = includes.iter().map(String::as_str).collect();

    tonic_prost_build::configure()
        // The gateway serves HTTP, not gRPC — it is a client of every module and a
        // gRPC server to none, so the CLIENT half is the half that gets used.
        //
        // **THE SERVER HALF IS GENERATED FOR THE TESTS, AND FOR NOTHING ELSE.**
        // This said `build_server(false)`, on the grounds that the server half
        // "would produce a service trait nothing implements" — true until identity
        // became an RPC. With every test pointing `iam` at a closed port, the only
        // reachable outcomes on the attested path were "no credential" and "the
        // transport failed": a credential that RESOLVES was untestable, and so was
        // the negative answer `iam` returns as `Ok` with an empty `user_id` —
        // which is an authentication bypass if this gateway reads it as a success.
        // A stub answering as `iam` makes both reachable, and it needs the trait.
        // Nothing outside `#[cfg(test)]` implements one.
        .build_server(true)
        .build_client(true)
        // `yadgar/telemetry/v1` IS VENDORED AND IS DELIBERATELY ABSENT FROM THE
        // LIST BELOW. `iam.proto` began importing it at v1.6.0 — D74's per-user
        // overrides key on D67's `Kind` — so `buf export` now brings the file in
        // through the import closure, and protoc needs it on the include path to
        // resolve that import. Compiling it as well would mint a SECOND `Kind` in
        // this crate, distinct at the type level from the one
        // `yadgar_telemetry::pb` already gives every `Call::start` in `http.rs`,
        // and every boundary between them would need a conversion through `i32`.
        // Pointing the generated code at the shared crate's copy is what keeps
        // one taxonomy for one concept — which is the same argument that put the
        // enum in `telemetry.proto` rather than in `common.proto`.
        .extern_path(
            ".yadgar.telemetry.v1",
            "::yadgar_telemetry::pb::yadgar::telemetry::v1",
        )
        // Every file, not just the entry point: prost generates only for the
        // files it is given, and taskapi.proto merely IMPORTING common.proto does
        // not produce a module for it.
        .compile_protos(
            &[
                "proto/yadgar/common/v1/common.proto",
                "proto/yadgar/task/v1/task.proto",
                "proto/yadgar/taskapi/v1/taskapi.proto",
                "proto/yadgar/iam/v1/iam.proto",
            ],
            &includes[..],
        )?;
    Ok(())
}
