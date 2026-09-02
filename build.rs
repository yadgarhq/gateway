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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");

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
