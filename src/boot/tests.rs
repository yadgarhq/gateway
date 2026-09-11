use super::{
    bootstrap_path_message, env_required, env_required_allow_empty, refusal, trusted_proxy_hops,
};

// Each test owns a UNIQUE key. `std::env` is process-global and `cargo test`
// runs these on threads of one process, so tests sharing a variable name
// would pass or fail depending on scheduling.

/// The case a naive test omits, and the only one that proves the value is
/// USED. A test that merely asserts "boot succeeds" passes just as happily
/// with a compiled-in default still in place behind the read.
#[test]
fn a_set_value_is_returned_verbatim() {
    std::env::set_var("YADGAR_TEST_REQUIRED_PRESENT", "0.0.0.0:8080");
    assert_eq!(
        env_required("YADGAR_TEST_REQUIRED_PRESENT").as_deref(),
        Ok("0.0.0.0:8080")
    );
}

#[test]
fn an_absent_knob_refuses_and_names_itself() {
    std::env::remove_var("YADGAR_TEST_REQUIRED_ABSENT");
    let err = env_required("YADGAR_TEST_REQUIRED_ABSENT").unwrap_err();
    assert!(
        err.contains("YADGAR_TEST_REQUIRED_ABSENT"),
        "the refusal must name the knob, got: {err}"
    );
    assert!(err.contains("NOT SET"), "got: {err}");
}

/// **THE CASE THAT DISCRIMINATES.** Helm renders an unset value as `""`, so
/// a nulled chart value arrives here as set-but-empty rather than as absent.
/// An implementation that collapses the two into one branch is the defect
/// this estate found three separate times in one week, so the messages are
/// asserted to DIFFER rather than merely to exist.
#[test]
fn an_empty_knob_refuses_with_its_own_message() {
    std::env::set_var("YADGAR_TEST_REQUIRED_EMPTY", "");
    std::env::remove_var("YADGAR_TEST_REQUIRED_EMPTY_ABSENT");
    let empty = env_required("YADGAR_TEST_REQUIRED_EMPTY").unwrap_err();
    let absent = env_required("YADGAR_TEST_REQUIRED_EMPTY_ABSENT").unwrap_err();
    assert!(empty.contains("set but EMPTY"), "got: {empty}");
    assert!(
        empty.replace("YADGAR_TEST_REQUIRED_EMPTY", "K")
            != absent.replace("YADGAR_TEST_REQUIRED_EMPTY_ABSENT", "K"),
        "empty and absent must not share one message"
    );
}

/// The other reader, and the reason it is a separate function: here an empty
/// value is a DECLARED STATE, and only absence refuses.
#[test]
fn allow_empty_accepts_empty_but_still_refuses_absence() {
    std::env::set_var("YADGAR_TEST_ALLOW_EMPTY_SET", "");
    std::env::remove_var("YADGAR_TEST_ALLOW_EMPTY_ABSENT");
    assert_eq!(
        env_required_allow_empty("YADGAR_TEST_ALLOW_EMPTY_SET").as_deref(),
        Ok("")
    );
    let err = env_required_allow_empty("YADGAR_TEST_ALLOW_EMPTY_ABSENT").unwrap_err();
    assert!(err.contains("YADGAR_TEST_ALLOW_EMPTY_ABSENT"), "got: {err}");
}

/// **PINS THE LITERAL THAT SHIPPED FALSE.** Ledger 868: the ENABLED boot-log
/// sentence used to end "and nothing else" after ADR-0655 (amended by
/// ADR-0656) admitted the bootstrap token to `IssueEnrolment`, and nothing
/// asserted the literal — `git grep -ln 'reaches creating an administrator'
/// origin/main -- src tests` matched only the sentence's own file, which is
/// why it shipped through CI green. Hand-typed here, never routed through
/// `bootstrap_path_message`'s own return value on both sides, per ADR-0599.
///
/// MUTATION: restore the old "and nothing else \n (ADR-0492)" wording in
/// `bootstrap_path_message` and this goes red.
#[test]
fn the_enabled_message_names_all_three_verbs_and_the_predicate() {
    assert_eq!(
        bootstrap_path_message(true),
        "the administrative bootstrap path is ENABLED: a bootstrap token is configured, \
         and it reaches creating an administrator, promoting one, and — under a \
         predicate enforced inside iam-db's write, never at this gateway — issuing an \
         enrolment for an administrator holding zero credentials (ADR-0492, ADR-0655, \
         ADR-0656)"
    );
}

/// The argued exception keeps its fallback, and the test says so out loud so
/// that deleting the exception breaks a test rather than passing silently.
#[test]
fn the_trust_boundary_is_undeclared_when_unset() {
    std::env::remove_var("YADGAR_TRUSTED_PROXY_HOPS");
    assert_eq!(trusted_proxy_hops(), "");
    std::env::set_var("YADGAR_TRUSTED_PROXY_HOPS", "1");
    assert_eq!(trusted_proxy_hops(), "1");
    std::env::remove_var("YADGAR_TRUSTED_PROXY_HOPS");
}

/// THE ONE THING LEDGER 733 IS ABOUT, against the REAL error rather than a
/// fixture that could be shaped to pass.
///
/// `tonic::transport::Error`'s whole `Display` is the two words `transport
/// error`, and `BalanceError::Tls` interpolates exactly that — so the sentence
/// `main` used to print for an unusable transport was `TLS could not be
/// configured: transport error`, which names no file, no key and no reason.
/// What went wrong sits one layer BELOW tonic's error and is reachable only by
/// walking `source()`.
///
/// **BOTH RENDERINGS ARE ASSERTED, and the negative one is the point.** A test
/// that only checked `refusal` contains the reason would pass against a
/// `to_string()` that happened to carry it; asserting that `to_string()` does
/// NOT is what shows the layer is genuinely lost, which is the finding rather
/// than a matched absence.
///
/// MUTATION: replace `refusal`'s body with `error.to_string()` and this fails.
///
/// The error is produced by `upstream::connect_iam` — the same call `main`
/// makes — given a bundle that is a real authority and a verification domain
/// `rustls::ServerName` refuses. No listener is involved: `TlsOptions::prepare`
/// runs before anything is resolved or dialled.
#[tokio::test]
async fn a_refusal_carries_the_layer_below_transport_error() {
    let ca = MintedCa::new();
    let tls = upstream_tls(ca.path(), "not a server name");

    let error = yadgar_gateway::upstream::connect_iam("iam", 50051, Some(&tls))
        .await
        .expect_err("a domain rustls cannot parse must refuse before any dial");

    assert!(
        refusal(&error).contains("invalid dns name"),
        "the refusal must carry the layer below tonic's `transport error`; got: {:?}",
        refusal(&error)
    );
    assert!(
        !error.to_string().contains("invalid dns name"),
        "if the head already carried the reason there would be nothing to walk \
         for, and this test would be certifying itself; got: {:?}",
        error.to_string()
    );
}

/// `UpstreamTls` assembled the way a DEPLOYMENT assembles it — through
/// `from_lookup` over the `IAM_TLS_*` names — rather than by hand, so the test
/// cannot configure a shape `main` could never produce.
fn upstream_tls(ca_file: &std::path::Path, domain: &str) -> yadgar_gateway::upstream::UpstreamTls {
    let vars = [
        ("IAM_TLS_ENABLED".to_string(), "1".to_string()),
        ("IAM_TLS_CA_FILE".to_string(), ca_file.display().to_string()),
        ("IAM_TLS_DOMAIN".to_string(), domain.to_string()),
    ];
    yadgar_gateway::upstream::UpstreamTls::from_lookup(yadgar_gateway::upstream::IAM, |key| {
        vars.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.to_string())
    })
    .expect("a flag, a bundle and a domain are a valid configuration")
    .expect("the flag is set, so TLS is on")
}

/// A CA bundle that is a REAL authority, minted per run and deleted after.
///
/// It has to be real: an empty or unparsable bundle is refused by
/// `TlsOptions::prepare` BEFORE the endpoint is built, so it would produce
/// `CaEmpty` and never reach the variant under test. Minted rather than
/// checked in, for the reason every other rig in this repository gives — a
/// fixture key in the repository is a secret in the repository.
///
/// The name carries a COUNTER as well as the pid: `cargo test` runs these on
/// threads of one process, and a clock is a timestamp rather than a nonce
/// (ledger 706, 710, 729).
struct MintedCa(std::path::PathBuf);

impl MintedCa {
    fn new() -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
            KeyUsagePurpose,
        };
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let key = KeyPair::generate().expect("a key pair");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(
            DnType::CommonName,
            "yadgar-gateway boot-refusal test authority",
        );
        let ca = CertifiedIssuer::self_signed(params, key).expect("a self-signed authority");

        let path = std::env::temp_dir().join(format!(
            "yadgar-gateway-refusal-{}-{}.pem",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::write(&path, ca.pem()).expect("the bundle must be written");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for MintedCa {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
