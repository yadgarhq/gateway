use std::path::PathBuf;

use super::*;

fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| (*v).to_string())
    }
}

fn password_file(name: &str, contents: &str) -> String {
    let path = std::env::temp_dir().join(format!("gateway-nats-{name}"));
    std::fs::write(&path, contents).expect("the fixture is written");
    path.to_string_lossy().to_string()
}

#[test]
fn subjects_match_the_ones_iam_publishes() {
    // Copied literals rather than a shared constant — see the module comment.
    // If either drifts, the consumer goes quiet rather than failing, so the
    // pair is pinned here as well as exercised over a socket in
    // `tests/credential_invalidation.rs`.
    assert_eq!(subject::CREDENTIAL_REVOKED, "yadgar.iam.credential.revoked");
    assert_eq!(subject::TEAMS_CHANGED, "yadgar.iam.user.teams-changed");
}

#[test]
fn the_gauge_name_is_pinned_by_a_literal() {
    // ADR-0599, and the same shape as `attest`'s pin of `CACHE`. A series
    // name crosses a boundary this repository does not own: a rename is a
    // query that goes blank rather than red, and asserting it THROUGH
    // `CONSUMING` would pass for any rename at all.
    assert_eq!(CONSUMING, "yadgar_gateway_invalidation_consuming");
}

#[test]
fn no_url_is_no_broker_rather_than_an_error() {
    // A LOCAL RUN IS A SUPPORTED DEPLOYMENT. Refusing here would make a
    // developer with no broker unable to start the binary at all.
    assert!(Broker::from_lookup(env_of(&[]))
        .expect("an unconfigured broker is not an error")
        .is_none());
    assert!(Broker::from_lookup(env_of(&[("NATS_URL", "")]))
        .expect("an empty url is the same as an unset one")
        .is_none());
}

#[test]
fn a_url_alone_parses_into_a_broker_carrying_no_credential() {
    // WHAT THIS CHECKS IS THE PARSE, AND ONLY THE PARSE. It used to be named
    // for connecting anonymously, which is a claim about a broker it never
    // dials — and against a broker with an `authorization` block that claim is
    // false: such a server REFUSES a credential-less CONNECT rather than
    // accepting it. What actually happens on the wire is
    // `a_gateway_with_no_credential_is_refused_and_says_so_rather_than_reporting_success`
    // in `tests/credential_invalidation.rs`, over a socket.
    let broker = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "0"),
    ]))
    .expect("a url alone is a usable broker")
    .expect("and it is a broker rather than nothing");
    assert!(broker.credentials.is_none());
}

#[test]
fn the_configured_pair_is_loaded_from_the_file() {
    let path = password_file("full", "sentinel-of-the-file-8a44\n");
    let broker = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "0"),
        ("NATS_USER", "gateway"),
        ("NATS_PASSWORD_FILE", path.as_str()),
    ]))
    .expect("a fully configured broker credential loads")
    .expect("and it is a broker");
    let credentials = broker.credentials.expect("a credential");
    assert_eq!(credentials.user, "gateway");
    // THE TRAILING NEWLINE IS GONE. A password with a `\n` on the end is a
    // different password, and the failure it causes is invisible.
    assert_eq!(credentials.password, "sentinel-of-the-file-8a44");
}

#[test]
fn a_user_with_no_password_refuses_the_boot_rather_than_connecting_anonymously() {
    // THE ARM THAT MATTERS. The tempting implementation returns `Ok(None)`
    // whenever the path is empty, which connects with no credential at all and
    // logs a warning nobody reads — the silent downgrade every other
    // credential in this binary refuses.
    let err = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "0"),
        ("NATS_USER", "gateway"),
    ]))
    .expect_err("an account with no password cannot authenticate");
    assert!(err.contains("NATS_PASSWORD_FILE"), "{err}");
}

#[test]
fn a_password_with_no_user_refuses_the_boot() {
    let path = password_file("no-user", "sentinel-of-the-file-8a44");
    let err = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "0"),
        ("NATS_PASSWORD_FILE", path.as_str()),
    ]))
    .expect_err("a password with no account to present it as cannot authenticate");
    assert!(err.contains("NATS_USER"), "{err}");
}

#[test]
fn an_empty_password_file_refuses_the_boot() {
    // A Secret whose key is present and blank is the ordinary way this goes
    // wrong, and a blank password is not one.
    let path = password_file("empty", "\n");
    let err = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "0"),
        ("NATS_USER", "gateway"),
        ("NATS_PASSWORD_FILE", path.as_str()),
    ]))
    .expect_err("a blank password is not a password");
    assert!(err.contains("empty"), "{err}");
}

#[test]
fn an_unreadable_password_file_refuses_the_boot_naming_the_path() {
    let err = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "0"),
        ("NATS_USER", "gateway"),
        ("NATS_PASSWORD_FILE", "/nowhere/at/all"),
    ]))
    .expect_err("a deployment that asked for a credential and cannot produce one");
    assert!(err.contains("/nowhere/at/all"), "{err}");
}

#[test]
fn a_credential_never_prints_itself() {
    let printed = format!(
        "{:?}",
        BrokerCredentials {
            user: "gateway".into(),
            password: "sentinel-of-the-nats-password".into(),
            password_file: PathBuf::from("/var/run/secrets/nats/password"),
        }
    );
    assert!(
        !printed.contains("sentinel-of-the-nats-password"),
        "{printed}"
    );
    assert!(printed.contains("gateway"), "{printed}");
}

#[tokio::test]
async fn an_unconfigured_broker_reports_that_it_is_not_consuming() {
    // THE HONESTY PROPERTY. `main` writes its boot line from this answer, so a
    // `true` here would be a running system asserting an invalidation path it
    // does not have.
    assert!(!start(None, |_: &str| unreachable!()).await);
}

#[tokio::test]
async fn an_unreachable_broker_reports_that_it_is_not_consuming() {
    assert!(
        !start(
            Some(Broker::new("nats://127.0.0.1:1".to_string(), None)),
            |_: &str| unreachable!()
        )
        .await
    );
}

// ── B-N3: TLS on the broker hop (ADR-0852, ADR-0845) ────────────────────────
//
// THE SWITCH IS REQUIRED WHENEVER A BROKER IS CONFIGURED, with no default in
// the binary or the chart, and it is read through the SAME parser the three gRPC
// hops use (`UpstreamTls::from_lookup` with prefix `NATS`), so the variable
// names and the refusal sentences are those hops' own. What happens on the wire
// is `tests/nats_tls.rs`, against a real TLS nats-server.

/// A certificate in PEM, minted per run: a fixture key in the repository is a
/// secret in the repository, and it expires on a date nobody is watching.
fn a_certificate_pem() -> String {
    let key = rcgen::KeyPair::generate().expect("a key");
    rcgen::CertificateParams::new(vec!["nats".to_string()])
        .expect("params")
        .self_signed(&key)
        .expect("a self-signed certificate")
        .pem()
}

fn a_key_pem() -> String {
    rcgen::KeyPair::generate().expect("a key").serialize_pem()
}

fn tls_file(name: &str, contents: &str) -> String {
    password_file(&format!("tls-{}-{name}", std::process::id()), contents)
}

#[test]
fn a_configured_broker_without_the_tls_switch_refuses_the_boot_naming_it_and_the_chart_key() {
    // ADR-0845: absence is not cleartext. The sentence names the variable AND
    // the chart key an operator edits, which is what makes it actionable.
    let err = Broker::from_lookup(env_of(&[("NATS_URL", "nats://nats:4222")]))
        .expect_err("a broker hop with no TLS switch is a deployment mistake");
    assert!(err.contains("NATS_TLS_ENABLED"), "{err}");
    assert!(err.contains("nats.tls.enabled"), "{err}");
}

#[test]
fn an_empty_tls_switch_is_the_same_refusal_as_an_absent_one() {
    let err = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", ""),
    ]))
    .expect_err("an empty switch is an absent one");
    assert!(err.contains("NATS_TLS_ENABLED"), "{err}");
}

#[test]
fn a_tls_switch_that_is_neither_one_nor_zero_refuses_the_boot() {
    let err = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "true"),
    ]))
    .expect_err("only \"1\" or \"0\"");
    assert!(err.contains("NATS_TLS_ENABLED"), "{err}");
    assert!(err.contains("\"true\""), "{err}");
}

#[test]
fn the_switch_is_not_read_while_the_broker_is_off() {
    // An empty NATS_URL is the chart's own "broker is off" value: there is no
    // hop, so there is no transport to decide.
    assert!(Broker::from_lookup(env_of(&[("NATS_URL", "")]))
        .expect("no broker, no switch to require")
        .is_none());
}

#[test]
fn tls_off_dials_with_no_tls_configuration() {
    let broker = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "0"),
    ]))
    .expect("\"0\" is the explicit cleartext value")
    .expect("a broker");
    assert!(broker.tls().is_none());
}

#[test]
fn tls_on_without_a_ca_bundle_refuses_the_boot() {
    let err = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "1"),
    ]))
    .expect_err("TLS with nothing to verify the broker against");
    assert!(err.contains("NATS_TLS_CA_FILE"), "{err}");
}

#[test]
fn tls_on_with_a_verification_domain_refuses_the_boot() {
    // async-nats verifies the broker against the HOST in NATS_URL and has no
    // override, so a domain this process would silently ignore is refused.
    let ca = tls_file("domain-ca", &a_certificate_pem());
    let err = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "1"),
        ("NATS_TLS_CA_FILE", ca.as_str()),
        ("NATS_TLS_DOMAIN", "nats.example"),
    ]))
    .expect_err("a domain the client cannot honour");
    assert!(err.contains("NATS_TLS_DOMAIN"), "{err}");
    assert!(err.contains("NATS_URL"), "{err}");
}

#[test]
fn a_ca_bundle_holding_no_certificate_refuses_the_boot_naming_the_path() {
    // THE SILENT ONE. A PEM with no `BEGIN CERTIFICATE` section is ZERO trust
    // anchors and no error inside async-nats, so every handshake would fail as
    // an unknown issuer and read as an outage. Refused here instead.
    let ca = tls_file("empty-ca", "not a certificate\n");
    let err = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "1"),
        ("NATS_TLS_CA_FILE", ca.as_str()),
    ]))
    .expect_err("a bundle with nothing in it");
    assert!(err.contains(ca.as_str()), "{err}");
    assert!(err.contains("NATS_TLS_CA_FILE"), "{err}");
}

#[test]
fn an_unreadable_ca_bundle_refuses_the_boot_naming_the_path() {
    let err = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "1"),
        ("NATS_TLS_CA_FILE", "/nowhere/nats-ca.pem"),
    ]))
    .expect_err("an optional CA mount whose Secret is missing is an empty directory");
    assert!(err.contains("/nowhere/nats-ca.pem"), "{err}");
}

#[test]
fn a_client_certificate_without_its_key_refuses_the_boot() {
    let ca = tls_file("half-ca", &a_certificate_pem());
    let cert = tls_file("half-cert", &a_certificate_pem());
    let err = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "1"),
        ("NATS_TLS_CA_FILE", ca.as_str()),
        ("NATS_TLS_CLIENT_CERT_FILE", cert.as_str()),
    ]))
    .expect_err("a certificate cannot be presented without its key");
    assert!(err.contains("NATS_TLS_CLIENT_KEY_FILE"), "{err}");
}

#[test]
fn an_unreadable_client_key_refuses_the_boot_naming_the_path() {
    let ca = tls_file("nokey-ca", &a_certificate_pem());
    let cert = tls_file("nokey-cert", &a_certificate_pem());
    let err = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "1"),
        ("NATS_TLS_CA_FILE", ca.as_str()),
        ("NATS_TLS_CLIENT_CERT_FILE", cert.as_str()),
        ("NATS_TLS_CLIENT_KEY_FILE", "/nowhere/client.key"),
    ]))
    .expect_err("an optional client-cert mount whose Secret is missing");
    assert!(err.contains("/nowhere/client.key"), "{err}");
}

#[test]
fn tls_on_resolves_the_ca_and_the_identity_this_gateway_presents() {
    let ca = tls_file("full-ca", &a_certificate_pem());
    let cert = tls_file("full-cert", &a_certificate_pem());
    let key = tls_file("full-key", &a_key_pem());
    let broker = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "1"),
        ("NATS_TLS_CA_FILE", ca.as_str()),
        ("NATS_TLS_CLIENT_CERT_FILE", cert.as_str()),
        ("NATS_TLS_CLIENT_KEY_FILE", key.as_str()),
    ]))
    .expect("a complete TLS configuration")
    .expect("a broker");
    let tls = broker.tls().expect("TLS is on");
    assert_eq!(tls.ca_file(), std::path::Path::new(&ca));
    assert_eq!(
        tls.client_certificate_file(),
        Some(std::path::Path::new(&cert))
    );
    assert_eq!(tls.client_key_file(), Some(std::path::Path::new(&key)));
}

#[test]
fn the_options_production_dials_with_require_tls_the_ca_and_the_identity() {
    // CONFIGURATION ONLY, and named as such: what the wire does with these is
    // `tests/nats_tls.rs`. This pins that `connect` and the tests there build
    // from ONE function, and that `require_tls` is set — the one option a TLS
    // server cannot reveal, because async-nats upgrades whenever the server
    // asks for TLS.
    let ca = tls_file("opts-ca", &a_certificate_pem());
    let cert = tls_file("opts-cert", &a_certificate_pem());
    let key = tls_file("opts-key", &a_key_pem());
    let broker = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "1"),
        ("NATS_TLS_CA_FILE", ca.as_str()),
        ("NATS_TLS_CLIENT_CERT_FILE", cert.as_str()),
        ("NATS_TLS_CLIENT_KEY_FILE", key.as_str()),
    ]))
    .expect("a complete TLS configuration")
    .expect("a broker");
    let printed = format!("{:?}", broker.connect_options());
    assert!(printed.contains("\"tls_required\": true"), "{printed}");
    assert!(printed.contains(ca.as_str()), "{printed}");
    assert!(printed.contains(cert.as_str()), "{printed}");
    assert!(printed.contains(key.as_str()), "{printed}");

    let plain = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
        ("NATS_TLS_ENABLED", "0"),
    ]))
    .expect("cleartext")
    .expect("a broker");
    assert!(format!("{:?}", plain.connect_options()).contains("\"tls_required\": false"));
}
