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
    let broker = Broker::from_lookup(env_of(&[("NATS_URL", "nats://nats:4222")]))
        .expect("a url alone is a usable broker")
        .expect("and it is a broker rather than nothing");
    assert!(broker.credentials.is_none());
}

#[test]
fn the_configured_pair_is_loaded_from_the_file() {
    let path = password_file("full", "sentinel-of-the-file-8a44\n");
    let broker = Broker::from_lookup(env_of(&[
        ("NATS_URL", "nats://nats:4222"),
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
