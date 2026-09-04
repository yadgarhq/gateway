//! WHICH FILES THIS DEPLOYMENT WATCHES — the half of the rotation watcher that
//! is this gateway's own.
//!
//! The watcher's behaviour is `yadgar-lifecycle`'s and is tested there, against
//! the atomic `..data` swap kubelet really performs: that a change ends the
//! watch, that an identical-bytes swap does not, that an unreadable mount is
//! survived, that the leaf rather than the issuer is what the gauge reports.
//! None of that is repeated here. What is here is the claim only this repository
//! can make: **a `gateway` configured this way reads exactly these files, so
//! exactly these files are watched.**
//!
//! **THE MUTANT THIS FILE EXISTS TO KILL.** The watch set used to be two chained
//! builder calls in `main.rs`, and no test in this repository spawns the binary
//! — so deleting either compiled, passed the whole suite, and shipped a process
//! that would never notice that file rotating. The old `tests/tls_rotation.rs`
//! could not catch it: it rebuilt the same assembly by hand, so `main.rs` and
//! the test could disagree while both stayed green. Every case below goes
//! through [`yadgar_gateway::rotate::watch_set`] — the SAME function `main.rs`
//! calls — so an upstream deleted from that list turns this red.
//!
//! **THE TWO BUNDLES ARE DIFFERENT AUTHORITIES ON PURPOSE.** One client leaf is
//! presented to both upstreams, so the identity pair de-duplicates to a single
//! entry; if `task` and `iam` also shared a CA bundle, dropping either upstream
//! from the list would change nothing observable and the mutant above would be
//! equivalent rather than killed. Two authorities is what makes it a real kill.
//!
//! CERTIFICATES ARE MINTED PER RUN, for the reason `tests/iam_tls.rs` gives: a
//! fixture key in the repository is a secret in the repository, and it expires on
//! a date nobody is watching.

use std::path::{Path, PathBuf};

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};

use yadgar_gateway::rotate::{self, Presented, CERTIFICATE_NOT_AFTER};
use yadgar_gateway::upstream::{self, UpstreamTls};

/// The CLIENT leaf's expiry, and the only certificate expiry this process has.
const CLIENT_NOT_AFTER: i64 = 1_844_640_000; // 2028-06-15T00:00:00Z

/// One generation of the mount: the file names the chart writes, and their
/// contents.
type Generation = Vec<(String, String)>;

/// The whole mount this process reads: the two CA bundles it verifies its
/// upstreams against, and the ONE client leaf it presents to both (ADR-0516).
///
/// **THERE IS NO SERVING CERTIFICATE HERE, and that is the shape rather than an
/// omission.** This gateway terminates no TLS — the edge leaf belongs to the
/// ingress in front of it (D71, D80) — so the client leaf is the only
/// certificate the process holds, and the only one the expiry gauge can speak
/// for.
///
/// `client.pem` holds the leaf FOLLOWED BY the authority that issued it, which
/// is the shape cert-manager writes.
fn generation() -> Generation {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_after = date_time_ymd(2037, 6, 15);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "yadgar-gateway assembly test authority");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    // A SECOND authority, so the two CA bundles are not byte-identical. Watching
    // one and calling it both would otherwise pass every case in this file.
    let other_key = KeyPair::generate().unwrap();
    let mut other_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    other_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    other_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    other_params.not_after = date_time_ymd(2037, 6, 15);
    other_params.distinguished_name.push(
        DnType::CommonName,
        "yadgar-gateway assembly test authority 2",
    );
    let other = CertifiedIssuer::self_signed(other_params, other_key).unwrap();

    // THE CLIENT LEAF, issued for `client auth` rather than `server auth`
    // (ADR-0516): a peer verifying a client chain refuses a leaf naming the
    // wrong purpose even though it trusts the issuer perfectly well.
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(vec!["gateway-caller".to_string()]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.not_after = date_time_ymd(2028, 6, 15);
    client_params
        .distinguished_name
        .push(DnType::CommonName, "gateway-caller");
    let client_leaf = client_params.signed_by(&client_key, &ca).unwrap();

    vec![
        ("task-ca.pem".to_string(), ca.pem()),
        ("iam-ca.pem".to_string(), other.pem()),
        (
            "client.pem".to_string(),
            format!("{}{}", client_leaf.pem(), ca.pem()),
        ),
        ("client-key.pem".to_string(), client_key.serialize_pem()),
    ]
}

/// A directory shaped the way kubelet shapes a mounted Secret.
///
/// ```text
///   <root>/..1234-5678/client.pem
///   <root>/..data      -> ..1234-5678
///   <root>/client.pem  -> ..data/client.pem
/// ```
///
/// The service is handed `<root>/client.pem` and never learns any of the rest,
/// which is exactly what the chart does: a DIRECTORY mount, never `subPath`,
/// because a `subPath` mount is a one-time copy kubelet never refreshes. The
/// shape is kept here even though nothing below rotates the mount, so that what
/// the configuration names is a symlink through `..data` — the path shape the
/// deployed process actually holds.
struct Mount {
    root: PathBuf,
}

impl Mount {
    fn new(files: &Generation) -> Self {
        let root = std::env::temp_dir().join(format!("yadgar-gateway-assembly-{}", unique()));
        std::fs::create_dir(&root).unwrap();
        let generation = root.join(format!("..{}", unique()));
        std::fs::create_dir(&generation).unwrap();
        for (name, contents) in files {
            std::fs::write(generation.join(name), contents).unwrap();
        }
        std::os::unix::fs::symlink(generation.file_name().unwrap(), root.join("..data")).unwrap();
        for (name, _) in files {
            std::os::unix::fs::symlink(Path::new("..data").join(name), root.join(name)).unwrap();
        }
        Self { root }
    }

    /// The path the SERVICE is given — a symlink through `..data`.
    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A name no other case in this run can collide with.
fn unique() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// How one upstream is verified, and who this gateway says it is on that hop.
///
/// **THE SAME CLIENT LEAF FOR BOTH**, which is what the chart mounts: one
/// `gateway-client-tls`, two upstreams.
///
/// **Built from the configuration rather than from paths spelled out here.** A
/// helper naming four paths would prove only that the watcher watches what it is
/// handed; going through `from_lookup` proves that a deployment's CONFIGURATION
/// puts them there, which is the half that can silently be wrong.
fn upstream_tls(mount: &Mount, prefix: &'static str, ca: &str) -> UpstreamTls {
    let vars = [
        (format!("{prefix}_TLS_ENABLED"), "1".to_string()),
        (
            format!("{prefix}_TLS_CA_FILE"),
            mount.path(ca).display().to_string(),
        ),
        (
            format!("{prefix}_TLS_CLIENT_CERT_FILE"),
            mount.path("client.pem").display().to_string(),
        ),
        (
            format!("{prefix}_TLS_CLIENT_KEY_FILE"),
            mount.path("client-key.pem").display().to_string(),
        ),
    ];
    UpstreamTls::from_lookup(prefix, move |k| {
        vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    })
    .expect("a complete configuration")
    .expect("the flag is set")
}

/// EVERY FILE THE CONFIGURATION NAMED IS IN THE WATCH SET, IN ORDER, AND NOTHING
/// ELSE.
///
/// This is the assertion the whole lift was for. Delete `&task` or `&iam` from
/// the list in `rotate::watch_set` and this case goes red; before the lift the
/// equivalent edit in `main.rs` was a mutant nothing killed.
///
/// **THE ORDER IS THE FOLD'S.** `task`'s bundle, then the shared identity pair
/// in the position it first appeared, then `iam`'s bundle — which is what one
/// client leaf presented to two upstreams looks like once de-duplicated.
#[test]
fn the_watch_set_holds_every_file_this_deployment_configured() {
    let mount = Mount::new(&generation());
    let task = upstream_tls(&mount, upstream::TASK, "task-ca.pem");
    let iam = upstream_tls(&mount, upstream::IAM, "iam-ca.pem");

    assert_eq!(
        rotate::watch_set(Some(&task), Some(&iam)).watched(),
        vec![
            mount.path("task-ca.pem").as_path(),
            mount.path("client.pem").as_path(),
            mount.path("client-key.pem").as_path(),
            mount.path("iam-ca.pem").as_path(),
        ],
        "a fully configured `gateway` reads four files at boot: a bundle per upstream, and \
         the one client identity it presents to both (ADR-0516)"
    );
}

/// THE CLIENT CERTIFICATE IS THE ONE THE GAUGE SPEAKS FOR, and it is recorded as
/// a certificate rather than merely watched.
///
/// A file can be in the watch set without being the leaf the gauge reports —
/// `File::read` puts it there and records no certificate — so this asserts the
/// second half rather than assuming it follows from the first.
///
/// **AND THERE IS NO SERVING LEAF.** This process terminates no TLS, so a
/// `Presented::Serving` that was ever `Some` here would mean an implementation
/// had labelled the client leaf as the thing this gateway serves.
#[test]
fn the_client_certificate_is_the_one_the_gauge_speaks_for() {
    let mount = Mount::new(&generation());
    let task = upstream_tls(&mount, upstream::TASK, "task-ca.pem");
    let iam = upstream_tls(&mount, upstream::IAM, "iam-ca.pem");
    let inputs = rotate::watch_set(Some(&task), Some(&iam));

    assert_eq!(inputs.not_after(Presented::Client), Some(CLIENT_NOT_AFTER));
    assert_eq!(
        inputs.not_after(Presented::Serving),
        None,
        "the edge leaf belongs to the ingress in front of this process (D71, D80)"
    );
}

/// EACH UPSTREAM CONTRIBUTES ON ITS OWN, AND THE SHARED LEAF IS COUNTED ONCE.
///
/// It also pins the cleartext default: with neither upstream configured this
/// process watches nothing and `rotate::watch` idles for the life of the pod.
/// `iam` differs — its enrolment CA (D73) is watched too, and its chart ships a
/// default for it.
#[test]
fn each_configured_half_contributes_on_its_own() {
    let mount = Mount::new(&generation());

    assert!(
        rotate::watch_set(None, None).is_empty(),
        "nothing configured is nothing to watch"
    );

    let task = upstream_tls(&mount, upstream::TASK, "task-ca.pem");
    assert_eq!(
        rotate::watch_set(Some(&task), None).watched(),
        vec![
            mount.path("task-ca.pem").as_path(),
            mount.path("client.pem").as_path(),
            mount.path("client-key.pem").as_path(),
        ],
        "one upstream: its bundle, plus the identity pair"
    );

    let iam = upstream_tls(&mount, upstream::IAM, "iam-ca.pem");
    assert_eq!(
        rotate::watch_set(None, Some(&iam)).watched(),
        vec![
            mount.path("iam-ca.pem").as_path(),
            mount.path("client.pem").as_path(),
            mount.path("client-key.pem").as_path(),
        ],
        "the other upstream on its own names a DIFFERENT bundle, which is what makes \
         dropping either from the list observable"
    );

    // AN ENCRYPTED HOP WITH NO IDENTITY — the state a cut-over passes through,
    // and the default shipped today.
    let vars = [
        ("TASK_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "TASK_TLS_CA_FILE".to_string(),
            mount.path("task-ca.pem").display().to_string(),
        ),
    ];
    let server_only = UpstreamTls::from_lookup(upstream::TASK, move |k| {
        vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    })
    .expect("a complete configuration")
    .expect("the flag is set");
    assert_eq!(
        rotate::watch_set(Some(&server_only), None).watched(),
        vec![mount.path("task-ca.pem").as_path()],
        "an encrypted hop with no identity watches the bundle and nothing else"
    );
}

/// THE GAUGE THIS PROCESS PUBLISHES SAYS `service = "gateway"`.
///
/// The metric NAME belongs to the crate and is asserted there. What belongs here
/// is the label a dashboard selects this service on: `SERVICE` is a constant in
/// `rotate`, and a value that drifted would blank a panel with nothing failing.
///
/// **ONE SERIES HERE, not two.** This process holds only a client leaf, so only
/// `kind = "client"` is published — and under ADR-0516 that is the one whose
/// expiry STOPS a hop, so a gateway with no gauge at all would be blind to its
/// only dated failure.
///
/// A plain `#[test]`: `with_local_recorder` is thread-local and
/// `export_not_after` is synchronous, so there is no runtime to involve.
#[test]
fn the_gauge_names_this_service_and_the_one_certificate_it_holds() {
    let mount = Mount::new(&generation());
    let task = upstream_tls(&mount, upstream::TASK, "task-ca.pem");
    let iam = upstream_tls(&mount, upstream::IAM, "iam-ca.pem");

    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        rotate::watch_set(Some(&task), Some(&iam)).export_not_after()
    });

    let emitted = snapshotter.snapshot().into_vec();
    // A metrics-util built against another `metrics` major links a SECOND
    // facade: everything compiles, nothing is captured, and the assertions below
    // would pass vacuously against an empty snapshot.
    assert_eq!(
        emitted.len(),
        1,
        "one gauge per certificate this process loaded, and this process loads \
         one — check for a duplicate `metrics` crate"
    );
    let (composite, _unit, _description, value) = &emitted[0];
    let key = composite.key();

    assert_eq!(key.name(), CERTIFICATE_NOT_AFTER);
    let labels: Vec<(String, String)> = key
        .labels()
        .map(|l| (l.key().to_string(), l.value().to_string()))
        .collect();
    assert_eq!(
        labels,
        vec![
            ("service".to_string(), "gateway".to_string()),
            ("kind".to_string(), "client".to_string()),
        ],
        "the gateway serves nothing, so the only leaf it can speak for is the one \
         it presents"
    );
    match value {
        DebugValue::Gauge(seconds) => assert_eq!(
            seconds.into_inner(),
            CLIENT_NOT_AFTER as f64,
            "the gauge carries the LOADED leaf's expiry"
        ),
        other => panic!("expected a gauge, got {other:?}"),
    }
}
