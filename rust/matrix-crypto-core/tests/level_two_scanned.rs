//! Level 2 for verification by scanning a code: a third-party client's code
//! reaching this library, and this library's code reaching it, over a real
//! homeserver, in all three modes the specification defines.
//!
//! # The question, and why the level 1 files cannot answer it
//!
//! `tests/qr_cross_user.rs`, `tests/qr_self_established_shows.rs` and
//! `tests/qr_self_new_login_shows.rs` drive a bare
//! `matrix_sdk_crypto::OlmMachine` as the counterparty. Both sides are then
//! upstream's own state machine, so a consistent misreading of the payload
//! layout -- ours or upstream's -- passes all three and looks like success.
//! This file asks the question that catches that: **does a code built by
//! people who have never seen this code work against it**, and does ours
//! work against theirs, over a homeserver neither side controls.
//!
//! # The counterparty, and how it was established before anything was built
//!
//! **`matrix-nio` is disqualified twice over.** Grepping the installed 0.26.0
//! wheel finds zero occurrences of the QR vocabulary and zero of the
//! cross-signing vocabulary. A code carries cross-signing keys and nothing
//! else authenticates it, so an implementation with neither cannot scan even
//! in principle. That is the same counterparty that stopped M3 short of a
//! completed comparison and M4 short of a verified identity, and it is why
//! this proof has a second one.
//!
//! **mautrix-go v0.30.0 can.** Read from its source before a line of this
//! file existed, because two milestones in a row assumed a counterparty was
//! capable and it was not:
//!
//! * `crypto/verificationhelper/qrcode.go` builds and parses the payload
//!   against the byte layout in the specification's QR code format section
//!   -- the six-byte header, the version, the mode, the big-endian
//!   identifier length, two keys and a shared secret -- and names all three
//!   modes as `QRCodeModeCrossSigning`,
//!   `QRCodeModeSelfVerifyingMasterKeyTrusted` and
//!   `QRCodeModeSelfVerifyingMasterKeyUntrusted`.
//! * `crypto/verificationhelper/reciprocate.go` reads a scanned payload,
//!   checks the keys **mode by mode** against what it holds, refuses with
//!   `m.key_mismatch` when they do not match, and answers a code it accepts
//!   with `m.key.verification.start` carrying the shared secret.
//! * `crypto/cross_sign*.go` mints, publishes and signs with a real
//!   cross-signing identity over the client-server API, which is the half
//!   `matrix-nio` does not have at all.
//! * `crypto/verificationhelper/verificationhelper.go` speaks the
//!   request/ready/start/done flow to device, which is the shape this
//!   library speaks.
//!
//! None of that is Rust and none of it is `matrix-sdk-crypto`. It does not
//! even share a ratchet: the counterparty is built with `-tags goolm`, which
//! selects mautrix's own pure-Go Olm implementation rather than the C
//! `libolm` binding. So unlike `level_two_interop.rs`, whose floor is the
//! `vodozemac` both sides link, **this proof has no shared crypto floor at
//! all**.
//!
//! # HOW FAR THIS GETS, AND WHERE IT STOPS
//!
//! **All three modes complete.** Each reaches `Done` on both sides and
//! announces a completion here. In every one of them **this library is the
//! side that scans**, and that is not a preference: a flow in which this
//! library shows the code and the counterparty scans it **does not finish
//! against this counterparty**, and the reason is in the counterparty rather
//! than here.
//!
//! **All three end with each side reporting the other verified**, and the
//! cross-user one only does so because of a fix this file used to record the
//! absence of. What that mode produces is a signature over the other person's
//! master key, and this library will not report their devices verified until
//! that signature is read back from the homeserver. Nothing used to queue the
//! key query that reads it back, and no call on the published surface could:
//! `share_scope_key` re-queues nothing for a user already tracked, and
//! `device_lists.changed` is the homeserver's to send. The completion queues
//! it now. Phase 3 asserts the signature was made and posted, and then asserts
//! that the trust state **moved**, with nothing between the two but the
//! ordinary drain-send-report loop.
//!
//! **mautrix-go sends `m.key.verification.done` the instant it accepts a
//! scanned code**, without waiting for the person on the showing side to
//! confirm anything (`reciprocate.go`'s `HandleScannedQRData`: "Immediately
//! send the m.key.verification.done event, as our side of the transaction is
//! done", still present on its `main` branch). The specification puts that
//! message last, after the confirmation: its steps 9 and 10 have the showing
//! device ask its user to confirm that the code was scanned and the user
//! press the button, and only then does step 11 say **"Both devices send an
//! `m.key.verification.done` message."** Step 10 is the whole security
//! argument of the mode, so the ordering is load-bearing rather than
//! cosmetic.
//!
//! `matrix-sdk-crypto` 0.18.0 implements that ordering literally.
//! `QrVerification::receive_done` acts on `Confirmed` and `Reciprocated` and
//! returns `(None, None)` for `Created`, `Scanned`, `Done` and `Cancelled`
//! (`verification/qrcode.rs:441-444`), and the cross-signing signature a
//! verification produces is uploaded in that `Confirmed` to `Done`
//! transition. So an early `done` lands while the code is still `Scanned`,
//! is dropped, and never comes again: this side confirms, reaches
//! `Confirmed`, and stays there.
//!
//! **Phase 2 below measures exactly that**, from the wire rather than by
//! reasoning: it asserts that the counterparty's `done` arrived in the same
//! `/sync` batch as its `start`, before any confirmation could exist, and
//! then that the flow is left `Confirmed` and nothing is verified. A
//! negative result, named and pinned, rather than a phase quietly left out.
//!
//! **A halted flow can be cleared up, and that half was this library's to
//! fix.** Upstream allows one live verification per person and cancels both
//! when a second is opened while the first is neither done nor cancelled
//! (`verification/cache.rs:86-104`), so a halted flow takes the next
//! verifications with that person down with it, silently. The way out is to
//! abandon it, and `cancel_flow` could not: it reached the comparison and the
//! request and not the code, and the request behind a halted flow is already
//! `Done`, so it refused. It reads the code now. **Phase 2 abandons the halt
//! and then verifies the same counterparty afterwards**, which is the whole
//! answer to the finding this file used to record: that phase asserted the
//! refusal, and asserts the recovery instead.
//!
//! `tests/qr_halt_recovery.rs` drives the same sequence at level 1, against a
//! bare upstream machine, with the two silent casualties measured as its
//! control. What this file adds is the counterparty that causes the halt in
//! the first place.
//!
//! **What that costs, honestly stated.** The claim "a foreign client reads
//! the symbol this library renders" is proven here: the counterparty decodes
//! our payload, checks its keys, accepts it when they match and refuses it
//! when one byte does not. The claim "and the flow then finishes" is proven
//! only in the direction where this library scans. The remaining half is
//! what the hardware walkthrough in `packages/example-app` exists for, since
//! the clients a product's users actually hold are not this one.
//!
//! # What is proven here, and in what order
//!
//! Five phases in one test binary, because this library holds one crypto
//! machine per process and Cargo gives each file under `tests/` its own. The
//! order is not arrangement: each phase leaves state the next one needs, and
//! the comments say which.
//!
//! 1. **A refusal, watched, before any agreement.** A cross-user flow whose
//!    code has one byte changed in the master key it carries. The
//!    counterparty decodes it, finds the key is not the one it expects from
//!    us, and cancels with `m.key_mismatch` -- and this library reports the
//!    flow `Cancelled` and verifies nothing.
//! 2. **The same code, untouched, accepted -- and the halt.** One byte apart
//!    from phase 1 and accepted rather than refused, which is what makes the
//!    refusal above a refusal of the change rather than of the format. Then
//!    the ordering defect above, measured. On its own counterparty account,
//!    because it is the account this file deliberately halts a flow on.
//!    Then, on the same counterparty account, **the halt abandoned and that
//!    person verified afterwards**: the same mode driven end to end with the
//!    screens the other way round, ending with this library reporting their
//!    device verified. Nothing between the halt and it but `cancel_flow` and
//!    the ordinary sync loop.
//! 3. **Cross-user, mode `0x00`.** The counterparty shows, this library
//!    scans, the flow finishes on both sides, the counterparty reports this
//!    library's owner verified, and this side's own view of them moves too,
//!    on the key query the completion queues.
//! 4. **Self, mode `0x02`.** A second device logs in to this library's own
//!    account and does not trust the master key, so it shows the untrusted
//!    self mode. This library scans it.
//! 5. **Self, mode `0x01`.** That same device now trusts the master key,
//!    which is what phase 4 gave it, so it shows the trusted self mode. This
//!    library scans that too.
//!
//! Both self modes count separately, and the reason is in the product rather
//! than in the protocol: which mode a flow uses is decided by which device is
//! held up to the other's camera, and a person chooses that.
//!
//! # Code scanning is off unless a build asks
//!
//! `offer_scanning(true)` is called once, at the top, and it is not
//! ceremony: with the switch untouched this library announces `m.sas.v1`
//! alone, no code is ever negotiated, and every phase below would fail at
//! its first code. A product that wants codes turns it on; this test is such
//! a product.
//!
//! # Running it
//!
//! `./scripts/run-level-two-interop.sh`, which starts a throwaway
//! homeserver, builds this counterparty and runs this test alongside its
//! siblings. It needs a Go toolchain for that build and says so when there
//! is none.
//!
//! `#[ignore]`, so an ordinary `cargo test` needs no network, no container,
//! no Go and no credential.

use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use matrix_crypto_core::{
    accept_flow, bootstrap_identity, cancel_flow, confirm_scan, create_machine, device_statuses,
    flow_stage, identity_status, offer_scanning, read_code, receive_sync_changes, request_flow,
    request_self_flow, set_crypto_observer, share_scope_key, submit_scanned_code, CryptoObserver,
    CryptoSignal, FlowId, FlowStage, MachineConfig, TrustState,
};
use serde_json::{json, Value};

#[path = "interop/harness.rs"]
mod harness;
#[path = "interop/scanned_party.rs"]
mod scanned_party;

use harness::{
    encode_segment, encryption_slice, login, pump_and_send, required_env, run, Homeserver,
    Teardown, HOMESERVER_ENV, PASSWORD_ENV,
};
use scanned_party::{
    MautrixParty, PARTY_BINARY_ENV, SCANNED_USER_ENV, SCANNER_USER_ENV, SHOWN_USER_ENV,
};

/// Not a credential: the store lives in a temporary directory this test also
/// deletes, and nothing outside this process opens it.
const STORE_PASSPHRASE: &str = "level-two-scanned";

/// A scope identifier, used for one thing only: `share_scope_key` is this
/// library's published way of saying "I am going to talk to these people",
/// and tracking is what makes a key query for another user happen at all.
/// Nothing is ever encrypted in it and no message is ever sent.
const SCOPE: &str = "!level-two-scanned:localhost";

/// The specification's own cancellation code for a code whose keys are not
/// the ones the reader expected. Matched on the code and never on the
/// human-readable reason beside it, which is the counterparty's prose.
const KEY_MISMATCH: &str = "m.key_mismatch";

/// The message whose position in the sequence phase 2 is about.
const DONE_EVENT: &str = "m.key.verification.done";
const START_EVENT: &str = "m.key.verification.start";

/// How long any one "advance both sides" loop below gets.
///
/// Generous rather than tight: each is bounded by a condition that must
/// become true and ends in an assertion naming what did not happen, so a
/// slow homeserver costs time and a broken one still fails readably rather
/// than hanging.
const PATIENCE: Duration = Duration::from_secs(60);

/// How many syncs phase 2 gives the halt before it calls it a halt.
///
/// A bounded number rather than a deadline, because this one is waiting for
/// something that must **not** happen: the cost of being generous here is
/// paid on every green run, so it is spent deliberately and counted.
const SYNCS_BEFORE_CALLING_IT_A_HALT: usize = 12;

// ---------------------------------------------------------------------------
// The signal channel, recorded
// ---------------------------------------------------------------------------

/// Records what the crypto signal channel delivered, in order.
///
/// A channel rather than a vector, for the reason `sas_two_party.rs` gives:
/// delivery is detached, so a test that looked at a vector at the wrong
/// instant would report an absence that was really a not-yet.
struct Recorder {
    tx: mpsc::Sender<CryptoSignal>,
}

impl CryptoObserver for Recorder {
    fn on_signal(&self, signal: CryptoSignal) {
        let _ = self.tx.send(signal);
    }
}

/// The homeserver, the credential to talk to it with, where the sync cursor
/// has reached, and what the channel has said.
struct Session<'a> {
    homeserver: &'a Homeserver,
    token: String,
    since: String,
    signals: mpsc::Receiver<CryptoSignal>,
    /// Every signal drawn off the channel so far, kept so a phase can ask
    /// what arrived without racing the phase that produced it.
    seen: Vec<CryptoSignal>,
    /// The to-device events of the last `/sync`, as the homeserver wrote
    /// them. Phase 2's whole argument is about which of them arrive
    /// together, so it reads them rather than inferring their order from
    /// what the library did afterwards.
    delivered: Vec<Value>,
    /// The `kind` of every request the pump has handed out and this test has
    /// posted. Phase 3 reads it to tell "the signature was never made" apart
    /// from "the signature was made and has not been read back", which are
    /// different findings with different remedies.
    posted: Vec<String>,
}

impl Session<'_> {
    /// One `/sync`, through the library, with the pump drained afterwards.
    ///
    /// Every sync a product performs goes through `receiveSyncChanges`,
    /// including the ones carrying nothing, and every request the library
    /// hands out is posted and reported. That is the whole of what this test
    /// does on the library's behalf between assertions.
    fn sync(&mut self) {
        let sync = self.homeserver.ok(
            "GET",
            &format!(
                "/_matrix/client/v3/sync?timeout=2000&since={}",
                encode_segment(&self.since)
            ),
            Some(&self.token),
            None,
        );
        self.since = sync["next_batch"]
            .as_str()
            .expect("a /sync response carries a next_batch")
            .to_string();
        self.delivered = sync["to_device"]["events"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        run(receive_sync_changes(&encryption_slice(&sync).to_string()))
            .expect("a real /sync payload must be accepted");

        self.pump();
        // Drawn every turn rather than at the end: delivery is detached, and
        // a channel read only at the end of a phase would be a race with the
        // sync that caused the signal.
        while let Ok(signal) = self.signals.recv_timeout(Duration::from_millis(50)) {
            self.seen.push(signal);
        }
    }

    /// Drains the pump, posts everything it handed out, and records what
    /// kinds those were.
    fn pump(&mut self) {
        for request in pump_and_send(self.homeserver, &self.token) {
            self.posted.push(request.kind);
        }
    }

    /// Syncs until `reached` says so, or fails naming what did not happen.
    fn sync_until(&mut self, what: &str, mut reached: impl FnMut(&mut Self) -> bool) {
        let deadline = Instant::now() + PATIENCE;
        loop {
            self.sync();
            if reached(self) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{what} did not happen within {PATIENCE:?} of syncing and pumping"
            );
        }
    }

    /// Which verification event types the last sync delivered, in the order
    /// the homeserver wrote them.
    fn delivered_types(&self) -> Vec<String> {
        self.delivered
            .iter()
            .filter_map(|event| event["type"].as_str())
            .filter(|kind| kind.starts_with("m.key.verification."))
            .map(str::to_string)
            .collect()
    }

    /// Whether a completion naming this flow has reached the channel.
    fn completed(&self, flow: &FlowId) -> bool {
        self.seen.iter().any(|signal| {
            matches!(signal, CryptoSignal::VerificationCompleted { flow_id } if *flow_id == flow.0)
        })
    }

    /// The identifier a `verification_requested` signal carried, if one has
    /// arrived for that device.
    fn requested_flow(&self, user_id: &str, device_id: &str) -> Option<String> {
        self.seen.iter().find_map(|signal| match signal {
            CryptoSignal::VerificationRequested {
                user,
                device_id: from,
                flow_id,
            } if user == user_id && from == device_id => Some(flow_id.clone()),
            _ => None,
        })
    }
}

// ---------------------------------------------------------------------------
// Reading the library's own answers, through calls a product would make
// ---------------------------------------------------------------------------

/// Whether the library's own device list for that user names the device yet.
fn device_known(user_id: &str, device_id: &str) -> bool {
    run(device_statuses(user_id))
        .expect("the library's machine must be live")
        .into_iter()
        .any(|status| status.device_id == device_id)
}

/// What this library reports about one of the counterparty's devices,
/// through the call a product would make.
fn library_trust(user_id: &str, device_id: &str) -> TrustState {
    run(device_statuses(user_id))
        .expect("the library's machine must be live")
        .into_iter()
        .find(|status| status.device_id == device_id)
        .unwrap_or_else(|| {
            panic!(
                "the library must know the counterparty's device {device_id} before it can \
                 say anything about it"
            )
        })
        .trust
}

fn stage(flow: &FlowId) -> FlowStage {
    run(flow_stage(flow)).unwrap_or_else(|error| {
        panic!("a flow this test created must have a stage, and this one answered {error:?}")
    })
}

// ---------------------------------------------------------------------------
// The payload, read and changed
// ---------------------------------------------------------------------------

/// Where the mode byte sits: six bytes of `MATRIX`, then the version.
const MODE_OFFSET: usize = 7;
/// Where the two-byte, big-endian identifier length sits.
const FLOW_ID_LENGTH_OFFSET: usize = 8;

/// The mode byte, with the two fields in front of it checked first.
///
/// A decoder rather than a claim: every claim made *with* it is an assertion
/// in the phases below. Mirrors `tests/scanned/harness.rs`'s `mode_of`, which
/// serves the level 1 files, and is repeated here rather than shared because
/// that module carries a machine-shaped harness this file has no use for.
fn mode_of(payload: &[u8]) -> u8 {
    assert!(
        payload.starts_with(b"MATRIX"),
        "the specification fixes the first six bytes of a payload; these were {:?}",
        &payload[..payload.len().min(6)]
    );
    assert_eq!(
        payload[6], 0x02,
        "the specification fixes the version byte at 2"
    );
    payload[MODE_OFFSET]
}

/// The same payload with one byte of the first key changed.
///
/// The first key is the master key of whoever is showing the code, which is
/// the whole of what a reader authenticates. Changing a byte of it is exactly
/// the attack the method exists to stop: a code that decodes perfectly and
/// carries somebody else's identity. Everything in front of it -- the header,
/// the version, the mode, the flow identifier -- is left alone, so the
/// counterparty reaches its key check rather than failing to parse.
fn with_a_changed_master_key(payload: &[u8]) -> Vec<u8> {
    let flow_id_length = u16::from_be_bytes([
        payload[FLOW_ID_LENGTH_OFFSET],
        payload[FLOW_ID_LENGTH_OFFSET + 1],
    ]) as usize;
    let first_key = FLOW_ID_LENGTH_OFFSET + 2 + flow_id_length;
    assert!(
        payload.len() >= first_key + 64 + 8,
        "a payload carries two 32-byte keys and at least eight bytes of shared secret \
         after the flow identifier; this one is {} bytes",
        payload.len()
    );
    let mut changed = payload.to_vec();
    // The last byte of the first key rather than the first: a reader that
    // compared only a prefix would still catch a changed first byte, and a
    // proof that a truncated comparison would also pass is not the proof this
    // phase is for.
    changed[first_key + 31] ^= 0x01;
    changed
}

/// The payload as lowercase hexadecimal, which is how it crosses to the
/// counterparty's stdin.
///
/// Hexadecimal rather than base64, and written here rather than pulled in:
/// this crate has no base64 dependency, the whole of what a transport
/// encoding must do here is survive a JSON line, and a new entry in the
/// lockfile for eight lines of arithmetic would be the worse trade. Both
/// directions run on every pass, so a defect in either shows up as a payload
/// that does not decode rather than as a silent difference.
fn as_hex(payload: &[u8]) -> String {
    use std::fmt::Write;
    let mut written = String::with_capacity(payload.len() * 2);
    for byte in payload {
        write!(written, "{byte:02x}").expect("writing to a String cannot fail");
    }
    written
}

fn from_hex(encoded: &str) -> Vec<u8> {
    assert!(
        encoded.len().is_multiple_of(2),
        "a hexadecimal payload has an even number of digits; this one has {}",
        encoded.len()
    );
    (0..encoded.len())
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(&encoded[at..at + 2], 16)
                .expect("the counterparty encodes its payload as lowercase hexadecimal")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs a real homeserver, a credential in the environment, and the mautrix-go \
            counterparty built; run ./scripts/run-level-two-interop.sh"]
fn a_third_party_client_and_this_library_verify_each_other_by_scanning_a_code() {
    let homeserver = Homeserver::new(required_env(HOMESERVER_ENV));
    let user = required_env(SCANNED_USER_ENV);
    let scanner_user = required_env(SCANNER_USER_ENV);
    let shown_user = required_env(SHOWN_USER_ENV);
    let password = required_env(PASSWORD_ENV);
    let party_binary = std::path::PathBuf::from(required_env(PARTY_BINARY_ENV));
    assert!(
        party_binary.is_file(),
        "the mautrix counterparty is not at {}; {PARTY_BINARY_ENV} must name a built binary",
        party_binary.display()
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let library_store = dir.path().join("library-store");

    // ---- 1. The library's device, machine and identity ------------------
    let library = login(&homeserver, &user, &password, "level-two-scanned-library");
    // Declared before anything else exists on the homeserver, and before any
    // counterparty, so an unwind kills the subprocesses first and this then
    // removes what the run created.
    let mut teardown = Teardown::new(&homeserver, &library, &password);

    run(create_machine(MachineConfig {
        user_id: library.user_id.clone(),
        device_id: library.device_id.clone(),
        store_path: library_store.to_string_lossy().into_owned(),
        store_passphrase: Some(STORE_PASSPHRASE.to_string()),
    }))
    .expect("the library's machine must be creatable");

    // Installed before the first sync, which is what this library's own
    // documentation tells a product to do.
    let (tx, rx) = mpsc::channel();
    set_crypto_observer(Arc::new(Recorder { tx }));

    // THE SWITCH. Without this line the library announces `m.sas.v1` alone
    // and no code is negotiated anywhere below. See this file's header.
    offer_scanning(true);

    for _ in 0..8 {
        if pump_and_send(&homeserver, &library.token).is_empty() {
            break;
        }
    }

    let status = run(identity_status()).expect("the machine is live");
    assert!(
        status.account_keys_fetched,
        "the pump above must have had a key query for this account answered, which is \
         what authorises minting an identity: {status:?}"
    );
    assert!(
        !status.identity_known,
        "this proof needs an account whose identity IT mints, so that this device holds \
         the private half. An account that already has one cannot be used: {status:?}"
    );
    run(bootstrap_identity()).expect("an account the server says has no identity may mint one");
    for _ in 0..8 {
        if pump_and_send(&homeserver, &library.token).is_empty() {
            break;
        }
    }
    let status = run(identity_status()).expect("the machine is live");
    assert!(
        status.identity_known && status.private_keys_held,
        "a code in either self mode is signed with this account's own identity, and the \
         cross-user mode signs the other person's with it: {status:?}"
    );

    let initial = homeserver.ok(
        "GET",
        "/_matrix/client/v3/sync?timeout=0",
        Some(&library.token),
        None,
    );
    run(receive_sync_changes(
        &encryption_slice(&initial).to_string(),
    ))
    .expect("a real /sync payload must be accepted");
    pump_and_send(&homeserver, &library.token);

    let mut session = Session {
        homeserver: &homeserver,
        token: library.token.clone(),
        since: initial["next_batch"]
            .as_str()
            .expect("a /sync response carries a next_batch")
            .to_string(),
        signals: rx,
        seen: Vec::new(),
        delivered: Vec::new(),
        posted: Vec::new(),
    };

    // ---- 2. Two cross-user counterparties, on two accounts --------------
    //
    // The second is not a duplicate. Phases 1 and 2 leave a flow that cannot
    // finish, and an unfinished flow makes upstream cancel every later
    // verification with the same *person*
    // (`verification/cache.rs:86-104`). Keeping those two phases on an
    // account of their own is what stops phase 3, which has to complete,
    // from inheriting that.
    let (mut shown_to, shown_user_id, shown_device_id) = cross_user_party(
        &party_binary,
        "shown-to",
        &homeserver,
        &shown_user,
        &library.user_id,
        "level-two-scanned-shown-to",
    );
    let (mut scanner, scanner_user_id, scanner_device_id) = cross_user_party(
        &party_binary,
        "cross-user",
        &homeserver,
        &scanner_user,
        &library.user_id,
        "level-two-scanned-cross-user",
    );
    assert_ne!(
        shown_user_id, scanner_user_id,
        "the two counterparties must be two people, which is the whole point of the \
         second one"
    );

    // And this library learns of both accounts. `share_scope_key` is the
    // published call that starts tracking a user, and tracking is what makes
    // upstream ask for their keys at all; nothing is ever encrypted in the
    // scope it names.
    run(share_scope_key(
        SCOPE,
        &[shown_user_id.clone(), scanner_user_id.clone()],
    ))
    .expect("the library must accept a scope and the users to share with");
    session.sync_until("the library learned both counterparties' devices", |_| {
        device_known(&shown_user_id, &shown_device_id)
            && device_known(&scanner_user_id, &scanner_device_id)
    });
    for (user_id, device_id) in [
        (&shown_user_id, &shown_device_id),
        (&scanner_user_id, &scanner_device_id),
    ] {
        assert_eq!(
            library_trust(user_id, device_id),
            TrustState::Unverified,
            "a device this machine merely knows the keys of is not verified; without \
             this the trust assertions below could pass against a surface that answered \
             the same thing throughout"
        );
    }

    // =====================================================================
    // PHASE 1: A REFUSAL, WATCHED, BEFORE ANY AGREEMENT
    // =====================================================================
    // Everything is real except one byte. Run before anything is verified,
    // so that "nothing was verified" is still observable.
    let refused = open_and_ready(
        &mut session,
        &mut shown_to,
        &shown_user_id,
        &shown_device_id,
    );
    let honest = run(read_code(&refused)).expect("a ready cross-user flow must offer a code");
    assert_eq!(
        mode_of(&honest.payload),
        0x00,
        "a flow with another person uses the cross-signing mode"
    );

    let tampered = with_a_changed_master_key(&honest.payload);
    assert_ne!(
        tampered, honest.payload,
        "the byte this phase changes must actually differ, or the refusal below would be \
         a refusal of the honest code"
    );
    let refusal = shown_to.try_call(json!({
        "op": "scan",
        "flow": refused.0,
        "payload": as_hex(&tampered),
    }));
    assert_eq!(
        refusal["ok"],
        json!(true),
        "the counterparty must answer the command rather than die on it: {refusal}"
    );
    assert_eq!(
        refusal["accepted"],
        json!(false),
        "a code carrying a master key that is not ours must be refused, not accepted. \
         The counterparty said: {refusal}"
    );
    let refusal_text = refusal["refusal"].as_str().unwrap_or_default().to_string();
    assert!(
        refusal_text.contains(KEY_MISMATCH),
        "and refused with the specification's own code for it. It said: {refusal_text}"
    );

    // Observed on the counterparty's own callback as well as in its reply to
    // the command, because those are two different things: the first is what
    // a client using it would be told, and the second is only what the
    // function returned.
    shown_to.drain();
    let cancellations = shown_to.all("cancelled");
    assert_eq!(
        cancellations.len(),
        1,
        "the counterparty must tell its own client the flow is over: {cancellations:?}"
    );
    assert_eq!(
        cancellations[0]["code"],
        json!(KEY_MISMATCH),
        "with the same code: {cancellations:?}"
    );

    // And this library hears the refusal and reports it.
    session.sync_until("the library learned the flow was refused", |_| {
        stage(&refused) == FlowStage::Cancelled
    });
    assert_eq!(
        library_trust(&shown_user_id, &shown_device_id),
        TrustState::Unverified,
        "a refused flow verifies nothing. This is the assertion the phase exists for: a \
         proof that can only ever succeed proves nothing"
    );
    assert!(
        !session.completed(&refused),
        "and a refused flow announces no completion"
    );

    // =====================================================================
    // PHASE 2: THE SAME CODE ACCEPTED, AND THE HALT THAT FOLLOWS
    // =====================================================================
    // One byte apart from phase 1. It is accepted rather than refused, which
    // is what makes the refusal above a refusal of the *change* and not of
    // the format. Then the counterparty's early `done` is measured off the
    // wire and the flow is pinned where it stops. See this file's header.
    let halted = open_and_ready(
        &mut session,
        &mut shown_to,
        &shown_user_id,
        &shown_device_id,
    );
    let shown = run(read_code(&halted)).expect("a ready cross-user flow must offer a code");
    assert_eq!(mode_of(&shown.payload), 0x00);
    assert_eq!(
        shown.modules.len(),
        (shown.width * shown.width) as usize,
        "the symbol is square and row-major, which is what a product draws"
    );
    assert!(
        shown.modules[..7].iter().all(|square| *square)
            && !shown.modules[7]
            && shown.modules[(shown.width - 7) as usize..shown.width as usize]
                .iter()
                .all(|square| *square),
        "and its top row starts and ends with a seven-square finder pattern, so `true` \
         is dark. A product that drew the negative of this would hand a camera a symbol \
         no scanner reads"
    );

    let accepted = shown_to.call(json!({
        "op": "scan",
        "flow": halted.0,
        "payload": as_hex(&shown.payload),
    }));
    assert_eq!(
        accepted["accepted"],
        json!(true),
        "THE RENDERING CLAIM. A foreign implementation decoded the payload this library \
         built, found the two keys it expected inside it, and accepted it. Everything \
         about this call is identical to the refusal above except one byte: {accepted}"
    );

    // The halt, measured off the wire rather than inferred.
    session.sync_until("the library was told its code had been scanned", |_| {
        stage(&halted) == FlowStage::CodeScanned
    });
    let together = session.delivered_types();
    assert!(
        together.iter().any(|kind| kind == START_EVENT)
            && together.iter().any(|kind| kind == DONE_EVENT),
        "THE ATTRIBUTION. The counterparty's `done` must have arrived in the same batch \
         as its `start`, before this side could confirm anything, which is what the \
         specification puts last and what upstream therefore drops. That sync carried \
         {together:?}"
    );

    run(confirm_scan(&halted)).expect("the side that showed a code answers for it");
    pump_and_send(&homeserver, &library.token);
    assert_eq!(
        stage(&halted),
        FlowStage::Confirmed,
        "confirming moves this side to Confirmed, which is where it waits for the other \
         side's `done`"
    );
    // And it waits there. Read tolerantly, because a flow whose *request* is
    // over is eventually retired by the registry sweep even though its code
    // never finished -- so `unknown_flow` is one of the two answers this
    // stall produces, and both of them are "not Done".
    for _ in 0..SYNCS_BEFORE_CALLING_IT_A_HALT {
        session.sync();
        assert_ne!(
            run(flow_stage(&halted)),
            Ok(FlowStage::Done),
            "and there it stops. The `done` that would move this flow to Done was spent \
             while the code was still Scanned, and no second one is coming"
        );
    }
    assert!(
        !session.completed(&halted),
        "so no completion is announced either"
    );
    assert_eq!(
        library_trust(&shown_user_id, &shown_device_id),
        TrustState::Unverified,
        "and nothing is verified, because the cross-signing signature is uploaded in the \
         Confirmed to Done transition this flow never makes"
    );

    // AND IT CAN BE CLEARED UP, WHICH IS THE HALT'S SECOND COST REMOVED AND
    // THE ONE HALF OF THIS FINDING THAT WAS THIS LIBRARY'S TO FIX.
    //
    // Upstream allows one live verification per person: inserting a new one
    // while an older uncancelled one with the same person is in its cache
    // cancels *both* (`verification/cache.rs:86-104`, "Received a new
    // verification whilst another one with the same user is ongoing.
    // Cancelling both verifications"). A halted flow is uncancelled for ever,
    // so it takes the next verifications with that person down with it, and
    // takes them silently: nothing is refused and no error reaches anybody.
    //
    // The way out is to abandon it, which is what a person does with a screen
    // that never finishes. `cancel_flow` could not: it reached the comparison
    // and the request and **not the code**, and the request behind a halted
    // flow is already `Done`, so upstream had nothing left to cancel and the
    // call refused. **This assertion used to be that refusal.** The code
    // handle sitting in the same record is what answers now.
    run(cancel_flow(&halted)).expect("a halted code flow must be abandonable through this surface");
    assert_eq!(
        run(flow_stage(&halted)),
        Ok(FlowStage::Cancelled),
        "and the abandonment must be visible on the flow the caller named, not only in \
         the return value: a product shows a person something on the strength of this"
    );
    // The counterparty is told, which is what frees its own side too.
    pump_and_send(&homeserver, &library.token);

    // =====================================================================
    // PHASE 2b: AND THE SAME COUNTERPARTY IS VERIFIED AFTERWARDS
    // =====================================================================
    // The measurement the abandonment exists for, and it is the one thing a
    // return value cannot show. Same account, same person, same mode; the only
    // difference from a first verification is the halted flow behind it, which
    // was abandoned rather than left.
    //
    // Driven with the screens the other way round from the halt above, because
    // that is the direction that finishes against this counterparty: it shows,
    // this library scans. Phase 2's own measurement is why. What is being
    // proven here is that the *person* is reachable again, not that the
    // counterparty's ordering defect went away.
    //
    // One sync first, and it is not padding. Upstream cancels a new request
    // outright while another request with the same person is still in its map
    // and not cancelled, and a request that finished is not a cancelled one
    // (`verification/machine.rs`'s `insert_request`); the map is emptied at
    // the top of every `receive_sync_changes`. `facade.ts` states that rule
    // where a product author reads it.
    session.sync();
    let recovered = open_and_ready(
        &mut session,
        &mut shown_to,
        &shown_user_id,
        &shown_device_id,
    );
    let their_payload = code_shown_by(&mut shown_to, &recovered, 0x00);
    run(submit_scanned_code(&recovered, &their_payload))
        .expect("this library must read a code the counterparty rendered");
    pump_and_send(&homeserver, &library.token);

    shown_to.sync_until_seen("our_code_scanned");
    let confirmed = shown_to.call(json!({"op": "confirm", "flow": recovered.0}));
    assert_eq!(
        confirmed["confirmed"],
        json!(true),
        "the side that showed the code answers for it: {confirmed}"
    );
    session.sync_until("the library finished the recovered flow", |session| {
        stage(&recovered) == FlowStage::Done && session.completed(&recovered)
    });
    assert_eq!(
        library_trust(&shown_user_id, &shown_device_id),
        TrustState::Verified,
        "THE RECOVERY. After a halted flow with this person was abandoned, a fresh \
         verification with the same person runs end to end and this library reports \
         their device verified. Nothing was done between the halt and this but the \
         cancellation and the ordinary sync loop"
    );

    shown_to.call(json!({"op": "logout"}));
    shown_to.call(json!({"op": "quit"}));
    drop(shown_to);

    // =====================================================================
    // PHASE 3: CROSS-USER, MODE 0x00, WITH THIS LIBRARY SCANNING
    // =====================================================================
    let cross_user = open_and_ready(
        &mut session,
        &mut scanner,
        &scanner_user_id,
        &scanner_device_id,
    );
    let their_payload = code_shown_by(&mut scanner, &cross_user, 0x00);
    run(submit_scanned_code(&cross_user, &their_payload))
        .expect("this library must read a code a third-party client rendered");
    pump_and_send(&homeserver, &library.token);

    scanner.sync_until_seen("our_code_scanned");
    assert!(
        !scanner.saw("cancelled"),
        "the counterparty must not have cancelled anything in this phase: {:?}",
        scanner.all("cancelled")
    );
    let confirmed = scanner.call(json!({"op": "confirm", "flow": cross_user.0}));
    assert_eq!(
        confirmed["confirmed"],
        json!(true),
        "the side that showed the code answers for it: {confirmed}"
    );

    session.sync_until("the library finished the cross-user flow", |session| {
        stage(&cross_user) == FlowStage::Done && session.completed(&cross_user)
    });
    // Both sides, not just this one. The counterparty's own callback is what
    // says its client considers the verification complete, and a phase that
    // asserted only this side's stage would pass against a peer that had
    // given up. After this side, never before it: the counterparty is
    // waiting for the `done` this side sends on reaching `Done`.
    scanner.sync_until_seen("done");
    let their_view = scanner.call(json!({
        "op": "device_trust",
        "user": library.user_id,
        "device": library.device_id,
    }));
    assert_eq!(
        their_view["user_trusted"],
        json!(true),
        "and the counterparty reports this library's owner verified, which is what a \
         cross-user verification is for: {their_view}"
    );

    // WHAT THIS SIDE SAYS, AND THE ASYMMETRY IN IT.
    //
    // The signature was made and posted: upstream signs the other person's
    // master key in the `Confirmed`/`Reciprocated` to `Done` transition and
    // hands the upload to the pump, which this run sent.
    assert!(
        session.posted.iter().any(|kind| kind == "signature_upload"),
        "a cross-user verification signs the other person's master key, and the upload \
         must have reached the pump: {:?}",
        session.posted
    );
    // AND THIS SIDE'S OWN VIEW OF THEM MOVES, WHICH IT DID NOT UNTIL THE
    // COMPLETION LEARNED TO ASK.
    //
    // `device_statuses` answers upstream's `is_verified`, which for another
    // person's device asks whether *their identity* is verified, and an
    // identity is verified by our signature being present on the master key
    // **as the homeserver serves it back**. Nothing marks it locally
    // (`verification/mod.rs:644-649` marks only our own). So making the
    // signature is not enough, and nothing in this library used to queue the
    // `/keys/query` that reads it back: the flow that would have is
    // `device_lists.changed`, which a homeserver reports only for people we
    // share an encrypted scope with, and no call on the published surface can
    // stand in for it (`update_tracked_users` flags only users it newly
    // inserts). This side therefore answered `Unverified` about the person it
    // had just verified, for the life of the process. **This assertion used
    // to be that limit.**
    //
    // `verification::queue_peer_key_queries` queues it now, on the sync that
    // completes the flow. Nothing was done here to help it: the `sync_until`
    // above is the ordinary drain-send-report loop, the same one every other
    // phase runs, and the query went out and came back inside it.
    assert_eq!(
        library_trust(&scanner_user_id, &scanner_device_id),
        TrustState::Verified,
        "a completed cross-user code verification must leave this library reporting the \
         other person's device verified, which needs their master key read back carrying \
         our signature and therefore needs a key query nothing but the completion itself \
         would ever ask for"
    );

    scanner.call(json!({"op": "logout"}));
    scanner.call(json!({"op": "quit"}));
    drop(scanner);

    // =====================================================================
    // PHASE 4: SELF, MODE 0x02, WITH THIS LIBRARY SCANNING
    // =====================================================================
    // A second device on this library's own account. It has just logged in,
    // so it does not trust the master key, and a device that does not trust
    // the master key shows mode 0x02.
    let mut new_login = MautrixParty::start(&party_binary, "self-new-login");
    let new_login_id = self_device(
        &mut new_login,
        &homeserver,
        &library.user_id,
        "level-two-scanned-new-login",
    );
    teardown.owns_device(&new_login_id);
    let untrusted = new_login.call(json!({"op": "identity_state"}));
    assert_eq!(
        untrusted["master_key_trusted"],
        json!(false),
        "a device that has just logged in has signed nothing, and that is what makes the \
         mode below 0x02 rather than 0x01: {untrusted}"
    );

    session.sync_until("the library learned of the new login", |_| {
        device_known(&library.user_id, &new_login_id)
    });

    // The new login opens the flow, which is what a new login does, and is
    // this library's third announcement site.
    new_login.forget();
    let opened = new_login.call(json!({"op": "start_flow", "user": library.user_id}));
    let opened_flow = opened["flow"]
        .as_str()
        .expect("the counterparty reports the flow it opened")
        .to_string();
    session.sync_until("the library was told a verification was asked of it", |s| {
        s.requested_flow(&library.user_id, &new_login_id).is_some()
    });
    let announced = session
        .requested_flow(&library.user_id, &new_login_id)
        .expect("the loop above waited for exactly this");
    assert_eq!(
        announced, opened_flow,
        "the identifier this library announces must be the one the counterparty opened, \
         or a product could not answer the flow it was told about"
    );
    let untrusted_shows = FlowId(announced);
    run(accept_flow(&untrusted_shows)).expect("a flow another device opened may be agreed to");
    pump_and_send(&homeserver, &library.token);

    let their_payload = code_shown_by(&mut new_login, &untrusted_shows, 0x02);
    run(submit_scanned_code(&untrusted_shows, &their_payload))
        .expect("this library must read a code a third-party client rendered");
    pump_and_send(&homeserver, &library.token);

    new_login.sync_until_seen("our_code_scanned");
    let confirmed = new_login.call(json!({"op": "confirm", "flow": untrusted_shows.0}));
    assert_eq!(
        confirmed["confirmed"],
        json!(true),
        "the side that showed the code answers for it: {confirmed}"
    );
    session.sync_until("the library finished the untrusted self flow", |session| {
        stage(&untrusted_shows) == FlowStage::Done && session.completed(&untrusted_shows)
    });
    new_login.sync_until_seen("done");
    assert_eq!(
        library_trust(&library.user_id, &new_login_id),
        TrustState::Verified,
        "after reading a third-party client's code this library reports that device of \
         its own account verified"
    );
    let their_state = new_login.call(json!({"op": "identity_state"}));
    assert_eq!(
        their_state["master_key_trusted"],
        json!(true),
        "and the counterparty now trusts the master key, which is both what a new login \
         gets out of this mode and what makes the next phase the other mode: {their_state}"
    );

    // =====================================================================
    // PHASE 5: SELF, MODE 0x01, WITH THIS LIBRARY SCANNING
    // =====================================================================
    // The same device, which phase 4 left trusting the master key. That one
    // fact is the whole difference between the two self modes, and this
    // phase is what makes it visible: the same counterparty, the same
    // account, the same call, a different mode byte.
    new_login.forget();
    let trusted_shows = FlowId(
        new_login.call(json!({"op": "start_flow", "user": library.user_id}))["flow"]
            .as_str()
            .expect("the counterparty reports the flow it opened")
            .to_string(),
    );
    session.sync_until(
        "the library was told a second verification was asked",
        |_| matches!(run(flow_stage(&trusted_shows)), Ok(FlowStage::Requested)),
    );
    run(accept_flow(&trusted_shows)).expect("a flow another device opened may be agreed to");
    pump_and_send(&homeserver, &library.token);

    let their_payload = code_shown_by(&mut new_login, &trusted_shows, 0x01);
    run(submit_scanned_code(&trusted_shows, &their_payload))
        .expect("this library must read a code a third-party client rendered");
    pump_and_send(&homeserver, &library.token);

    new_login.sync_until_seen("our_code_scanned");
    let confirmed = new_login.call(json!({"op": "confirm", "flow": trusted_shows.0}));
    assert_eq!(
        confirmed["confirmed"],
        json!(true),
        "the side that showed the code answers for it: {confirmed}"
    );
    session.sync_until("the library finished the trusted self flow", |session| {
        stage(&trusted_shows) == FlowStage::Done && session.completed(&trusted_shows)
    });
    new_login.sync_until_seen("done");

    // The library's own self request is driven too, so that the third of the
    // three call sites the switch has to reach is exercised against a real
    // homeserver rather than only in the level 1 files. Nothing scans it:
    // this asks whether the announcement travels and reaches a real second
    // device, and phase 2 has already measured what happens when this
    // counterparty answers a code.
    //
    // One sync first, and it is not padding. Upstream cancels a new request
    // outright while another request with the same person is still in its
    // map and not cancelled, and a *finished* request is not a cancelled one
    // (`verification/machine.rs`'s `insert_request`). The map is emptied at
    // the top of every `receive_sync_changes`, so one sync between two
    // verifications is what a real client does and what this needs. Removing
    // it turns the assertion below into `Cancelled`, which is how the
    // sentence was established.
    session.sync();
    let asked = run(request_self_flow()).expect("this library may ask its own account to verify");
    session.pump();
    assert_eq!(
        stage(&asked),
        FlowStage::Requested,
        "a self request this library opened is waiting for an answer"
    );
    new_login.forget();
    new_login.sync_until_seen("requested");
    assert_eq!(
        new_login.all("requested")[0]["flow"],
        json!(asked.0),
        "and it reached the other device of the account, under the identifier this \
         library handed back"
    );

    new_login.call(json!({"op": "logout"}));
    new_login.call(json!({"op": "quit"}));
    drop(new_login);

    drop(teardown);
}

// ---------------------------------------------------------------------------
// The steps several phases share
// ---------------------------------------------------------------------------

/// Opens a cross-user flow from this library, has the counterparty agree to
/// it, and returns the identifier once the library reports it ready.
///
/// Shared because phases 1 and 2 differ in exactly one byte of one payload
/// and nothing else, which is the whole force of the pair: a control and a
/// change, not two differently written tests.
fn open_and_ready(
    session: &mut Session,
    party: &mut MautrixParty,
    user_id: &str,
    device_id: &str,
) -> FlowId {
    // Forgotten before the request rather than after it, so every assertion
    // below is about this phase's flow and not a sibling's.
    party.forget();
    let flow = run(request_flow(user_id, device_id))
        .expect("the library must be able to ask a device it knows to verify");
    pump_and_send(session.homeserver, &session.token);

    party.sync_until_seen("requested");
    assert_eq!(
        party.all("requested")[0]["flow"],
        json!(flow.0),
        "the counterparty must be asked about the flow this library opened"
    );
    party.call(json!({"op": "accept_flow", "flow": flow.0}));
    session.sync_until("the library's request was agreed to", |_| {
        stage(&flow) == FlowStage::Ready
    });
    flow
}

/// The payload the counterparty is showing for a flow, with its mode
/// asserted.
///
/// The mode is checked here rather than at each call site because it is the
/// one fact each phase is named for, and a phase that read the wrong one
/// would otherwise pass as its sibling.
fn code_shown_by(party: &mut MautrixParty, flow: &FlowId, expected_mode: u8) -> Vec<u8> {
    party.sync_until_seen("ready");
    let offered = party.call(json!({"op": "code", "flow": flow.0}));
    assert_eq!(
        offered["offered"],
        json!(true),
        "the counterparty must have built a code for a flow this library agreed to: \
         {offered}"
    );
    let payload = from_hex(
        offered["payload"]
            .as_str()
            .expect("an offered code carries a payload"),
    );
    assert_eq!(
        mode_of(&payload),
        expected_mode,
        "this phase is named for mode {expected_mode:#04x}"
    );
    payload
}

/// Logs a counterparty in as another *person*, with a cross-signing identity
/// of its own, and has it learn this library's account.
///
/// The identity is not scaffolding: mode `0x00` signs the other person's
/// master key with the user-signing private key, which only the account that
/// minted an identity holds, and `generateQRCode` declines to build a
/// cross-user code at all when its own master key is untrusted.
fn cross_user_party(
    binary: &std::path::Path,
    name: &str,
    homeserver: &Homeserver,
    user: &str,
    library_user_id: &str,
    display_name: &str,
) -> (MautrixParty, String, String) {
    let mut party = MautrixParty::start(binary, name);
    let logged_in = party.call(json!({
        "op": "login",
        "homeserver": homeserver.base,
        "user": user,
        "display_name": display_name,
    }));
    let user_id = logged_in["user_id"]
        .as_str()
        .expect("the counterparty reports its user id")
        .to_string();
    let device_id = logged_in["device_id"]
        .as_str()
        .expect("the counterparty reports its device id")
        .to_string();
    assert_ne!(
        user_id, library_user_id,
        "a cross-user verification needs two different accounts, which is what makes \
         mode 0x00 the mode these phases produce"
    );

    let identity = party.call(json!({"op": "bootstrap_identity"}));
    assert_eq!(
        identity["master_key_trusted"],
        json!(true),
        "the counterparty must trust the identity it just minted, or it will decline to \
         build a cross-user code at all: {identity}"
    );
    party.call(json!({"op": "fetch_keys", "user": library_user_id}));
    (party, user_id, device_id)
}

/// Logs a counterparty in as a second device of this library's own account
/// and has it learn what the account already holds.
///
/// The key fetch is not scaffolding: a device that has not asked the
/// homeserver for its own account's keys holds no master key, and
/// `generateQRCode` declines to build a code at all without one.
fn self_device(
    party: &mut MautrixParty,
    homeserver: &Homeserver,
    user_id: &str,
    display_name: &str,
) -> String {
    let logged_in = party.call(json!({
        "op": "login",
        "homeserver": homeserver.base,
        "user": user_id,
        "display_name": display_name,
    }));
    assert_eq!(
        logged_in["user_id"],
        json!(user_id),
        "a self verification needs both devices on one account: {logged_in}"
    );
    let device_id = logged_in["device_id"]
        .as_str()
        .expect("the counterparty reports its device id")
        .to_string();
    let keys = party.call(json!({"op": "fetch_keys", "user": user_id}));
    assert!(
        keys["master_key"].is_string(),
        "the counterparty must see the identity this library published for the account, \
         or it can build no code in either self mode: {keys}"
    );
    device_id
}
