//! Verifying **our own account with the established device holding up its
//! screen**. Mode `0x01`.
//!
//! # The other half of a feature that otherwise works half the time
//!
//! `qr_self_new_login_shows.rs` is the half where the phone being held up is
//! the new one. This is the half where it is the old one, and which half a
//! person gets is decided by which phone they picked up. Both ship or the
//! feature fails for half its users, for a reason no product can see coming.
//!
//! They are separate binaries because this library holds one crypto machine
//! per process: here the library **is** the device that minted the account's
//! signing identity, and there it is the login that holds none of it.
//!
//! # What mode `0x01` says
//!
//! *I am showing you this code and I hold this account's private signing
//! keys.* So the code carries the account's master key first and the
//! **scanning** device's key second, which is the reverse of what the other
//! self mode carries, and a scanner checks its own device key against it.
//! Producing the wrong one of the two is not a cosmetic difference: the
//! scanner would compare the wrong key against the wrong thing and refuse.
//!
//! # Which side is the library
//!
//! **The library is the established device.** The bare `OlmMachine` is a
//! second login of the same account that knows the account's identity exists
//! and holds none of it -- exactly the device `tests/self_verification.rs`
//! makes the library, with the sides swapped.

use matrix_crypto_core::{
    bootstrap_identity, confirm_scan, create_machine, device_statuses, flow_stage, identity_status,
    in_runtime, mark_request_sent, offer_scanning, read_code, request_flow, take_outgoing_requests,
    CryptoSignal, FlowStage, MachineConfig, TrustState,
};
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId, TransactionId};
use matrix_sdk_crypto::matrix_sdk_qrcode::QrVerificationData;
use matrix_sdk_crypto::{OlmMachine, QrVerificationState};

#[path = "scanned/harness.rs"]
mod harness;
use harness::{
    deliver_to_library, deliver_verification_request, device_keys_of, drain_signals,
    drain_to_quiet, every_method, keys_query_response, mode_of, no_signal, one_of,
    pump_bare_to_library, pump_to_bare, queried_users, settle_key_upload, subscribe,
    MODE_SELF_TRUSTED,
};

const ACCOUNT: &str = "@alice:example.org";
/// The library: the device that set the account up.
const MAIN_DEVICE: &str = "FIRSTLOGIN";
/// The bare upstream machine: a login that has just happened.
const NEW_DEVICE: &str = "NEWLOGIN";

#[test]
fn the_device_that_holds_the_identity_shows_a_code_and_a_new_login_scans_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(in_runtime(async move {
        // Before anything syncs, which is what the facade tells a product to
        // do and what this file needs: the channel is silent while nobody is
        // listening, so a subscriber that arrives later has no way to learn
        // that a flow finished while it was away.
        subscribe();
        let account: OwnedUserId = ACCOUNT.parse().expect("a literal user id parses");
        let new_device_id: OwnedDeviceId = NEW_DEVICE.into();

        // The product asks to take part in verification by a scannable code.
        // Off until it does, and off is byte for byte the wire this library
        // put out before codes existed, so without this line every flow
        // below negotiates the short string alone and nothing here can
        // happen. `tests/qr_announcement.rs` is where that default is the
        // subject rather than the setting.
        offer_scanning(true);

        // ---- The login that has just happened ------------------------------
        let new_login = OlmMachine::new(&account, &new_device_id).await;
        settle_key_upload(&new_login).await;
        let new_login_keys =
            serde_json::to_value(device_keys_of(&new_login, &account, &new_device_id).await)
                .expect("upstream device keys serialise");

        // ---- The library ----------------------------------------------------
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: MAIN_DEVICE.to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        let batch = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let upload = one_of(
            &batch,
            "keys_upload",
            "a fresh machine must have keys to publish",
        );
        let upload_body: serde_json::Value =
            serde_json::from_str(&upload.body).expect("the pump's own body is well-formed JSON");
        let main_device_keys = upload_body
            .get("device_keys")
            .cloned()
            .expect("a fresh machine's upload carries its device keys");
        mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
            .await
            .expect("a keys-upload response must be accepted");

        // One answer doing two jobs, both of them a homeserver's: it names
        // no signing identity, which is what lifts `bootstrap_identity`'s
        // ordering gate, and it names the other login's device, which is how
        // this device comes to know a device of its own account exists at
        // all.
        let account_query = batch
            .iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == ACCOUNT)
            })
            .expect("a fresh machine must owe a key query for its own account");
        mark_request_sent(
            &account_query.id,
            &serde_json::json!({
                "device_keys": { ACCOUNT: { NEW_DEVICE: new_login_keys } },
            })
            .to_string(),
        )
        .await
        .expect("answering the account key query must not fail");

        // ---- This device mints the account's identity ------------------------
        bootstrap_identity()
            .await
            .expect("an account with no identity may mint one");
        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .private_keys_held,
            "the mode this file is about is the one a device shows when it *does* \
             hold the account's private signing keys. Against a device that did not, \
             the library would produce the other self mode and this test would be \
             measuring its sibling"
        );

        let published = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let signing_keys = one_of(
            &published,
            "signing_keys_upload",
            "a bootstrap must publish the identity it minted",
        );
        let identity: serde_json::Value = serde_json::from_str(&signing_keys.body)
            .expect("the pump's own body is well-formed JSON");
        let master_key = identity
            .get("master_key")
            .cloned()
            .expect("a published identity carries a master key");
        let self_signing_key = identity
            .get("self_signing_key")
            .cloned()
            .expect("a published identity carries a self-signing key");
        let user_signing_key = identity
            .get("user_signing_key")
            .cloned()
            .expect("a published identity carries a user-signing key");
        for request in &published {
            mark_request_sent(&request.id, "{}")
                .await
                .expect("a bootstrap publication response must be accepted");
        }

        // ---- The new login learns what the account published -----------------
        //
        // The public identity and nothing private, which is exactly what a
        // `/keys/query` gives a device that has just logged in. It is enough
        // to scan with: upstream's scan needs the account's *public* master
        // key on both sides, and the private seeds only on the side that
        // signs afterwards.
        new_login
            .mark_request_as_sent(
                &TransactionId::new(),
                &keys_query_response(
                    &serde_json::json!({
                        "device_keys": { ACCOUNT: { MAIN_DEVICE: main_device_keys } },
                        "master_keys": { ACCOUNT: master_key },
                        "self_signing_keys": { ACCOUNT: self_signing_key },
                        "user_signing_keys": { ACCOUNT: user_signing_key },
                    })
                    .to_string(),
                ),
            )
            .await
            .expect("the bare machine must accept a keys-query response");

        // ---- The flow ---------------------------------------------------------
        //
        // `request_flow` naming the other device, not `request_self_flow`:
        // this device knows exactly which of its owner's devices is in front
        // of them, because its owner is holding it. The fan-out call is for
        // the device that does not, and it would exclude this new login
        // anyway -- the identity has not signed it yet, which is the whole
        // point of the flow.
        let flow = request_flow(ACCOUNT, NEW_DEVICE)
            .await
            .expect("a device of this account can be asked to verify itself");
        pump_to_bare(&new_login, ACCOUNT, ACCOUNT, NEW_DEVICE).await;

        let peer_request = new_login
            .get_verification_request(&account, &flow.0)
            .expect("the new login must have received the invitation");
        let ready = peer_request
            .accept_with_methods(every_method())
            .expect("a fresh invitation can be accepted");
        deliver_verification_request(&ready, ACCOUNT, ACCOUNT, MAIN_DEVICE).await;
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Ready,
            "the other device agreed, so the flow is where a code would be produced"
        );

        // ---- The code ----------------------------------------------------------
        let code = read_code(&flow)
            .await
            .expect("the device holding the account's keys can show a code for it");
        assert_eq!(
            mode_of(&code.payload),
            MODE_SELF_TRUSTED,
            "a device showing a code for its own account while holding the account's \
             private signing keys must say so in the code. The other self mode puts \
             the *showing* device's key first, so a scanner reading this one under \
             that mode would compare the wrong key against the wrong thing"
        );
        // ---- the polarity of the grid, which nothing else here reads ------
        //
        // `true` means dark. A mapping the other way round produces the
        // photographic negative of a valid code, which most scanners refuse
        // and some read as a different code -- and it changes no length, no
        // width and no payload byte, so every other assertion in this
        // repository passes against it. The only other thing that would
        // catch it is a person holding a phone at the end of the milestone,
        // which is the most expensive check there is and the last one.
        //
        // The top row of a symbol carries a finder pattern at each end:
        // seven dark squares, then one light separator between the finder
        // and the data. Read off the drawn grid at both corners, so this
        // cannot pass on one that happened to be dark.
        assert_eq!(
            code.width,
            harness::SYMBOL_WIDTH,
            "upstream fixes the version of every one of these symbols, so a \
             different side means it stopped doing that and the finder patterns \
             below are being read at the wrong offsets"
        );
        let side = harness::SYMBOL_WIDTH as usize;
        let top = harness::row_of(&code, 0);
        assert!(
            top[..7].iter().all(|square| *square) && !top[7],
            "the top-left finder must be seven dark squares and then a light \
             separator. An inverted grid is the photographic negative of a valid \
             code and is what a product would hand to a camera: {:?}",
            &top[..8]
        );
        assert!(
            top[side - 7..].iter().all(|square| *square) && !top[side - 8],
            "and the top-right finder the same: {:?}",
            &top[side - 8..]
        );

        // ---- The stages a scanned flow passes through ---------------------------
        //
        // Collected as one sequence and compared once at the end rather than
        // asserted one at a time. Three separate assertions would all pass
        // against a mapping that answered every question with whatever it
        // was handed, and answering every question the same way is exactly
        // the defect this measures: before the code handle was read, a flow
        // that had become a code reported `Started` from the moment it
        // transitioned until the moment it finished, so a product could not
        // tell "nobody has scanned this yet" from "somebody has, and a
        // person must now say whether it was them".
        let mut stages = vec![flow_stage(&flow).await.expect("the flow exists")];

        // ---- The new login scans it ---------------------------------------------
        let scanned = QrVerificationData::from_bytes(&code.payload)
            .expect("what this library produced must decode as what the format defines");
        let peer_code = peer_request
            .scan_qr_code(scanned)
            .await
            .expect("a new login that knows the account's identity can scan its code")
            .expect("a ready flow that announced scanning produces a code object");
        assert!(
            matches!(peer_code.state(), QrVerificationState::Reciprocated),
            "the side that scanned owes the other one a message: {:?}",
            peer_code.state()
        );
        let reciprocation = peer_code
            .reciprocate()
            .expect("a scanner must tell the other side it scanned");
        deliver_verification_request(&reciprocation, ACCOUNT, ACCOUNT, MAIN_DEVICE).await;
        stages.push(flow_stage(&flow).await.expect("the flow exists"));

        // ---- The person says it really was their new phone -----------------------
        confirm_scan(&flow)
            .await
            .expect("a code somebody has scanned can be confirmed");
        stages.push(flow_stage(&flow).await.expect("the flow exists"));
        assert_eq!(
            stages,
            vec![
                FlowStage::Started,
                FlowStage::CodeScanned,
                FlowStage::Confirmed
            ],
            "showing a code, having it scanned and confirming the scan are three \
             different situations for the person holding this phone: wait, answer, \
             and wait again. The middle one is the only moment a code flow asks \
             anything of a person, and it is the one `confirm_scan` may be called at"
        );
        let crossed = pump_to_bare(&new_login, ACCOUNT, ACCOUNT, NEW_DEVICE).await;
        assert!(
            crossed.contains(&"m.key.verification.done".to_string()),
            "confirming a scan must reach the other device through the pump: {crossed:?}"
        );
        // Everything this account's own bootstrap and this flow's earlier
        // syncs announced is cleared here, so what is asserted below is what
        // the one remaining sync produced. **This cut is what stops the
        // assertion being vacuous**, and in the sibling mode it demonstrably
        // is: a `TrustChanged` for this very account arrives on its own from
        // the seeds, and a test that merely looked for one passed with the
        // producer under test deleted outright.
        drain_to_quiet();
        let crossed = pump_bare_to_library(&new_login, ACCOUNT, ACCOUNT, MAIN_DEVICE).await;
        assert!(
            crossed.contains(&"m.key.verification.done".to_string()),
            "the other device's acknowledgement must reach the library: {crossed:?}"
        );

        // ---- What a product is told ---------------------------------------------
        //
        // The whole vector, not a `contains`. This is the one mode of the
        // three where the completed code names a device, so it is the one
        // where announcing a trust change instead would have been truthful
        // and the one where a product would have seen it working. It does
        // not, on purpose: the two self modes are chosen by which phone a
        // person picks up, so a signal only this one emitted would reach
        // half the users of a product that had tested it.
        let signals = drain_signals("a code this device showed was scanned and confirmed");
        assert_eq!(
            signals,
            vec![CryptoSignal::VerificationCompleted {
                flow_id: flow.0.clone(),
            }],
            "a product that verified by code has nothing to poll: no call returns \
             when the other side acknowledges, and without this it would learn that \
             its own verification succeeded only by asking again and again"
        );

        // Announced once, not on every sync from here on. A standing report
        // is indistinguishable from an arrival to anything acting on it, and
        // this channel exists to be acted on rather than polled. The sync
        // below carries nothing, so the only thing that could produce a
        // signal is a producer with no mark behind it.
        deliver_to_library(Vec::new()).await;
        no_signal("a flow finishes once, so its completion is announced once");

        assert!(
            peer_code.is_done(),
            "the other device must have finished the flow: {:?}",
            peer_code.state()
        );
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Done,
            "a flow that finished by scanning must report that it finished"
        );

        // ---- What the flow was for ------------------------------------------------
        //
        // This side holds the private keys, so this side is the one that
        // signs: a device of our own is signed with the account's
        // self-signing key, which is what makes the new login a device of
        // this account as far as everybody else is concerned.
        let owed = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let signature = one_of(
            &owed,
            "signature_upload",
            "the device holding the private keys must sign the one it just verified",
        );
        assert!(
            signature.body.contains(NEW_DEVICE),
            "the signature must be over the device that was verified: {}",
            signature.body
        );

        let statuses = device_statuses(ACCOUNT)
            .await
            .expect("reading device statuses must not fail");
        assert!(
            statuses.iter().any(
                |status| status.device_id == NEW_DEVICE && status.trust == TrustState::Verified
            ),
            "the device that scanned this one's code must read verified: {statuses:?}"
        );
    }));
}
