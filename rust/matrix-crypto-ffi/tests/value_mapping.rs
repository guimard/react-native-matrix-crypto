//! Which core value becomes which FFI value.
//!
//! `error_mapping.rs`'s hazard, one file over and with two more shapes of
//! it. This crate mirrors four more core types by hand -- `FlowStage`,
//! `TrustState`, `SasMaterial` and `DeviceStatus` -- and every one of them
//! has the property that a wrong arm compiles, passes `clippy -D warnings`,
//! and passes every other test in this repository:
//!
//! * **Two fieldless enums.** Every variant of `FlowStage` is
//!   interchangeable with every other as far as the compiler is concerned,
//!   and so is every variant of `TrustState`. Mapping `Done` to `Cancelled`
//!   presents a refused verification as a completed one; mapping
//!   `Unverified` to `Verified` presents an unverified device as a verified
//!   one, which is the single worst sentence this library could say.
//!   Neither is reachable from the core's own tests, which never cross this
//!   boundary, nor from the TypeScript tests, which mock the boundary away.
//! * **Three same-typed fields on one record.** `SasMaterial`'s three
//!   decimals are `u16`, `u16`, `u16`. Swapping two of them is invisible to
//!   the compiler and produces a short authentication string that differs
//!   from the far side's in a way that looks exactly like a genuine
//!   mismatch -- so the observable symptom of this defect is a verification
//!   that a careful person correctly refuses, every time, for no reason.
//!
//! No machine, no store and no runtime: every `From` impl under test is
//! public, every core type is public and constructible from outside the
//! crate, and none of the conversions touches state. That is why this file
//! runs in no measurable time.

use matrix_crypto_core::{
    CryptoSignal, DeviceStatus, Envelope, FlowStage, SasEmoji, SasMaterial, SenderVerification,
    TrustState,
};
use matrix_crypto_ffi::{
    CryptoSignal as FfiCryptoSignal, DeviceStatus as FfiDeviceStatus, Envelope as FfiEnvelope,
    SasMaterial as FfiSasMaterial, SenderVerification as FfiSenderVerification,
    TrustState as FfiTrustState, VerificationStage,
};

/// All seven stages, each to its own. One assertion per variant rather than
/// a loop, for `error_mapping.rs`'s reason: a loop would need the two enums
/// to be relatable by something other than this mapping, which is the very
/// thing under test.
#[test]
fn every_flow_stage_maps_to_the_matching_ffi_variant() {
    assert!(
        matches!(
            VerificationStage::from(FlowStage::Requested),
            VerificationStage::Requested
        ),
        "FlowStage::Requested must not arrive as another stage"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::Ready),
            VerificationStage::Ready
        ),
        "FlowStage::Ready must not arrive as another stage -- it is the one \
         stage at which a comparison may be started, so a product told \
         anything else waits forever and a product told this one when it is \
         false starts a comparison that is refused"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::Started),
            VerificationStage::Started
        ),
        "FlowStage::Started must not arrive as another stage"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::KeysExchanged),
            VerificationStage::KeysExchanged
        ),
        "FlowStage::KeysExchanged must not arrive as another stage -- it is \
         the one stage at which there is a string to show a person"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::Confirmed),
            VerificationStage::Confirmed
        ),
        "FlowStage::Confirmed must not arrive as another stage -- confirmed \
         is not done, and a product told Done here reports a device verified \
         two messages before it is"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::Done),
            VerificationStage::Done
        ),
        "FlowStage::Done must not arrive as another stage"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::Cancelled),
            VerificationStage::Cancelled
        ),
        "FlowStage::Cancelled must not arrive as another stage -- Done and \
         Cancelled are the two outcomes of a verification and they are \
         opposites, so this pair is the one a swap damages most: a refusal \
         would be presented as a success"
    );
}

/// All three trust values, each to its own.
#[test]
fn every_trust_state_maps_to_the_matching_ffi_variant() {
    assert!(
        matches!(
            FfiTrustState::from(TrustState::Unverified),
            FfiTrustState::Unverified
        ),
        "TrustState::Unverified must not arrive as another value -- reported \
         as Verified it would tell a product a device had been through a \
         comparison that never happened, which is the one sentence this \
         library exists to be able to say truthfully"
    );
    assert!(
        matches!(
            FfiTrustState::from(TrustState::Recognized),
            FfiTrustState::Recognized
        ),
        "TrustState::Recognized must not arrive as another value -- nothing \
         produces it today, which is exactly why nothing else would notice"
    );
    assert!(
        matches!(
            FfiTrustState::from(TrustState::Verified),
            FfiTrustState::Verified
        ),
        "TrustState::Verified must not arrive as another value"
    );
}

/// The three decimals keep their order, and the symbols keep theirs.
///
/// Three distinguishable values, not three equal ones: the point of the
/// test is position, and `(1, 1, 1)` would pass against any permutation.
/// Same for the symbols, which are compared as a sequence rather than a
/// set.
#[test]
fn the_short_authentication_string_crosses_in_the_order_it_was_computed() {
    let crossed = FfiSasMaterial::from(SasMaterial {
        emoji: Some(vec![
            SasEmoji {
                symbol: "first-symbol".to_string(),
                description: "first-word".to_string(),
            },
            SasEmoji {
                symbol: "second-symbol".to_string(),
                description: "second-word".to_string(),
            },
        ]),
        decimals: (1111, 2222, 3333),
    });

    assert_eq!(
        (
            crossed.decimal_one,
            crossed.decimal_two,
            crossed.decimal_three
        ),
        (1111, 2222, 3333),
        "the three decimals must cross in the order they were computed -- a \
         swap here produces a string that differs from the far side's and \
         looks exactly like a genuine mismatch"
    );

    let symbols = crossed
        .emoji
        .expect("a material carrying symbols must still carry them after crossing");
    assert_eq!(
        symbols
            .iter()
            .map(|emoji| emoji.symbol.as_str())
            .collect::<Vec<_>>(),
        vec!["first-symbol", "second-symbol"],
        "the symbols must cross in order"
    );
    assert_eq!(
        symbols
            .iter()
            .map(|emoji| emoji.description.as_str())
            .collect::<Vec<_>>(),
        vec!["first-word", "second-word"],
        "each symbol must keep its own word -- symbol and description have \
         the same type, so a swap between the two fields compiles"
    );
}

/// The symbol-less case, which the protocol produces whenever both sides
/// did not negotiate the symbol form.
///
/// Asserted because `Option::map` over an absent value and an empty vector
/// are easy to confuse in either direction, and a surface that showed seven
/// blank symbols instead of falling back to the digits would be showing a
/// person nothing to compare.
#[test]
fn a_material_with_no_symbols_crosses_with_none_rather_than_an_empty_list() {
    let crossed = FfiSasMaterial::from(SasMaterial {
        emoji: None,
        decimals: (4444, 5555, 6666),
    });

    assert!(
        crossed.emoji.is_none(),
        "an absent symbol form must stay absent, not become an empty list"
    );
    assert_eq!(
        (
            crossed.decimal_one,
            crossed.decimal_two,
            crossed.decimal_three
        ),
        (4444, 5555, 6666),
    );
}

/// A device status keeps its identifier and its trust together.
///
/// The pairing is the whole content of this record: one device reported
/// under another device's identifier is a product showing a verification
/// tick beside the wrong entry in a list.
#[test]
fn a_device_status_keeps_its_identifier_and_its_trust_together() {
    let crossed = FfiDeviceStatus::from(DeviceStatus {
        device_id: "A-DEVICE-IDENTIFIER".to_string(),
        trust: TrustState::Verified,
    });

    assert_eq!(crossed.device_id, "A-DEVICE-IDENTIFIER");
    assert!(matches!(crossed.trust, FfiTrustState::Verified));

    let other = FfiDeviceStatus::from(DeviceStatus {
        device_id: "ANOTHER-DEVICE-IDENTIFIER".to_string(),
        trust: TrustState::Unverified,
    });

    assert_eq!(other.device_id, "ANOTHER-DEVICE-IDENTIFIER");
    assert!(
        matches!(other.trust, FfiTrustState::Unverified),
        "the second status is here so this test fails against an \
         implementation that returns a constant"
    );
}

/// Every sender-verification value this build can produce, each to its own.
///
/// # Why `Verified` is not an input anywhere in this file
///
/// It is not an oversight and it is not laziness. The M3 design ruling on
/// this type (spec section 7, question 3) binds the implementation to two
/// things: document the unreachable values at the type, and keep the
/// test suite free of any case that appears to produce `Verified`. A
/// `From` test taking `SenderVerification::Verified` as a literal is such a
/// case -- read out of context it says this library produces that value,
/// which it does not, and the whole reason the ruling exists is that
/// believing otherwise is the expensive mistake.
///
/// So the `Verified` arm is covered from the other side instead, which is
/// where the danger actually lives. What would hurt is not "`Verified` fails
/// to arrive"; it is "something else arrives *as* `Verified`" -- the same
/// sentence this file's own header calls the worst one this library could
/// say, one enum over. `nothing_this_build_produces_crosses_as_verified`
/// below asserts exactly that, over every value this build can produce, and
/// never constructs a `Verified` to do it. Between the two, the only arm no
/// assertion touches is one the compiler already proves total: the `From`
/// impl matches exhaustively with no wildcard, so the arm exists and a
/// variant added to either side fails the build.
///
/// One assertion per variant rather than a loop, for the reason the flow
/// stage test above gives: a loop would need the two enums to be relatable
/// by something other than this mapping, which is the thing under test.
#[test]
fn every_reachable_sender_verification_maps_to_the_matching_ffi_variant() {
    assert!(
        matches!(
            FfiSenderVerification::from(SenderVerification::UnsignedDevice),
            FfiSenderVerification::UnsignedDevice
        ),
        "the ordinary case for every peer in this build must not arrive as \
         another value"
    );
    assert!(
        matches!(
            FfiSenderVerification::from(SenderVerification::NoDeviceMissing),
            FfiSenderVerification::NoDeviceMissing
        ),
        "a missing device and an insecure source are different reasons and \
         must stay apart across the boundary"
    );
    assert!(
        matches!(
            FfiSenderVerification::from(SenderVerification::NoDeviceInsecureSource),
            FfiSenderVerification::NoDeviceInsecureSource
        ),
        "an insecure source must not arrive as a merely missing device"
    );
    assert!(
        matches!(
            FfiSenderVerification::from(SenderVerification::MismatchedSender),
            FfiSenderVerification::MismatchedSender
        ),
        "the impersonation signal must not arrive as one of its neighbours; \
         folding it is the failure the design ruling on this type names"
    );

    // `UnverifiedIdentity` **is** produced by this build, and this file said
    // otherwise until 0.1.0. It depends on the sender's cross-signing
    // identity rather than on ours, so any peer whose client has
    // cross-signing set up produces it here.
    // `matrix-crypto-core/tests/cross_signed_peer.rs` decrypts an event from
    // one and asserts the value; this assertion is the boundary half of the
    // same claim, and it belongs in the reachable list for that reason.
    assert!(
        matches!(
            FfiSenderVerification::from(SenderVerification::UnverifiedIdentity),
            FfiSenderVerification::UnverifiedIdentity
        ),
        "a device its owner cross-signed, whose owner we have not verified, \
         must not arrive as one of its neighbours: `UnsignedDevice` would \
         understate what is known about the sender and `Verified` would \
         overstate it"
    );

    // `VerificationViolation` genuinely is unreachable here, and unlike
    // `Verified` there is no fixture hazard in naming it: it is not a claim
    // of authenticity. It needs the sender's identity to have been verified
    // by us once, which needs a cross-signing identity of our own, which
    // this build has no way to create.
    assert!(matches!(
        FfiSenderVerification::from(SenderVerification::VerificationViolation),
        FfiSenderVerification::VerificationViolation
    ));
}

/// No value this build produces crosses the boundary as `Verified`.
///
/// The complement of the test above, and the one that would catch the
/// expensive defect. A `From` arm sending `UnsignedDevice` to `Verified`
/// compiles, passes clippy, and passes every other test in this repository
/// -- and it turns "a device this machine has merely heard of" into "this
/// message is guaranteed to be authentic" on a product's screen.
///
/// Constructs no `Verified` of its own, deliberately: see the previous
/// test's doc comment.
#[test]
fn nothing_this_build_produces_crosses_as_verified() {
    for produced in [
        SenderVerification::UnsignedDevice,
        SenderVerification::NoDeviceMissing,
        SenderVerification::NoDeviceInsecureSource,
        SenderVerification::MismatchedSender,
        // `UnverifiedIdentity` is produced by this build, so it is a live
        // entry rather than a precaution: a cross-signed device whose owner
        // we have not verified crossing as `Verified` is exactly the
        // sentence this test exists to forbid, and it is the value most
        // likely to be folded into `Verified` by someone reading
        // "cross-signed" as "trusted".
        SenderVerification::UnverifiedIdentity,
        // Unreachable in this build, and here so that it must arrive as
        // itself on the day it is not.
        SenderVerification::VerificationViolation,
    ] {
        assert!(
            !matches!(
                FfiSenderVerification::from(produced),
                FfiSenderVerification::Verified
            ),
            "{produced:?} crossed the boundary as Verified -- the one value \
             this build cannot honestly report about a decrypted event"
        );
    }
}

/// An envelope carries its authenticity across, and an absent one stays
/// absent.
///
/// Two envelopes, not one: an implementation that hard-codes either answer
/// passes a single-case test. The absent case is the encrypt direction,
/// where there is no such thing as a verification state and `None` says so
/// rather than a value being invented.
#[test]
fn an_envelope_carries_its_authenticity_across_and_an_absent_one_stays_absent() {
    let decrypted = FfiEnvelope::from(Envelope {
        scope: "!s:example.org".to_string(),
        algorithm: "an.algorithm".to_string(),
        event_type: "an.event.type".to_string(),
        ciphertext: b"plaintext".to_vec(),
        sender: "@someone:example.org".to_string(),
        sender_verification: Some(SenderVerification::MismatchedSender),
    });
    assert!(matches!(
        decrypted.sender_verification,
        Some(FfiSenderVerification::MismatchedSender)
    ));

    let encrypted = FfiEnvelope::from(Envelope {
        scope: "!s:example.org".to_string(),
        algorithm: "an.algorithm".to_string(),
        event_type: "an.event.type".to_string(),
        ciphertext: b"ciphertext".to_vec(),
        sender: "@someone:example.org".to_string(),
        sender_verification: None,
    });
    assert!(
        encrypted.sender_verification.is_none(),
        "an absent authenticity must stay absent, not acquire a default -- \
         a default here would be a claim about an event nobody decrypted"
    );
}

/// A trust change keeps the user and the state it belongs to.
#[test]
fn a_trust_change_crosses_with_the_user_it_belongs_to() {
    let crossed = FfiCryptoSignal::from(CryptoSignal::TrustChanged {
        user: "@someone:example.org".to_string(),
        state: TrustState::Verified,
    });

    let FfiCryptoSignal::TrustChanged { user, state } = crossed else {
        panic!("a trust change must cross as one");
    };
    assert_eq!(user, "@someone:example.org");
    assert!(matches!(state, FfiTrustState::Verified));

    let other = FfiCryptoSignal::from(CryptoSignal::TrustChanged {
        user: "@another:example.org".to_string(),
        state: TrustState::Unverified,
    });

    let FfiCryptoSignal::TrustChanged { user, state } = other else {
        panic!("a trust change must cross as one");
    };
    assert_eq!(user, "@another:example.org");
    assert!(
        matches!(state, FfiTrustState::Unverified),
        "the second signal is here so this test fails against an \
         implementation that returns a constant"
    );
}

/// The three strings of an inbound announcement stay in their own fields.
///
/// This is the file's opening hazard in its purest form: `user`,
/// `device_id` and the identifier are all `String`, so any permutation of
/// the three compiles and passes every other test in this repository. The
/// consequence is not cosmetic. The identifier is what a receiving product
/// passes to `acceptVerification`, and it is the whole reason this variant
/// exists -- a swap would hand a product a user id to accept a verification
/// with, and every call it then made would reject with `unknown_flow` for a
/// reason no error message could explain.
///
/// The three fixtures are deliberately distinguishable from one another and
/// from anything a permutation could make look right.
#[test]
fn an_inbound_announcement_keeps_its_three_strings_apart() {
    let crossed = FfiCryptoSignal::from(CryptoSignal::VerificationRequested {
        user: "@the-user:example.org".to_string(),
        device_id: "THE-DEVICE-IDENTIFIER".to_string(),
        flow_id: "the-flow-identifier".to_string(),
    });

    let FfiCryptoSignal::VerificationRequested {
        user,
        device_id,
        verification_id,
    } = crossed
    else {
        panic!("an inbound announcement must cross as one");
    };
    assert_eq!(user, "@the-user:example.org");
    assert_eq!(device_id, "THE-DEVICE-IDENTIFIER");
    assert_eq!(
        verification_id, "the-flow-identifier",
        "the core calls this a flow id and this crate calls it a verification id; they \
         must be the same value, because it is the one a product hands back"
    );
}
