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

use matrix_crypto_core::{DeviceStatus, FlowStage, SasEmoji, SasMaterial, TrustState};
use matrix_crypto_ffi::{
    DeviceStatus as FfiDeviceStatus, SasMaterial as FfiSasMaterial, TrustState as FfiTrustState,
    VerificationStage,
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
