//! Which core error variant becomes which FFI error variant.
//!
//! This crate mirrors two core error enums by hand,
//! `From<matrix_crypto_core::SessionError> for SessionFfiError` and
//! `From<matrix_crypto_core::MachineError> for MachineFfiError`. Both matches
//! are exhaustive with no wildcard arm, so a *new* upstream variant fails the
//! build. Nothing checked that the existing arms point anywhere sensible:
//! **swapping two same-shaped variants compiles, passes
//! `clippy -D warnings`, and passes every Rust and TypeScript test**, because
//! the mapping is only exercised on failure paths and the TypeScript layer
//! drives its own `toCryptoError` from hand-written fixtures rather than from
//! these impls. `gate:drift` cannot see it either: the enum *declarations* are
//! unchanged, so the regenerated bindings are byte-identical.
//!
//! That is the same "two values, one type" hazard `delegate_order.rs` exists
//! for, one layer over, and it matters more than its size suggests: the
//! decryption taxonomy these variants carry took a full review round to settle
//! in Task 6, precisely because `MissingKey`, `UnsharedSession`,
//! `SessionRefused`, `UnknownDevice` and `Undecryptable` call for five
//! different product responses. A swap here silently tells a product to
//! retry what it should never retry, or to give up on what a retry would
//! fix -- `UnsharedSession` and `SessionRefused` are the sharpest version of
//! that risk: same shape, opposite retriability, split apart for exactly
//! this reason (G26 in the milestone's own ledger).
//!
//! No machine, no store, no runtime, and no failure path: both `From` impls
//! are public, both core enums are public and not `#[non_exhaustive]`, and
//! their variants are constructible from outside the crate. So the mapping is
//! asserted directly, which is why this file runs in no measurable time.

use matrix_crypto_core::{MachineError, SessionError};
use matrix_crypto_ffi::{MachineFfiError, SessionFfiError};

/// All ten `SessionError` variants, each to its own kind.
///
/// One assertion per variant rather than a loop: a loop would need the two
/// enums to be relatable by something other than this mapping, which is the
/// very thing under test.
#[test]
fn every_session_error_maps_to_the_matching_ffi_variant() {
    assert!(
        matches!(
            SessionFfiError::from(SessionError::MalformedPayload),
            SessionFfiError::MalformedPayload
        ),
        "SessionError::MalformedPayload must not arrive as another kind"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::NotInitialised),
            SessionFfiError::NotInitialised
        ),
        "SessionError::NotInitialised must not arrive as another kind"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::Failed),
            SessionFfiError::Failed
        ),
        "SessionError::Failed must not arrive as another kind"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::UnknownRequest),
            SessionFfiError::UnknownRequest
        ),
        "SessionError::UnknownRequest must not arrive as another kind"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::MalformedIdentifier),
            SessionFfiError::MalformedIdentifier
        ),
        "SessionError::MalformedIdentifier must not arrive as another kind -- \
         it is fieldless and same-shaped as MalformedPayload, and the whole \
         point of the split is that a caller with a bad scope is not sent to \
         inspect a payload that is fine"
    );

    // The five decryption kinds. These are the ones a swap damages most:
    // each names a different product response, and all five are fieldless,
    // so the compiler cannot tell them apart.
    assert!(
        matches!(
            SessionFfiError::from(SessionError::MissingKey),
            SessionFfiError::MissingKey
        ),
        "SessionError::MissingKey must not arrive as another kind -- it is \
         retriable, and a product told UnsharedSession or SessionRefused \
         instead may stop asking, or ask forever"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::UnsharedSession),
            SessionFfiError::UnsharedSession
        ),
        "SessionError::UnsharedSession must not arrive as another kind -- it \
         is the circumstantial half of the withheld-code split and stays \
         retriable, and a product told SessionRefused instead may give up on \
         a withheld session a later attempt could still resolve"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::SessionRefused),
            SessionFfiError::SessionRefused
        ),
        "SessionError::SessionRefused must not arrive as another kind -- it \
         is the policy half of the withheld-code split (G26) and is never \
         retriable, and a product told UnsharedSession instead may retry a \
         deliberate blacklist or unauthorised refusal forever, at real cost \
         in battery and network for a retry that can never succeed"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::UnknownDevice),
            SessionFfiError::UnknownDevice
        ),
        "SessionError::UnknownDevice must not arrive as another kind"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::Undecryptable),
            SessionFfiError::Undecryptable
        ),
        "SessionError::Undecryptable must not arrive as another kind -- it is \
         the one that is never worth retrying"
    );
}

/// All five `MachineError` variants, each to its own kind, and both
/// `detail`-carrying variants checked for the payload as well as the kind.
///
/// The two field-carrying variants are the ones a swap could hide behind a
/// kind-only check: `MalformedIdentifier` and `Store` have identical shapes,
/// so mapping either to the other type-checks and would carry the detail
/// along with it.
#[test]
fn every_machine_error_maps_to_the_matching_ffi_variant() {
    assert!(
        matches!(
            MachineFfiError::from(MachineError::NotInitialised),
            MachineFfiError::NotInitialised
        ),
        "MachineError::NotInitialised must not arrive as another kind"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::AlreadyInitialised),
            MachineFfiError::AlreadyInitialised
        ),
        "MachineError::AlreadyInitialised must not arrive as another kind"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::MismatchedAccount),
            MachineFfiError::MismatchedAccount
        ),
        "MachineError::MismatchedAccount must not arrive as another kind -- it \
         is the recoverable configuration mistake, deliberately kept distinct \
         from the storage failure Store covers"
    );

    // Distinguishable per variant, so a swap between the two same-shaped
    // variants changes the observed detail as well as the kind. Neither
    // value is a real identifier: this crate's `detail` carries a category
    // label, never the identifier itself.
    let identifier_detail = "detail-from-the-identifier-variant";
    assert!(
        matches!(
            MachineFfiError::from(MachineError::MalformedIdentifier {
                detail: identifier_detail.to_string()
            }),
            MachineFfiError::MalformedIdentifier { detail } if detail == identifier_detail
        ),
        "MachineError::MalformedIdentifier must arrive as the same kind, carrying \
         the same detail"
    );

    let store_detail = "detail-from-the-store-variant";
    assert!(
        matches!(
            MachineFfiError::from(MachineError::Store {
                detail: store_detail.to_string()
            }),
            MachineFfiError::Store { detail } if detail == store_detail
        ),
        "MachineError::Store must arrive as the same kind, carrying the same \
         detail -- it has the same shape as MalformedIdentifier, so a swap \
         between them type-checks and carries the detail along with it"
    );
}
