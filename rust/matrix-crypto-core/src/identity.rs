use matrix_sdk_common::ruma::OwnedUserId;

use crate::machine::MachineError;

/// The device's own public identity keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeys {
    pub curve25519: String,
    pub ed25519: String,
}

/// The live machine's own public identity keys.
///
/// The identifiers are checked rather than used: the machine already knows
/// who it is, and a caller who disagrees is a caller about to attribute these
/// keys to the wrong identity.
pub async fn device_identity_keys(
    user_id: &str,
    device_id: &str,
) -> Result<IdentityKeys, MachineError> {
    // Owned before the closure, not borrowed: `with_machine` now runs its
    // whole call inside `in_runtime`, which requires the closure to be
    // `Send + 'static` (see its doc comment) -- a closure borrowing these
    // `&str` parameters would tie it to this call's stack frame instead.
    let user_id = user_id.to_owned();
    let device_id = device_id.to_owned();

    // `Box::pin(async move { ... })`, not an async closure: `with_machine`
    // takes `MachineFuture`, a boxed future, not `AsyncFnOnce` -- see its
    // doc comment for why an async closure does not work here.
    crate::machine::with_machine(move |machine| {
        Box::pin(async move {
            if machine.user_id().as_str() != user_id || machine.device_id().as_str() != device_id {
                return Err(MachineError::MalformedIdentifier {
                    detail: "identifiers do not match the active machine".to_string(),
                });
            }
            let keys = machine.identity_keys();
            Ok(IdentityKeys {
                curve25519: keys.curve25519.to_base64(),
                ed25519: keys.ed25519.to_base64(),
            })
        })
    })
    .await?
}

/// What this library is prepared to say about one device.
///
/// Three values, one of which this build cannot produce -- see
/// [`TrustState::Recognized`]. The set is deliberately closed, and its
/// TypeScript mirror is a closed string union for the same reason: a
/// product branching on trust has to be told when a value it has never
/// seen appears, rather than handed an open type that compiles either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    /// This machine holds the device's keys and has no reason to trust it
    /// beyond that. Every device is here until a comparison finishes.
    ///
    /// A blacklisted or ignored device also reads `Unverified`. Upstream
    /// keeps those apart in its own `LocalTrust`, and this library exposes
    /// no call that can set either, so folding them here says exactly as
    /// much as this build can honestly say.
    Unverified,
    /// **Not produced by this build.** Reserved for a device this library
    /// has reason to believe in without a person having compared anything:
    /// one signed by its owner's cross-signing identity.
    ///
    /// **This library does see such devices today.** An earlier version of
    /// this comment said the signature was something "nothing publishes or
    /// checks until cross-signing lands", which was the same misreading
    /// that made `SenderVerification`'s doc comment wrong in 0.1.0: peers
    /// running mainstream clients publish that signature, and the decrypt
    /// path already reads it, which is what
    /// `SenderVerification::UnverifiedIdentity` reports.
    ///
    /// What keeps this value unreachable is the mapping below, not the
    /// absence of the signature. [`device_statuses`] asks upstream's
    /// `Device::is_verified`, which is `is_locally_trusted() ||
    /// is_cross_signing_trusted()`: two inputs, one boolean, no middle
    /// value to carry a "signed by its owner, owner unverified" answer.
    ///
    /// This said the value would stay unreachable **after** cross-signing
    /// landed as well. Cross-signing has landed, in M4, and the mapping did
    /// not move, so it is still unreachable and the sentence is now a
    /// statement about the present rather than a prediction. What did
    /// change is the other side of that same boolean: see
    /// [`TrustState::Verified`], which now has two ways of arriving instead
    /// of one. Folding this value is defensible; folding it silently is
    /// not, which is why this paragraph is here rather than a milestone
    /// name.
    ///
    /// Declared now rather than added later because the set is closed:
    /// widening a closed union is a breaking change for every consumer that
    /// switched on it exhaustively, and it would arrive precisely when a
    /// product had stopped expecting the shape to move. Named as
    /// unreachable at the type itself, in both languages, so its presence
    /// is never read as a claim that it happens.
    Recognized,
    /// This machine has reason to trust the device, by either of two
    /// routes that this value does not tell apart.
    ///
    /// **A person compared a short authentication string** on this device
    /// and on the far one, both said it matched, and the flow completed:
    /// see [`crate::verification`]. That was the only route until M4, and
    /// this comment described only it.
    ///
    /// **Or the device is signed by its owner's cross-signing identity and
    /// this machine has verified that identity.** Nobody compares anything
    /// on the second route. The mapping below asks upstream's
    /// `Device::is_verified`, which is `is_locally_trusted() ||
    /// is_cross_signing_trusted()`, and the second half of that had no way
    /// to be true before this machine could hold a signing identity of its
    /// own. It can since [`crate::bootstrap_identity`], so verifying one
    /// device of a user can move **every** device of that user to this
    /// value at once, including devices that appear afterwards.
    ///
    /// That is correct rather than a defect, and it is the point of
    /// cross-signing. It is also a behaviour change a caller cannot see
    /// coming: anything that read this value as "a human compared a string
    /// with this exact device" was right until M4 and is wrong from it.
    /// Read it as "trusted", and read [`crate::SenderVerification`] for
    /// what an individual event can be said to prove, which is a different
    /// question with a different and more expensive answer.
    ///
    /// **This machine's own device reads `Verified` from the moment it is
    /// created, before anything has been compared.** That is upstream's own
    /// rule and it is the right one -- this process holds that device's
    /// private keys, so there is nothing to prove -- but it is a trap for
    /// anything reading this list. "At least one device reads `Verified`"
    /// is true of a machine that has never run a verification in its life.
    /// What means something is a device of *another* user changing.
    Verified,
}

/// One device of one user, and what this library will say about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceStatus {
    pub device_id: String,
    pub trust: TrustState,
}

/// Errors must not carry an identifier or key material, so an upstream
/// store failure reports its shape and nothing else -- the same rule, and
/// the same fixed string, as `machine.rs`'s `store_error_detail` and
/// `verification.rs`'s `store_failed`.
fn store_failed() -> MachineError {
    MachineError::Store {
        detail: "the crypto store could not be opened".to_string(),
    }
}

/// Every device this machine has been told about for `user_id`, and the
/// trust it currently reports for each.
///
/// **This is where a completed comparison becomes visible.** It is the one
/// call in this library whose answer a short-string comparison changes, and
/// it changes it for a *device*. Whether a decrypted event proves who sent
/// it is a different question with a different answer, and a comparison
/// does not move that one: see the M3 design, section 7, question 6.
///
/// # An empty answer is not "this user has no devices"
///
/// It is "this machine has been told about none of them". Devices arrive
/// through the outbound pump: [`crate::receive_sync_changes`] flags a user
/// as changed, that produces a `keys_query` request, and only reporting
/// that request sent puts anything in the store. A caller that has never
/// done that gets an empty vector for a user with a dozen devices, and gets
/// it successfully. Guessing instead, or waiting for a query this library
/// cannot send itself, is what [`crate::request_flow`] refuses for the same
/// reason.
///
/// Sorted by device id, so two calls that saw the same store answer in the
/// same order; upstream's own iteration order is a map's and is not
/// promised to be stable between calls.
pub async fn device_statuses(user_id: &str) -> Result<Vec<DeviceStatus>, MachineError> {
    // Owned before the closure, not borrowed. See `device_identity_keys`.
    let user_id = user_id.to_owned();

    crate::machine::with_machine(move |machine| {
        Box::pin(async move {
            let user: OwnedUserId =
                user_id
                    .parse()
                    .map_err(|_| MachineError::MalformedIdentifier {
                        detail: "user id".to_string(),
                    })?;

            // `None`, not a timeout, for the reason `request_flow` gives in
            // full: waiting here would depend on the caller draining the
            // pump from another task while this call holds the machine
            // lock, which it cannot do. So this reports what the store
            // holds now rather than blocking on a query it cannot send.
            let devices = machine
                .get_user_devices(&user, None)
                .await
                .map_err(|_upstream| store_failed())?;

            let mut statuses: Vec<DeviceStatus> = devices
                .devices()
                .map(|device| DeviceStatus {
                    device_id: device.device_id().to_string(),
                    // `is_verified`, which is local trust OR a cross
                    // signature this machine can follow. Only the first can
                    // be true today, and the reason is our own missing
                    // identity rather than the sender's: upstream's
                    // `is_cross_signing_trusted` needs our user-signing key
                    // over the owner's master key, so it is `false` even for
                    // a device its owner has genuinely signed. Asking the
                    // broader question means this answer does not have to
                    // change when the second can. See `TrustState::Recognized`
                    // for what this two-valued mapping costs.
                    trust: if device.is_verified() {
                        TrustState::Verified
                    } else {
                        TrustState::Unverified
                    },
                })
                .collect();
            statuses.sort_by(|left, right| left.device_id.cmp(&right.device_id));
            Ok(statuses)
        })
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &std::path::Path) -> crate::machine::MachineConfig {
        crate::machine::MachineConfig {
            user_id: "@a:server1".to_string(),
            device_id: "DEVICE1".to_string(),
            store_path: dir.join("store").to_string_lossy().into_owned(),
            store_passphrase: Some("test-passphrase".to_string()),
        }
    }

    #[tokio::test]
    async fn returns_well_formed_identity_keys() {
        let _guard = crate::machine::lock_for_test().await;
        crate::machine::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        crate::machine::create_machine(config(dir.path()))
            .await
            .unwrap();

        let keys = device_identity_keys("@a:server1", "DEVICE1").await.unwrap();

        // Curve25519 and Ed25519 public keys are 32 bytes, unpadded base64 = 43 chars.
        assert_eq!(keys.curve25519.len(), 43);
        assert_eq!(keys.ed25519.len(), 43);
        assert_ne!(keys.curve25519, keys.ed25519);
    }

    /// The machine is process-wide and created once, so repeated calls read
    /// the same live machine instead of minting a fresh identity per call --
    /// the way the throwaway-machine implementation this replaces used to.
    #[tokio::test]
    async fn repeated_calls_return_the_same_keys() {
        let _guard = crate::machine::lock_for_test().await;
        crate::machine::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        crate::machine::create_machine(config(dir.path()))
            .await
            .unwrap();

        let a = device_identity_keys("@a:server1", "DEVICE1").await.unwrap();
        let b = device_identity_keys("@a:server1", "DEVICE1").await.unwrap();
        assert_eq!(a, b);
    }

    /// The identifiers are an assertion, not an input: a caller who disagrees
    /// with the live machine about who this device is must be refused rather
    /// than handed keys under the wrong identity. This covers only the
    /// device-id half of the comparison -- see
    /// `mismatched_user_id_is_refused` for the other half, which a review
    /// found was unverified: deleting the `user_id` half of the `||` in
    /// `device_identity_keys` left the whole suite green, because nothing
    /// exercised it.
    #[tokio::test]
    async fn mismatched_device_id_is_refused() {
        let _guard = crate::machine::lock_for_test().await;
        crate::machine::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        crate::machine::create_machine(config(dir.path()))
            .await
            .unwrap();

        let err = device_identity_keys("@a:server1", "DEVICE2")
            .await
            .unwrap_err();
        assert_eq!(
            err,
            MachineError::MalformedIdentifier {
                detail: "identifiers do not match the active machine".to_string()
            }
        );
    }

    /// The other half of the same assertion: a caller who agrees on the
    /// device id but disagrees on the user id must also be refused. Without
    /// this, a refactor that dropped the `user_id` comparison entirely, or
    /// swapped it for the wrong field, would ship with every test green.
    #[tokio::test]
    async fn mismatched_user_id_is_refused() {
        let _guard = crate::machine::lock_for_test().await;
        crate::machine::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        crate::machine::create_machine(config(dir.path()))
            .await
            .unwrap();

        let err = device_identity_keys("@b:server1", "DEVICE1")
            .await
            .unwrap_err();
        assert_eq!(
            err,
            MachineError::MalformedIdentifier {
                detail: "identifiers do not match the active machine".to_string()
            }
        );
    }

    /// A user this machine has never been told about answers with an empty
    /// list, successfully, and that is the documented behaviour rather than
    /// an oversight -- so the doc comment saying so is pinned by a test.
    ///
    /// A machine on which no query has ever been reported sent knows about
    /// exactly one device, its own, so the assertion is against the
    /// *other* user rather than against a global emptiness that would also
    /// hold if this function returned `Vec::new()` unconditionally. Both
    /// halves are here for that reason: the second is what fails if the
    /// implementation stops reading the store at all.
    #[tokio::test]
    async fn a_user_this_machine_knows_nothing_about_reports_no_devices() {
        let _guard = crate::machine::lock_for_test().await;
        crate::machine::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        crate::machine::create_machine(config(dir.path()))
            .await
            .unwrap();

        assert_eq!(
            device_statuses("@nobody:server1").await.unwrap(),
            Vec::new()
        );
        assert_eq!(
            device_statuses("@a:server1").await.unwrap(),
            vec![DeviceStatus {
                device_id: "DEVICE1".to_string(),
                // `Verified`, on a machine that has never verified
                // anything. Upstream marks a machine's own device locally
                // trusted the moment it creates it, because this process
                // holds its private keys and there is nothing left to
                // prove (`OlmMachine::with_store`, "we can safely mark the
                // device as verified").
                //
                // Pinned rather than skipped over, because it is the exact
                // shape of the false sentence this project keeps
                // producing: a test asserting "after a verification, some
                // device reads verified" passes on a machine where no
                // verification has ever run. `tests/sas_two_party.rs`
                // asserts the change on another user's device for that
                // reason, and asserts this one is unmoved by it.
                trust: TrustState::Verified,
            }],
        );

        crate::machine::reset_for_test();
    }

    /// A user id that does not parse is the caller's mistake, and is
    /// reported as one rather than as an empty list -- which is what an
    /// implementation that swallowed the parse failure would return, and
    /// which the test above would still pass.
    #[tokio::test]
    async fn a_malformed_user_id_is_refused_rather_than_answered_emptily() {
        let _guard = crate::machine::lock_for_test().await;
        crate::machine::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        crate::machine::create_machine(config(dir.path()))
            .await
            .unwrap();

        assert_eq!(
            device_statuses("not-a-user-id")
                .await
                .expect_err("that identifier does not parse"),
            MachineError::MalformedIdentifier {
                detail: "user id".to_string()
            }
        );

        crate::machine::reset_for_test();
    }
}
