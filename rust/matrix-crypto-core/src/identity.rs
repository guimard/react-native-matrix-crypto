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
    // A true async closure (`async move |..|`), not a plain closure returning
    // an `async move { }` block: `with_machine` needs the lending shape only
    // an async closure provides. See its doc comment.
    crate::machine::with_machine(async move |machine| {
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
    /// than handed keys under the wrong identity.
    #[tokio::test]
    async fn mismatched_identifiers_are_refused() {
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
}
