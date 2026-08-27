// `matrix-sdk-crypto` does NOT re-export `ruma` at its own crate root (verified by
// reading its vendored source: only `vodozemac` and, behind the `qrcode` feature,
// `matrix_sdk_qrcode` get a `pub use` there). `matrix-sdk-common` does
// (`pub use ruma;`, unconditional), and `matrix-sdk-crypto` 0.18.0 itself depends on
// `matrix-sdk-common = "0.18.0"`, so pinning the same version here guarantees Cargo
// unifies on a single `ruma` in the tree rather than resolving two independently
// versioned copies with incompatible types.
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId};
use matrix_sdk_crypto::OlmMachine;

/// The device's own public identity keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeys {
    pub curve25519: String,
    pub ed25519: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("malformed identifier: {detail}")]
    MalformedIdentifier { detail: String },
}

/// Creates an in-memory crypto machine and returns its identity keys.
///
/// This is the first genuine cryptographic value to cross the binding chain.
pub async fn device_identity_keys(
    user_id: &str,
    device_id: &str,
) -> Result<IdentityKeys, IdentityError> {
    let user: OwnedUserId = user_id
        .parse()
        .map_err(|_| IdentityError::MalformedIdentifier {
            detail: "user id".to_string(),
        })?;
    let device: OwnedDeviceId = device_id.into();

    let machine = OlmMachine::new(&user, &device).await;
    let keys = machine.identity_keys();

    Ok(IdentityKeys {
        curve25519: keys.curve25519.to_base64(),
        ed25519: keys.ed25519.to_base64(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_well_formed_identity_keys() {
        let keys = device_identity_keys("@a:server1", "DEVICE1").await.unwrap();

        // Curve25519 and Ed25519 public keys are 32 bytes, unpadded base64 = 43 chars.
        assert_eq!(keys.curve25519.len(), 43);
        assert_eq!(keys.ed25519.len(), 43);
        assert_ne!(keys.curve25519, keys.ed25519);
    }

    /// `OlmMachine::new` generates fresh random keys on every call; user and
    /// device ids are metadata that never derive the keys. This proves
    /// generation freshness -- repeated calls don't reuse or predict a key --
    /// not device-parameter correctness. Passing the same device id twice
    /// would prove the same thing: Matrix identity keys aren't scoped by
    /// device id, they're generated fresh per `OlmMachine` instance.
    #[tokio::test]
    async fn repeated_calls_get_fresh_random_keys() {
        let a = device_identity_keys("@a:server1", "DEVICE1").await.unwrap();
        let b = device_identity_keys("@a:server1", "DEVICE2").await.unwrap();
        assert_ne!(a.ed25519, b.ed25519);
    }
}
