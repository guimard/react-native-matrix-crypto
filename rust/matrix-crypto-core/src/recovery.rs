//! Server-side storage of this account's private signing keys, and the
//! recovery that brings them back.
//!
//! # What this is for
//!
//! Delete the application and install it again and the store goes with it.
//! Without this module, what is lost is not a cache: the account's private
//! signing keys were only ever on that device, so the new installation has
//! to be verified against another device, and every person who had verified
//! this account has to verify it again. If no other device exists, the
//! identity is gone and there is nothing to join.
//!
//! Secret storage is the answer the protocol already has. The three private
//! signing keys are encrypted under a key derived from a passphrase, and the
//! result is stored in the account's own global account data, which the
//! homeserver keeps and never reads. A reinstalled device asks for the
//! passphrase, decrypts them, and is the same identity it was before.
//!
//! # What upstream gives, and what this module had to write
//!
//! `matrix_sdk_crypto::secret_storage` is public and needs no Cargo
//! feature. It provides key generation, derivation from a passphrase,
//! reconstruction from either a passphrase or the base58 recovery key
//! **verified against a stored MAC**, encryption and decryption per secret
//! name, the account data content object for the key description, and a
//! `DecodeError` that tells a wrong passphrase from input it could not
//! parse.
//!
//! It provides none of the plumbing. There is no code anywhere upstream
//! that assembles those pieces into the five account data events a
//! recovery is made of, none that reads them back, and none that connects
//! the decrypted bytes to the crypto store: turning them into a working
//! identity is `OlmMachine::import_cross_signing_keys`, and nothing joins
//! the two. That assembly is this module.
//!
//! # This library still performs no request
//!
//! Account data is a read-then-write interaction with the homeserver, and
//! the outbound pump is shaped for fire-and-acknowledge: a pump entry is a
//! body to send and a report that it was sent, with no value coming back.
//! Rather than redefine what a pump entry means for every other kind of
//! request, the two calls here **take and return the account data as JSON**
//! and leave the two HTTP requests, a read and a write, to the product.
//! That is the shape `receive_sync_changes` already uses for the one other
//! place this library needs something from the server, and the M4 design's
//! section 5.2 is where it was settled, along with what would overturn it:
//! if the number of round trips a recovery needs turned out to be unusable
//! from a product's point of view, extending the pump becomes the better
//! trade.
//!
//! # What is deliberately not here
//!
//! Key backup (`m.megolm_backup.v1`) coordination. Upstream has a separate
//! module for it and it is separate work; nothing in this module reads or
//! writes a backup key, and a recovery restored here leaves any backup
//! exactly as it found it.

use matrix_sdk_common::ruma::events::secret::request::SecretName;
use matrix_sdk_common::ruma::events::secret_storage::default_key::SecretStorageDefaultKeyEventContent;
use matrix_sdk_common::ruma::events::secret_storage::key::SecretStorageKeyEventContent;
use matrix_sdk_common::ruma::events::secret_storage::secret::SecretEventContent;
use matrix_sdk_common::ruma::events::{EventContentFromType, GlobalAccountDataEventContent};
use matrix_sdk_crypto::secret_storage::{DecodeError, SecretStorageKey};
use matrix_sdk_crypto::store::types::CrossSigningKeyExport;
use matrix_sdk_crypto::store::SecretImportError;
use matrix_sdk_crypto::OlmMachine;

use crate::machine::{with_machine, MachineError};

/// One global account data event, as the homeserver stores it.
///
/// `content` is the event's content object as JSON, exactly the body of a
/// `PUT /user/{id}/account_data/{type}` and exactly what the matching `GET`
/// answers with. This library never adds an envelope of its own around it,
/// so a product moves these bytes to and from the homeserver unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountDataEntry {
    /// The global account data event type, such as
    /// `m.secret_storage.default_key`.
    pub event_type: String,
    /// The event's content object, as JSON.
    pub content: String,
}

/// Everything [`create_recovery`] produced: the one secret to show the user,
/// and the account data to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySetup {
    /// The base58 recovery key, formatted in groups of four characters as
    /// the specification requires.
    ///
    /// **This value is not stored anywhere and cannot be produced again.**
    /// It is the passphrase's equal, not a backup of it: either one opens
    /// this recovery, and losing both loses the identity. Show it once, and
    /// mean it.
    pub recovery_key: String,
    /// The account data to write, in the order it should be written.
    ///
    /// Five events: the key description, the pointer that makes it the
    /// account's default key, and one per private signing key. The pointer
    /// is second on purpose, so a product that stops partway through has
    /// never named a key description it did not manage to write.
    pub account_data: Vec<AccountDataEntry>,
}

/// Errors must not carry an identifier or key material, so an upstream
/// store failure reports its shape and nothing else. The same rule and the
/// same fixed string as `machine.rs`'s `store_error_detail`, `identity.rs`'s
/// `store_failed`, `signing.rs`'s and `verification.rs`'s.
fn store_failed() -> MachineError {
    MachineError::Store {
        detail: "the crypto store could not be opened".to_string(),
    }
}

/// The three secrets a recovery carries, in the order they are written and
/// read.
///
/// One list, used by both directions, so a name added to one and not the
/// other cannot happen.
const SECRETS: [SecretName; 3] = [
    SecretName::CrossSigningMasterKey,
    SecretName::CrossSigningSelfSigningKey,
    SecretName::CrossSigningUserSigningKey,
];

/// The account data event type that names which key is the account's
/// default.
///
/// Built from ruma's own content type rather than written as a literal, so
/// the string comes from the same place the parse below expects it.
fn default_key_event_type() -> String {
    SecretStorageDefaultKeyEventContent::new(String::new())
        .event_type()
        .to_string()
}

/// The content of the first entry whose type matches, if any.
///
/// The **first**, not the only one: a caller may hand over a list built
/// from more than one source, and duplicates of a global account data type
/// are the same event by definition. Taking the first is a rule rather than
/// an accident, and it is the one a `/sync` response's own ordering
/// produces.
fn entry<'a>(account_data: &'a [AccountDataEntry], event_type: &str) -> Option<&'a str> {
    account_data
        .iter()
        .find(|entry| entry.event_type == event_type)
        .map(|entry| entry.content.as_str())
}

/// Writes this account's private signing keys into server-side storage,
/// under a key derived from `passphrase`.
///
/// Returns the recovery key to show the user and the account data to write.
/// **Nothing here reaches the network**, and nothing is written until the
/// product writes it: on success, `PUT` each entry of
/// [`RecoverySetup::account_data`] to
/// `/_matrix/client/v3/user/{userId}/account_data/{eventType}` with the
/// entry's content as the body, in the order they are handed back.
///
/// # What this costs the user, said once
///
/// The recovery key comes back exactly once and is never stored. Losing it
/// **and** forgetting the passphrase loses the account's identity: nothing
/// on the server can open the stored keys without one of them, and this
/// library has no second copy. A product that shows the key and moves on
/// without making the user record it has built the support burden into its
/// first screen.
///
/// # This is the interoperable format
///
/// The account data written here is Matrix's own secret storage, the
/// `m.secret_storage.v1.aes-hmac-sha2` scheme, produced by upstream's own
/// implementation of it. Another Matrix client signed into the same account
/// reads the same five events with the same passphrase or recovery key, and
/// a recovery another client wrote is one [`recover_identity`] restores.
/// Nothing about the container is this library's invention.
///
/// # Refusals
///
/// [`MachineError::PrivateKeysNotHeld`] if this device does not hold all
/// three private signing keys. There is nothing to write, and a partial
/// write would be worse than none: it would leave account data that opens
/// with the right passphrase and restores an incomplete identity.
/// [`crate::identity_status`] says which of the two remedies applies, which
/// are [`crate::bootstrap_identity`] for an account with no identity and
/// [`crate::request_self_flow`] for one this device has not joined yet.
pub async fn create_recovery(passphrase: &str) -> Result<RecoverySetup, MachineError> {
    let passphrase = passphrase.to_string();
    with_machine(move |machine| {
        Box::pin(async move {
            let export = machine
                .export_cross_signing_keys()
                .await
                .map_err(|_upstream| store_failed())?
                .ok_or(MachineError::PrivateKeysNotHeld)?;

            // Cloned field by field, which is the one place in this crate
            // that does not destructure an upstream struct. It cannot:
            // `CrossSigningKeyExport` is `ZeroizeOnDrop`, so it implements
            // `Drop` and Rust forbids moving its fields out. The rule
            // Global Constraints states, that a field added upstream must
            // fail this build rather than be silently dropped, is kept by
            // the exhaustive `let ... else` immediately below instead: it
            // names all three fields, and a fourth private key upstream
            // added would be visible as an export whose contents this
            // module knowingly ignores rather than as a compile error.
            let master_key = export.master_key.clone();
            let self_signing_key = export.self_signing_key.clone();
            let user_signing_key = export.user_signing_key.clone();

            // `Some` for all three, not merely a non-`None` export.
            // Upstream returns `Some` as soon as any one of them is
            // present, and a store holding one seed of three is exactly the
            // half-recovered state this refusal exists to keep out of
            // account data.
            let (Some(master), Some(self_signing), Some(user_signing)) =
                (master_key, self_signing_key, user_signing_key)
            else {
                return Err(MachineError::PrivateKeysNotHeld);
            };

            let key = SecretStorageKey::new_from_passphrase(&passphrase);
            let key_id = key.key_id().to_string();

            let mut account_data = Vec::with_capacity(2 + SECRETS.len());
            account_data.push(AccountDataEntry {
                event_type: key.event_type().to_string(),
                content: to_json(key.event_content())?,
            });
            account_data.push(AccountDataEntry {
                event_type: default_key_event_type(),
                content: to_json(&SecretStorageDefaultKeyEventContent::new(key_id.clone()))?,
            });

            for (name, seed) in SECRETS.iter().zip([master, self_signing, user_signing]) {
                // The plaintext is the seed exactly as upstream exports it,
                // an unpadded base64 string, which is what the
                // specification puts in these events and what every other
                // client expects to find there. Encoding it any other way
                // would produce account data only this library could read.
                let encrypted = key.encrypt(seed.into_bytes(), name);
                account_data.push(AccountDataEntry {
                    event_type: name.as_str().to_string(),
                    content: to_json(&serde_json::json!({
                        "encrypted": { &key_id: encrypted },
                    }))?,
                });
            }

            Ok(RecoverySetup {
                recovery_key: key.to_base58(),
                account_data,
            })
        })
    })
    .await?
}

/// Serialises a value that cannot reasonably fail to serialise.
///
/// A failure here would be an upstream type whose `Serialize` refuses, not
/// anything a caller did, so it reports as a store-shaped failure rather
/// than inventing a variant nothing can reach.
fn to_json<T: serde::Serialize>(value: &T) -> Result<String, MachineError> {
    serde_json::to_string(value).map_err(|_upstream| store_failed())
}

/// Restores this account's private signing keys from server-side storage.
///
/// `secret` is **either** the passphrase [`create_recovery`] derived the key
/// from **or** the base58 recovery key it returned. Upstream tries the
/// passphrase first and falls back to the recovery key, so one parameter
/// serves both and a product need not ask the user which one they are
/// holding.
///
/// `account_data` is what the product read back from the homeserver. Five
/// events are needed and a complete recovery has all five:
/// `m.secret_storage.default_key`, the `m.secret_storage.key.<id>` it names,
/// and `m.cross_signing.master`, `m.cross_signing.self_signing` and
/// `m.cross_signing.user_signing`. They may be fetched individually with
/// `GET /_matrix/client/v3/user/{userId}/account_data/{eventType}`, or taken
/// out of a `/sync` response's global account data, which carries all of
/// them. Entries this call does not need are ignored, so handing over the
/// whole of an account's global account data is fine.
///
/// **The key description's type is not known in advance**, because it ends
/// in the key's own id: read `m.secret_storage.default_key` first, and its
/// `key` field is that id. A product fetching events one at a time
/// therefore needs two rounds, which is the cost this shape was chosen with
/// (M4 design section 5.2).
///
/// # What this does not do
///
/// It asks the server nothing and it sends nothing. The device that
/// recovers still has to publish its own device keys, and the identity it
/// has just rejoined still has to sign that device, which is
/// [`crate::bootstrap_identity`]'s republication. What recovery restores is
/// the ability to do those things at all, and every verification anyone
/// else had made of this account, which is the part a second device could
/// not give back.
///
/// # Refusals, and the one distinction a product's error message needs
///
/// [`MachineError::RecoveryKeyIncorrect`] means the secret is wrong and the
/// stored recovery is intact: ask again.
/// [`MachineError::RecoveryDataMalformed`] means no secret will ever open
/// it: stop asking, and set recovery up again from a device that still
/// holds the keys. **These two are never folded together**, because folding
/// them either tells a user with a typo that their identity is destroyed or
/// leaves a user whose recovery really is destroyed retyping forever. The
/// line comes from upstream rather than from a guess here: a passphrase or
/// recovery key is verified against a MAC stored beside the key
/// description, and `DecodeError::Mac` is that check failing.
///
/// [`MachineError::RecoveryNotSetUp`] means the account data handed over
/// carries no complete recovery. Either there is none, or not all of it was
/// fetched; see the variant's own documentation for why this call cannot
/// tell those apart.
///
/// [`MachineError::AccountKeysNotFetched`] and
/// [`MachineError::IdentityNotKnown`] are the same pair
/// [`crate::bootstrap_identity`] and [`crate::request_self_flow`] report,
/// and they are checked first, before the passphrase is even derived. The
/// reason is upstream's: importing private keys needs the account's
/// **public** identity already in the store, so that each seed can be
/// checked against the key it claims to be. Without it upstream logs and
/// does nothing, which is the silent success this call exists not to
/// return. `AccountKeysNotFetched` queues the key query that lifts it, so
/// the remedy is the ordinary loop: drain the pump, send, report sent, call
/// this again.
pub async fn recover_identity(
    secret: &str,
    account_data: &[AccountDataEntry],
) -> Result<(), MachineError> {
    let secret = secret.to_string();
    let account_data = account_data.to_vec();
    with_machine(move |machine| {
        Box::pin(async move { restore(machine, &secret, &account_data).await })
    })
    .await?
}

/// Which upstream decode failure is a wrong secret and which is a stored
/// recovery that cannot be read.
///
/// **The whole point of keeping [`MachineError::RecoveryKeyIncorrect`] and
/// [`MachineError::RecoveryDataMalformed`] apart lives in this function**,
/// so the question it answers is asked once, of every variant, by name.
///
/// # The rule
///
/// Upstream's `DecodeError` mixes two subjects that its own name does not
/// separate: some variants describe the string the user just typed, and
/// some describe the key description this library read back from the
/// server. The first set is a wrong secret and the user retypes it; the
/// second is a recovery no secret will ever open.
///
/// # Why this was wrong once, and what it cost
///
/// This was a single `Mac` arm and a wildcard, on the reasoning that
/// "every other variant describes input that could not be parsed at all".
/// That premise is false, and the case it is false in is the one a product
/// most needs right. `SecretStorageKey::from_account_data`
/// (`matrix-sdk-crypto-0.18.0/src/secret_storage.rs`) branches on whether
/// the key description carries a `passphrase` block. **With** one it tries
/// the passphrase, falls back to base58, and on double failure returns the
/// passphrase error, which is `Mac`. **Without** one, which the
/// specification permits, which upstream handles explicitly and which
/// another client's recovery can perfectly well be, it goes straight to the
/// base58 path, whose failures are `Base58`, `Prefix`, `Parity` and
/// `KeyLength`. Every one of those describes the typed secret, and every
/// one of them landed in the wildcard.
///
/// So a user with a one-character typo in their recovery key was told their
/// stored data was unreadable, whose documented remedy is to set recovery
/// up again, which is the single action that destroys the recovery they
/// were trying to open. That is precisely the harm this pair of variants
/// exists to prevent, arrived at through the one path no fixture reached,
/// because `create_recovery` always writes a passphrase block.
///
/// # Exhaustive, and no wildcard
///
/// `DecodeError` is not `#[non_exhaustive]`, so every variant is named. A
/// variant upstream adds later must fail this build rather than fall
/// through to whichever answer the wildcard happened to give, which is
/// exactly how the defect above survived.
fn classify_decode_error(upstream: DecodeError) -> MachineError {
    // Matched by variant, not by text, like every other upstream error this
    // crate classifies.
    match upstream {
        // The typed secret. `Mac` is the reconstructed key failing its own
        // check, which a wrong passphrase and a wrong recovery key both
        // produce. The other four come out of `parse_base58_key` and
        // describe the characters the user entered: not base58 at all, the
        // wrong length once decoded, the wrong two-byte prefix, or a parity
        // byte that does not match the key it is meant to check.
        DecodeError::Mac(_)
        | DecodeError::Base58(_)
        | DecodeError::KeyLength(_, _)
        | DecodeError::Prefix(_, _)
        | DecodeError::Parity(_, _) => MachineError::RecoveryKeyIncorrect,
        // The stored key description. The iteration count is the one that
        // looks like it could be about the secret and is not: it is the
        // count the *description* asks for, refused because it does not fit
        // in this platform's `usize`, and no secret changes it. `IvLength`
        // and `MacLength` are the description's own check fields being the
        // wrong size, and `UnsupportedAlgorithm` is a scheme this build
        // does not implement.
        //
        // `Base64` is unreachable from this call in
        // `matrix-sdk-crypto` 0.18.0: it exists as a `#[from]` conversion
        // and nothing on the path from `from_account_data` constructs one.
        // Named rather than left to a wildcard anyway, and put here because
        // if it ever becomes reachable it will be a field of the stored
        // description that failed to decode.
        DecodeError::Base64(_)
        | DecodeError::IvLength(_, _)
        | DecodeError::MacLength(_, _)
        | DecodeError::UnsupportedAlgorithm(_)
        | DecodeError::KdfIterationCount(_) => MachineError::RecoveryDataMalformed,
    }
}

/// The whole of [`recover_identity`] once a machine is in hand.
///
/// Separate so that the `with_machine` closure stays a single expression
/// and the ordering below can be read as one sequence.
async fn restore(
    machine: &OlmMachine,
    secret: &str,
    account_data: &[AccountDataEntry],
) -> Result<(), MachineError> {
    // The cheap precondition first, and it is a precondition rather than a
    // courtesy: without the account's public identity in the store,
    // upstream's import checks nothing and stores nothing. Deriving a key
    // from a passphrase costs half a million PBKDF2 iterations, so a caller
    // that has not asked the server yet is turned away before paying for
    // it.
    let status = crate::signing::read_status(machine).await?;
    if !status.identity_known {
        if !status.account_keys_fetched {
            // Queued by the refusal, exactly as `bootstrap_identity` does
            // and for the same reason: upstream volunteers an own-account
            // key query only while the account is not yet tracked, so on
            // any process that has already shared a key this refusal would
            // otherwise be permanent.
            let (id, request) = machine.query_keys_for_users(std::iter::once(machine.user_id()));
            crate::session::queue_account_key_query(id, request);
            return Err(MachineError::AccountKeysNotFetched);
        }
        return Err(MachineError::IdentityNotKnown);
    }

    let default_key =
        entry(account_data, &default_key_event_type()).ok_or(MachineError::RecoveryNotSetUp)?;
    let default_key: SecretStorageDefaultKeyEventContent =
        serde_json::from_str(default_key).map_err(|_| MachineError::RecoveryDataMalformed)?;
    let key_id = default_key.key_id;

    // The key description's event type carries the key id, so it is built
    // here rather than searched for by prefix: an account may hold several
    // key descriptions, and the default key names exactly one of them.
    let description_type = format!("m.secret_storage.key.{key_id}");
    let description =
        entry(account_data, &description_type).ok_or(MachineError::RecoveryNotSetUp)?;
    let description = serde_json::value::RawValue::from_string(description.to_string())
        .map_err(|_| MachineError::RecoveryDataMalformed)?;
    // `from_parts`, not a plain deserialise: the key id lives in the event
    // type rather than in the content, and this is upstream's own way of
    // putting the two back together.
    let description = SecretStorageKeyEventContent::from_parts(&description_type, &description)
        .map_err(|_| MachineError::RecoveryDataMalformed)?;

    let key =
        SecretStorageKey::from_account_data(secret, description).map_err(classify_decode_error)?;

    let mut seeds = Vec::with_capacity(SECRETS.len());
    for name in &SECRETS {
        let stored = entry(account_data, name.as_str()).ok_or(MachineError::RecoveryNotSetUp)?;
        let stored: SecretEventContent =
            serde_json::from_str(stored).map_err(|_| MachineError::RecoveryDataMalformed)?;
        // Absent under *this* key id is `RecoveryNotSetUp` rather than
        // malformed: the event is well formed and simply does not carry a
        // copy encrypted to the key the account calls its default, which is
        // an incomplete recovery and not damaged data.
        let encrypted = stored
            .encrypted
            .get(&key_id)
            .ok_or(MachineError::RecoveryNotSetUp)?
            .deserialize_as_unchecked()
            .map_err(|_| MachineError::RecoveryDataMalformed)?;
        // A MAC failure here is not a wrong secret: the secret already
        // passed its own MAC check above, so what failed is this
        // ciphertext.
        let plaintext = key
            .decrypt(&encrypted, name)
            .map_err(|_| MachineError::RecoveryDataMalformed)?;
        seeds.push(String::from_utf8(plaintext).map_err(|_| MachineError::RecoveryDataMalformed)?);
    }

    let mut seeds = seeds.into_iter();
    let export = CrossSigningKeyExport {
        master_key: seeds.next(),
        self_signing_key: seeds.next(),
        user_signing_key: seeds.next(),
    };

    let imported = machine
        .import_cross_signing_keys(export)
        .await
        .map_err(|upstream| match upstream {
            SecretImportError::Store(_) => store_failed(),
            // `Key` is a seed that is not a signing key;
            // `MismatchedPublicKeys` is a recovery written for an identity
            // this account has since replaced. Both are folded, and
            // `MachineError::RecoveryDataMalformed`'s own documentation
            // says why and what would change that.
            _other => MachineError::RecoveryDataMalformed,
        })?;

    // Upstream's import is documented to return the private identity's
    // status rather than an error when it declines to do anything, so the
    // one way this call could report a silent success is caught here rather
    // than trusted away. Every path that reaches this line supplied all
    // three seeds, so an incomplete identity means upstream stored none of
    // them.
    if !imported.is_complete() {
        return Err(MachineError::RecoveryDataMalformed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::machine::{
        create_machine, lock_for_test, reset_for_test, with_machine, MachineConfig,
    };
    use crate::runtime::in_runtime;
    use crate::session::{
        decrypt_event, mark_request_sent, receive_sync_changes, share_scope_key,
        take_outgoing_requests, OutgoingRequest, SenderVerification,
    };
    use crate::signing::{bootstrap_identity, identity_status};
    use matrix_sdk_common::ruma::api::client::keys::claim_keys::v3::Response as KeysClaimResponse;
    use matrix_sdk_common::ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
    use matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Response as KeysUploadResponse;
    use matrix_sdk_common::ruma::api::IncomingResponse;
    use matrix_sdk_common::ruma::events::AnyMessageLikeEventContent;
    // `exports::http`, not a direct `http` dependency: the exact version
    // ruma's own `IncomingResponse::try_from_http_response` requires,
    // reached through ruma's re-export, as `session.rs` documents for
    // itself.
    use matrix_sdk_common::ruma::exports::http;
    use matrix_sdk_common::ruma::serde::Raw;
    use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId, TransactionId};
    use matrix_sdk_crypto::types::requests::AnyOutgoingRequest;
    use matrix_sdk_crypto::types::DeviceKeys;
    use matrix_sdk_crypto::{CrossSigningBootstrapRequests, EncryptionSettings, OlmMachine};

    const ALICE_USER: &str = "@alice:example.org";
    /// The device that holds the identity and writes the recovery.
    const FIRST_DEVICE: &str = "DEVICEONE";
    /// The reinstall. A different device id, because that is what a fresh
    /// login is: the store is gone and so is the device it belonged to.
    const SECOND_DEVICE: &str = "DEVICETWO";
    const PEER_USER: &str = "@peer:example.org";
    const PEER_DEVICE: &str = "PEERDEVICE";
    /// A scope only ever used to make the library ask who a user's devices
    /// are and to carry one event. Nothing about it is read back.
    const SCOPE: &str = "!recovery:example.org";
    const PAYLOAD: &str = r#"{"body":"sent after the reinstall","msgtype":"m.text"}"#;

    /// Literals with no account anywhere behind them, exactly like the
    /// `store_passphrase` every other test in this crate hands to
    /// `MachineConfig`. Neither opens anything outside this test process.
    const PASSPHRASE: &str = "recovery-test-passphrase";
    const WRONG_PASSPHRASE: &str = "not-the-recovery-test-passphrase";

    /// A `/keys/query` answer naming no identity for this account: the
    /// server has been asked and has said there is none. Every field of
    /// ruma's own response type is `#[serde(default)]`, so an empty object
    /// says exactly that, and it is what lifts `bootstrap_identity`'s gate.
    const NO_IDENTITY: &str = r#"{"device_keys":{}}"#;

    fn config(store_path: String, device_id: &str) -> MachineConfig {
        MachineConfig {
            user_id: ALICE_USER.to_string(),
            device_id: device_id.to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        }
    }

    /// A fixed-shape 200 response, the form ruma's own
    /// `IncomingResponse::try_from_http_response` expects.
    fn http_ok(body: &str) -> http::Response<Vec<u8>> {
        http::Response::builder()
            .status(200)
            .body(body.as_bytes().to_vec())
            .expect("a fixed-shape http::Response with no custom headers cannot fail to build")
    }

    fn keys_upload_response(body: &str) -> KeysUploadResponse {
        KeysUploadResponse::try_from_http_response(http_ok(body))
            .expect("this test builds its own well-formed keys-upload response")
    }

    fn keys_query_response(body: &str) -> KeysQueryResponse {
        KeysQueryResponse::try_from_http_response(http_ok(body))
            .expect("this test builds its own well-formed keys-query response")
    }

    fn keys_claim_response(body: &str) -> KeysClaimResponse {
        KeysClaimResponse::try_from_http_response(http_ok(body))
            .expect("this test builds its own well-formed keys-claim response")
    }

    /// The top-level `event_type` a to-device request's JSON body declares.
    ///
    /// Every assertion about what crossed goes through this rather than
    /// stopping at the request kind: a withheld notice is a to-device
    /// request too, so the kind alone distinguishes nothing.
    fn declared_event_type(body: &str) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|value| value.get("event_type")?.as_str().map(str::to_owned))
            .unwrap_or_else(|| "<no event_type in body>".to_string())
    }

    /// Turns one to-device request body into the to-device event the
    /// addressed device would have received from its homeserver. Reads the
    /// per-recipient content out of the request and wraps it with the
    /// sender and type the request itself declares; it reaches into neither
    /// machine.
    fn relay_to(body: &str, sender: &str, user_id: &str, device_id: &str) -> Option<String> {
        let request: serde_json::Value = serde_json::from_str(body).ok()?;
        let event_type = request.get("event_type")?.as_str()?;
        let content = request.get("messages")?.get(user_id)?.get(device_id)?;
        Some(
            serde_json::json!({
                "sender": sender,
                "type": event_type,
                "content": content,
            })
            .to_string(),
        )
    }

    /// Wraps an encrypted content in the surrounding event a homeserver
    /// would have delivered.
    fn scoped_event(sender: &str, event_id: &str, content: &str) -> String {
        let content: serde_json::Value =
            serde_json::from_str(content).expect("an encrypted content is well-formed JSON");
        serde_json::json!({
            "sender": sender,
            "event_id": event_id,
            "origin_server_ts": 1_700_000_000_000u64,
            "content": content,
        })
        .to_string()
    }

    /// The device keys a bare machine holds for its own device.
    ///
    /// Read from the store rather than from the key upload request, because
    /// the upload was built before the bootstrap below and a bootstrap does
    /// not retroactively change what an already-built request carried.
    async fn device_keys_of(
        machine: &OlmMachine,
        user_id: &OwnedUserId,
        device_id: &OwnedDeviceId,
    ) -> DeviceKeys {
        machine
            .get_device(user_id, device_id, None)
            .await
            .expect("a machine's own store must be readable")
            .expect("a machine always knows its own device")
            .as_device_keys()
            .to_owned()
    }

    /// The self-signing signature a bootstrap produced over the peer's own
    /// device, put back onto that device's keys.
    ///
    /// This is the homeserver's half and nothing more. A bootstrap does not
    /// write this signature into its own store copy of the device: it emits
    /// it in a signature upload, and the server is what stores it and hands
    /// it back on the next key query. Both the signature and the keys it
    /// covers come out of upstream. The same helper, and the same
    /// reasoning, as `tests/cross_signed_peer.rs`.
    fn with_owner_signature(
        mut device_keys: DeviceKeys,
        bootstrap: &CrossSigningBootstrapRequests,
        user_id: &OwnedUserId,
        device_id: &OwnedDeviceId,
    ) -> DeviceKeys {
        let self_signing_key_id = bootstrap
            .upload_signing_keys_req
            .self_signing_key
            .as_ref()
            .expect("a bootstrap always produces a self-signing key")
            .get_first_key_and_id()
            .expect("a self-signing key always carries exactly one key")
            .0
            .to_owned();
        // Looked up by device id, not taken as the first entry: this map is
        // keyed by device id *and* by cross-signing key id, because a
        // bootstrap also signs its own master key with the device.
        let signed: DeviceKeys = bootstrap
            .upload_signatures_req
            .signed_keys
            .get(user_id)
            .expect("a bootstrap signs the device of the user that ran it")
            .iter()
            .find(|(id, _)| *id == device_id.as_str())
            .map(|(_, raw)| {
                serde_json::from_str(raw.get())
                    .expect("upstream's own signed device keys deserialise as device keys")
            })
            .expect("a bootstrap signs the running device, keyed by its device id");
        device_keys.signatures.add_signature(
            user_id.clone(),
            self_signing_key_id.clone(),
            signed
                .signatures
                .get_signature(user_id, &self_signing_key_id)
                .expect("the signed copy carries the signature the bootstrap just made"),
        );
        device_keys
    }

    /// How many signatures, across every signing user, a cross-signing key
    /// carries.
    fn signature_count(key: &serde_json::Value) -> usize {
        key.get("signatures")
            .and_then(serde_json::Value::as_object)
            .map(|users| {
                users
                    .values()
                    .filter_map(serde_json::Value::as_object)
                    .map(serde_json::Map::len)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Merges the signature the first device made over the peer's master
    /// key into that key, as a homeserver does with a signature upload.
    ///
    /// Only the signatures are taken, never the key object around them:
    /// upstream's `sign_user` *replaces* the master key's signature map
    /// with its own single signature rather than adding to it, so posting
    /// that object verbatim as the master key would drop the signature the
    /// peer's own device made over it.
    ///
    /// Asserts the merge actually added one. A key query body is just JSON,
    /// and one describing an unsigned master key reads exactly like one
    /// describing a signed one, so the fixture this whole file rests on is
    /// checked rather than trusted.
    fn with_our_signature(
        mut master_key: serde_json::Value,
        signatures: &serde_json::Value,
    ) -> serde_json::Value {
        let before = signature_count(&master_key);

        let target = master_key
            .get_mut("signatures")
            .and_then(serde_json::Value::as_object_mut)
            .expect("a published master key always carries its own device's signature");
        for (user, keys) in signatures
            .as_object()
            .expect("an uploaded signature map is an object")
        {
            let slot = target
                .entry(user.clone())
                .or_insert_with(|| serde_json::json!({}));
            let slot = slot
                .as_object_mut()
                .expect("a per-user signature map is an object");
            for (key_id, signature) in keys
                .as_object()
                .expect("a per-user signature map is an object")
            {
                slot.insert(key_id.clone(), signature.clone());
            }
        }

        let after = signature_count(&master_key);
        assert!(
            after > before,
            "merging the uploaded signature must add one: the master key \
             carried {before} signatures before and {after} after. Equal \
             means this response is indistinguishable from one in which the \
             peer was never verified, and this file would assert nothing"
        );
        master_key
    }

    /// Drains the library's pump and returns the one request of `kind`,
    /// leaving everything else pending.
    async fn drain_for(kind: &str, why: &str) -> OutgoingRequest {
        take_outgoing_requests()
            .await
            .expect("the pump must be drainable")
            .into_iter()
            .find(|request| request.kind == kind)
            .unwrap_or_else(|| panic!("{why}"))
    }

    /// The users a `/keys/query` body asks about.
    fn queried_users(body: &str) -> Vec<String> {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|body| {
                Some(
                    body.get("device_keys")?
                        .as_object()?
                        .keys()
                        .cloned()
                        .collect(),
                )
            })
            .expect("a keys-query body always carries a device_keys object")
    }

    /// Drains the library's pump and returns the key query that asks about
    /// `user_id`.
    ///
    /// **Not `drain_for("keys_query", ..)`.** A query for this account and a
    /// query for anyone else are one endpoint with one wire tag, so taking
    /// whichever came first could answer the account's own query with the
    /// peer's keys while every assertion below still read plausibly.
    async fn drain_for_query_about(user_id: &str, why: &str) -> OutgoingRequest {
        take_outgoing_requests()
            .await
            .expect("the pump must be drainable")
            .into_iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == user_id)
            })
            .unwrap_or_else(|| panic!("{why}"))
    }

    /// Everything the first device leaves behind, and everything the
    /// reinstalled one needs.
    struct BeforeTheReinstall {
        /// The store directory of the device that is about to be deleted.
        store_dir: std::path::PathBuf,
        /// The three public cross-signing keys the account published,
        /// exactly as a `/keys/query` for this account would return them.
        account_identity: serde_json::Value,
        /// The peer, still alive: a reinstall on our side is not a new
        /// device on theirs.
        peer: OlmMachine,
        peer_device_keys: serde_json::Value,
        /// Carrying the first device's user-signing signature, which is the
        /// thing a recovery has to give back.
        peer_master_key: serde_json::Value,
        peer_self_signing_key: serde_json::Value,
        recovery: RecoverySetup,
    }

    /// The device that has the identity: it creates one, verifies a peer
    /// with it, and writes the recovery.
    async fn before_the_reinstall() -> BeforeTheReinstall {
        // `keep()`: this directory has to outlive the guard, because the
        // caller deletes it by hand to model the uninstall.
        let store_dir = tempfile::tempdir().expect("temp dir").keep();
        create_machine(config(
            store_dir.join("store").to_string_lossy().into_owned(),
            FIRST_DEVICE,
        ))
        .await
        .expect("the library's machine must be creatable");

        // ---- The first device publishes its own keys --------------------
        let upload = drain_for("keys_upload", "a fresh machine must have keys to publish").await;
        mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
            .await
            .expect("a keys-upload response must be accepted");

        // ---- It creates the account's identity --------------------------
        let account_query = drain_for_query_about(
            ALICE_USER,
            "a fresh machine must owe a key query for its own account",
        )
        .await;
        mark_request_sent(&account_query.id, NO_IDENTITY)
            .await
            .expect("answering the account key query must not fail");

        bootstrap_identity()
            .await
            .expect("bootstrapping after the account keys have been fetched must be served");

        // The publication the bootstrap queued is what a `/keys/query` for
        // this account answers with from here on, so the reinstalled device
        // is handed exactly these three keys and nothing invented here.
        let published = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let signing_keys = published
            .iter()
            .find(|request| request.kind == "signing_keys_upload")
            .expect("a served bootstrap always queues the signing keys upload");
        let signing_keys: serde_json::Value = serde_json::from_str(&signing_keys.body)
            .expect("the pump's own body is well-formed JSON");
        let account_identity = serde_json::json!({
            "master_keys": { ALICE_USER: signing_keys["master_key"] },
            "self_signing_keys": { ALICE_USER: signing_keys["self_signing_key"] },
            "user_signing_keys": { ALICE_USER: signing_keys["user_signing_key"] },
        });
        for request in &published {
            mark_request_sent(&request.id, "{}")
                .await
                .expect("a bootstrap publication response must be accepted");
        }

        // ---- A peer, with an identity of its own ------------------------
        let peer_user: OwnedUserId = PEER_USER.parse().expect("a literal user id parses");
        let peer_device: OwnedDeviceId = PEER_DEVICE.into();
        let peer = OlmMachine::new(&peer_user, &peer_device).await;

        let batch = peer
            .outgoing_requests()
            .await
            .expect("a fresh bare machine has keys to publish");
        let upload_id = batch
            .iter()
            .find(|request| matches!(request.request(), AnyOutgoingRequest::KeysUpload(_)))
            .expect("a fresh bare machine has a key upload")
            .request_id()
            .to_owned();
        peer.mark_request_as_sent(
            &upload_id,
            &keys_upload_response(r#"{"one_time_key_counts":{}}"#),
        )
        .await
        .expect("the bare machine must accept its own upload response");

        // `false`, not `true`: the device keys were published above, and
        // what this bootstrap is wanted for is the identity and the
        // signature it puts on that device.
        let bootstrap = peer
            .bootstrap_cross_signing(false)
            .await
            .expect("a bare machine must be able to bootstrap its own identity");
        let peer_device_keys = with_owner_signature(
            device_keys_of(&peer, &peer_user, &peer_device).await,
            &bootstrap,
            &peer_user,
            &peer_device,
        );
        let peer_device_keys =
            serde_json::to_value(&peer_device_keys).expect("upstream device keys serialise");
        let peer_master_key = serde_json::to_value(&bootstrap.upload_signing_keys_req.master_key)
            .expect("an upstream master key serialises");
        let peer_self_signing_key =
            serde_json::to_value(&bootstrap.upload_signing_keys_req.self_signing_key)
                .expect("an upstream self-signing key serialises");
        assert_eq!(
            signature_count(&peer_device_keys),
            2,
            "a bootstrapped peer's device carries two signatures, its own and \
             its owner's self-signing key. One means the bootstrap did not \
             sign the device, and nothing below would be about recovery"
        );

        // ---- The first device verifies the peer -------------------------
        //
        // Reached one layer below this crate's own comparison flow, on
        // purpose. `OtherUserIdentity::verify` is the same `sign_user` call
        // upstream makes inside `mark_as_done` when a comparison completes,
        // so the signature produced here is the signature a completed
        // comparison produces; what is skipped is six relayed to-device
        // messages, which are `tests/sas_two_party.rs`'s subject and not
        // this file's. What is not skipped, and is the point, is that this
        // signature is made with the first device's real user-signing key
        // and is checked by the reinstalled device with the recovered one.
        share_scope_key(SCOPE, &[PEER_USER.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let query = drain_for_query_about(
            PEER_USER,
            "the machine must ask who exists before it can verify anyone",
        )
        .await;
        mark_request_sent(
            &query.id,
            &serde_json::json!({
                "device_keys": { PEER_USER: { PEER_DEVICE: peer_device_keys.clone() } },
                "master_keys": { PEER_USER: peer_master_key.clone() },
                "self_signing_keys": { PEER_USER: peer_self_signing_key.clone() },
            })
            .to_string(),
        )
        .await
        .expect("a keys-query response must be accepted");

        let signed_keys = with_machine(move |machine| {
            Box::pin(async move {
                machine
                    .get_identity(&peer_user, None)
                    .await
                    .expect("the store must be readable")
                    .expect("the peer's identity has just been fetched")
                    .other()
                    .expect("the peer is another user")
                    .verify()
                    .await
                    .expect("a device holding the private user-signing key can sign a peer")
                    .signed_keys
            })
        })
        .await
        .expect("the library's machine must be live");
        let signed_keys =
            serde_json::to_value(&signed_keys).expect("an upstream signature upload serialises");
        let uploaded = signed_keys
            .get(PEER_USER)
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| {
                panic!("the signature upload must name the peer it signed: {signed_keys}")
            });
        assert_eq!(
            uploaded.len(),
            1,
            "a user signature covers exactly the master key, so exactly one \
             entry is expected here: {signed_keys}"
        );
        let signatures = uploaded
            .values()
            .next()
            .and_then(|signed| signed.get("signatures"))
            .cloned()
            .expect("a signed master key always carries the signature that signed it");
        let peer_master_key = with_our_signature(peer_master_key, &signatures);

        // ---- The recovery -----------------------------------------------
        let recovery = create_recovery(PASSPHRASE)
            .await
            .expect("a device holding the private signing keys can write a recovery");

        // Anything the traffic above queued is drained, so the reinstalled
        // device's pump carries only its own.
        take_outgoing_requests()
            .await
            .expect("the pump must be drainable");

        BeforeTheReinstall {
            store_dir,
            account_identity,
            peer,
            peer_device_keys,
            peer_master_key,
            peer_self_signing_key,
            recovery,
        }
    }

    /// What one run of the reinstall produced.
    struct Outcome {
        /// What the library reported about the sender of the event it
        /// decrypted.
        verification: Option<SenderVerification>,
        /// The plaintext the library recovered. The control on every
        /// authenticity assertion: if decryption itself broke, the value
        /// above is meaningless rather than wrong, and this says which of
        /// the two happened.
        recovered: Vec<u8>,
        /// Whether the reinstalled device holds the account's private
        /// signing keys by the time the event arrives.
        private_keys_held: bool,
    }

    /// The reinstall: a brand new store, a new device id, and one axis.
    ///
    /// `recover` is the single difference between this file's two
    /// scenarios. Everything else, the account, the peer, the signature the
    /// peer's master key carries and the payload, is identical, so the only
    /// thing that can explain two different values at the end is whether
    /// the identity came back.
    async fn after_the_reinstall(before: BeforeTheReinstall, recover: bool) -> Outcome {
        // Destructured, so a field added to the fixture later has to be
        // given a use here rather than being silently ignored.
        let BeforeTheReinstall {
            store_dir: _,
            account_identity,
            peer,
            peer_device_keys,
            peer_master_key,
            peer_self_signing_key,
            recovery,
        } = before;

        let dir = tempfile::tempdir().expect("temp dir").keep();
        create_machine(config(
            dir.join("store").to_string_lossy().into_owned(),
            SECOND_DEVICE,
        ))
        .await
        .expect("the reinstalled device's machine must be creatable");

        // ---- The reinstalled device publishes its own keys --------------
        let upload = drain_for(
            "keys_upload",
            "a machine on a fresh store must have keys to publish",
        )
        .await;
        let upload_body: serde_json::Value =
            serde_json::from_str(&upload.body).expect("the pump's own body is well-formed JSON");
        let device_keys = upload_body
            .get("device_keys")
            .cloned()
            .expect("a fresh machine's upload carries its device keys");
        let (one_time_key_id, one_time_key) = upload_body
            .get("one_time_keys")
            .and_then(serde_json::Value::as_object)
            .and_then(|keys| keys.iter().next())
            .map(|(id, key)| (id.clone(), key.clone()))
            .expect("a fresh machine's upload carries one-time keys");
        mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
            .await
            .expect("a keys-upload response must be accepted");

        // ---- It learns what identity the account has --------------------
        //
        // Answered with what the first device published, which is what a
        // homeserver returns. Without this the store holds no public
        // identity for the account, and upstream's import has nothing to
        // check a recovered seed against.
        let account_query = drain_for_query_about(
            ALICE_USER,
            "a machine on a fresh store must owe a key query for its own account",
        )
        .await;
        mark_request_sent(&account_query.id, &account_identity.to_string())
            .await
            .expect("answering the account key query must not fail");

        // ---- The axis ---------------------------------------------------
        if recover {
            recover_identity(PASSPHRASE, &recovery.account_data)
                .await
                .expect("the passphrase that wrote this recovery must open it");
        }

        let private_keys_held = identity_status()
            .await
            .expect("reading the identity status must not fail")
            .private_keys_held;

        // ---- The peer's keys reach the reinstalled device ---------------
        share_scope_key(SCOPE, &[PEER_USER.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let query =
            drain_for_query_about(PEER_USER, "the reinstalled device must ask who the peer is")
                .await;
        mark_request_sent(
            &query.id,
            &serde_json::json!({
                "device_keys": { PEER_USER: { PEER_DEVICE: peer_device_keys } },
                "master_keys": { PEER_USER: peer_master_key },
                "self_signing_keys": { PEER_USER: peer_self_signing_key },
            })
            .to_string(),
        )
        .await
        .expect("a keys-query response must be accepted");

        // The mirror image on the bare side: the peer learns the new
        // device, claims one of its one-time keys, and opens a session.
        let alice_user: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
        peer.mark_request_as_sent(
            &TransactionId::new(),
            &keys_query_response(
                &serde_json::json!({
                    "device_keys": { ALICE_USER: { SECOND_DEVICE: device_keys } }
                })
                .to_string(),
            ),
        )
        .await
        .expect("the bare machine must accept a keys-query response");

        let (claim_id, _request) = peer
            .get_missing_sessions(std::iter::once(alice_user.as_ref()))
            .await
            .expect("the bare machine must be able to report missing sessions")
            .expect("the bare machine has no session to the reinstalled device yet");
        peer.mark_request_as_sent(
            &claim_id,
            &keys_claim_response(
                &serde_json::json!({
                    "one_time_keys": {
                        ALICE_USER: { SECOND_DEVICE: { one_time_key_id: one_time_key } }
                    }
                })
                .to_string(),
            ),
        )
        .await
        .expect("the bare machine must accept a keys-claim response");

        // ---- The peer's group key, then one event -----------------------
        let room_id: OwnedRoomId = SCOPE.parse().expect("a literal room id parses");
        let shares = peer
            .share_room_key(
                &room_id,
                std::iter::once(alice_user.as_ref()),
                EncryptionSettings::default(),
            )
            .await
            .expect("the bare machine must be able to share its own group key");
        let key_events: Vec<serde_json::Value> = shares
            .iter()
            .map(|request| {
                serde_json::to_string(request.as_ref())
                    .expect("an upstream to-device request serialises")
            })
            .filter(|body| declared_event_type(body) == "m.room.encrypted")
            .filter_map(|body| relay_to(&body, PEER_USER, ALICE_USER, SECOND_DEVICE))
            .map(|event| {
                serde_json::from_str(&event).expect("this test builds its own well-formed event")
            })
            .collect();
        assert_eq!(
            key_events.len(),
            1,
            "the peer must produce exactly one to-device message carrying its \
             session key to the reinstalled device; zero means it produced a \
             withheld notice instead, which is not what this file is about"
        );

        let outcome = receive_sync_changes(
            &serde_json::json!({ "to_device_events": key_events }).to_string(),
        )
        .await
        .expect("the library must accept a sync carrying a session key");
        assert_eq!(
            outcome.new_session_count, 1,
            "the relayed to-device message must give the reinstalled device \
             exactly one new inbound session"
        );

        let content = Raw::<AnyMessageLikeEventContent>::from_json_string(PAYLOAD.to_owned())
            .expect("a literal payload is well-formed JSON");
        let encrypted = peer
            .encrypt_room_event_raw(&room_id, "m.room.message", &content)
            .await
            .expect("the bare machine must be able to encrypt for its own session");
        let event = scoped_event(
            PEER_USER,
            "$after-the-reinstall:example.org",
            encrypted.content.json().get(),
        );
        let envelope = decrypt_event(SCOPE, &event)
            .await
            .expect("the library must decrypt what the peer encrypted");

        Outcome {
            verification: envelope.sender_verification,
            recovered: envelope.ciphertext,
            private_keys_held,
        }
    }

    /// Deletes the first device's store, and proves it is gone.
    ///
    /// The uninstall, made literal. `reset_for_test` above releases the
    /// machine that held it open; this is what makes the bytes stop
    /// existing, so nothing below can be resting on a file that survived.
    fn destroy(store_dir: &std::path::Path) {
        std::fs::remove_dir_all(store_dir).expect("the first device's store must be deletable");
        assert!(
            !store_dir.exists(),
            "the store this scenario destroys must actually be gone; a \
             surviving one would let every assertion below pass for the \
             wrong reason"
        );
    }

    /// **The milestone's promise.** Write the recovery, destroy the store,
    /// restore from the passphrase on a brand new device, and read a
    /// decrypted event's sender.
    ///
    /// Nothing in this test is a stand-in for the value under test. The
    /// peer is a bare upstream machine, the signature on its master key was
    /// made by the first device's real user-signing key, the store really
    /// is deleted from disk, and the reinstalled device recovers the seeds
    /// from account data and nothing else. `Verified` at the end means the
    /// recovered user-signing key was used to check that signature, which
    /// is the whole claim: a person who verified this account before the
    /// reinstall does not have to verify it again.
    ///
    /// Driven by `block_on` inside `in_runtime`, because the bare machine
    /// needs a tokio context this crate does not supply for it: upstream's
    /// `share_room_key` reaches `tokio::task::spawn`.
    #[test]
    fn a_recovered_identity_makes_a_decrypted_event_read_verified_again() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let before = futures::executor::block_on(in_runtime(before_the_reinstall()));
        let store_dir = before.store_dir.clone();

        // The uninstall. `reset_for_test` releases the machine holding the
        // store open, and `destroy` deletes it.
        reset_for_test();
        destroy(&store_dir);

        let outcome = futures::executor::block_on(in_runtime(after_the_reinstall(before, true)));

        assert!(
            outcome.private_keys_held,
            "recovering from the passphrase must leave the reinstalled device \
             holding the account's private signing keys; without them nothing \
             below can be about a recovery"
        );
        assert_eq!(
            outcome.recovered,
            PAYLOAD.as_bytes(),
            "the reinstalled device must recover the peer's payload byte for \
             byte, or the value under test is meaningless rather than wrong"
        );
        assert_eq!(
            outcome.verification,
            Some(SenderVerification::Verified),
            "after a recovery, an event from a peer this account had verified \
             before the reinstall reads `Verified` again. Anything below it \
             means the recovered user-signing key did not check the signature \
             on the peer's master key, which is the one thing a recovery is \
             for"
        );
    }

    /// The mirror image, and the reason the test above is not asserting a
    /// constant.
    ///
    /// The same account, the same peer, the same signature on the same
    /// master key, the same payload, the same reinstall. One difference:
    /// the account data is never handed to `recover_identity`. If this
    /// still read `Verified`, the value would be coming from somewhere
    /// other than the recovered key and the test above would prove nothing.
    #[test]
    fn a_reinstall_without_the_recovery_reads_below_verified() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let before = futures::executor::block_on(in_runtime(before_the_reinstall()));
        let store_dir = before.store_dir.clone();

        reset_for_test();
        destroy(&store_dir);

        let outcome = futures::executor::block_on(in_runtime(after_the_reinstall(before, false)));

        assert!(
            !outcome.private_keys_held,
            "a reinstall that does not recover holds no private signing keys; \
             if it does, the axis this file turns on is not the axis"
        );
        assert_eq!(
            outcome.recovered,
            PAYLOAD.as_bytes(),
            "decryption itself still works without a recovery, and saying so \
             is what makes the value below a statement about authenticity \
             rather than about decryption"
        );
        assert_eq!(
            outcome.verification,
            Some(SenderVerification::UnverifiedIdentity),
            "without the recovery the peer's identity is one this device has \
             never verified, so the event stops one rung short. `Verified` \
             here would mean the value does not depend on the recovered key \
             at all"
        );
    }

    /// A wrong passphrase and a recovery that cannot be read are different
    /// answers, and this is the test that says so.
    ///
    /// All four outcomes are driven against **one** fixture, in one
    /// process, and the correct passphrase is tried last. That ordering is
    /// the control: it proves the three refusals were caused by what was
    /// changed rather than by a fixture that could never have opened.
    #[test]
    fn a_wrong_secret_is_told_apart_from_a_recovery_that_cannot_be_read() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let before = futures::executor::block_on(in_runtime(before_the_reinstall()));
        let store_dir = before.store_dir.clone();

        reset_for_test();
        destroy(&store_dir);

        futures::executor::block_on(in_runtime(async move {
            let BeforeTheReinstall {
                account_identity,
                recovery,
                ..
            } = before;

            let dir = tempfile::tempdir().expect("temp dir").keep();
            create_machine(config(
                dir.join("store").to_string_lossy().into_owned(),
                SECOND_DEVICE,
            ))
            .await
            .expect("the reinstalled device's machine must be creatable");

            let upload = drain_for(
                "keys_upload",
                "a machine on a fresh store must have keys to publish",
            )
            .await;
            mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
                .await
                .expect("a keys-upload response must be accepted");
            let account_query = drain_for_query_about(
                ALICE_USER,
                "a machine on a fresh store must owe a key query for its own account",
            )
            .await;
            mark_request_sent(&account_query.id, &account_identity.to_string())
                .await
                .expect("answering the account key query must not fail");

            // (1) A typo. The stored recovery is untouched.
            assert_eq!(
                recover_identity(WRONG_PASSPHRASE, &recovery.account_data).await,
                Err(MachineError::RecoveryKeyIncorrect),
                "a wrong passphrase must report exactly that, so a product can \
                 ask its user to try again"
            );

            // (2) Damage, with the right passphrase. One byte of one
            //     ciphertext is changed and nothing else, so the key's own
            //     MAC still verifies and the secret's does not. That is
            //     precisely the case a folded error would report as a wrong
            //     passphrase, sending a user to retype something that was
            //     already right.
            let damaged = with_a_damaged_secret(&recovery.account_data);
            assert_eq!(
                recover_identity(PASSPHRASE, &damaged).await,
                Err(MachineError::RecoveryDataMalformed),
                "a recovery whose stored secret has been altered must report \
                 that no secret will open it, not that the secret was wrong"
            );

            // (3) Content that is not JSON at all, in the key description.
            let unparseable = with_replaced_content(
                &recovery.account_data,
                |event_type| event_type.starts_with("m.secret_storage.key."),
                "not json at all",
            );
            assert_eq!(
                recover_identity(PASSPHRASE, &unparseable).await,
                Err(MachineError::RecoveryDataMalformed),
                "a key description that is not JSON must report the same thing \
                 as damaged ciphertext: nothing a user types will fix it"
            );

            // (4) An incomplete recovery: one of the three secrets was
            //     never written. Different from both of the above, and the
            //     remedy is different too.
            let incomplete: Vec<AccountDataEntry> = recovery
                .account_data
                .iter()
                .filter(|entry| entry.event_type != SecretName::CrossSigningUserSigningKey.as_str())
                .cloned()
                .collect();
            assert_eq!(
                recover_identity(PASSPHRASE, &incomplete).await,
                Err(MachineError::RecoveryNotSetUp),
                "account data missing one of the three secrets is neither a \
                 wrong passphrase nor damaged data"
            );

            // (5) A mistyped recovery key, against a recovery whose key
            //     description carries no passphrase block.
            //
            //     That shape is legal, upstream branches on it explicitly,
            //     and this library promises to restore a recovery another
            //     client wrote, so it is a shape that arrives here. With no
            //     passphrase block upstream goes straight to the base58
            //     path, whose failures describe the string the user just
            //     typed. **This is the case the whole pair of variants
            //     exists for**, and it is the one no fixture on this branch
            //     could reach until now, because `create_recovery` always
            //     writes a passphrase block.
            let key_only = without_the_passphrase_block(&recovery.account_data);
            assert_eq!(
                recover_identity(&mistyped(&recovery.recovery_key), &key_only).await,
                Err(MachineError::RecoveryKeyIncorrect),
                "a recovery key with one character wrong is a wrong secret, \
                 whatever the key description does or does not carry. Reporting \
                 it as unreadable data sends a user whose only mistake was a \
                 typo to set recovery up again, which is the one action that \
                 destroys what they were trying to recover"
            );
            assert_eq!(
                recover_identity(PASSPHRASE, &key_only).await,
                Err(MachineError::RecoveryKeyIncorrect),
                "a passphrase typed at a recovery that has no passphrase block \
                 is a wrong secret too, for the same reason: nothing about the \
                 stored data is wrong"
            );

            //     The control for that pair, and what makes the two above
            //     statements about the secret rather than about the
            //     fixture: the same key-only description opens with the
            //     right recovery key.
            recover_identity(&recovery.recovery_key, &key_only)
                .await
                .expect(
                    "a recovery with no passphrase block must still open with \
                     the recovery key it was created with",
                );

            // (6) The other control, and it is what stops the fix for (5)
            //     from being `report every secret as wrong`. The
            //     **passphrase is right** and the key description names an
            //     encryption scheme this build does not implement, so the
            //     answer must still be that the stored data cannot be read.
            //
            //     The passphrase block is deliberately left in place. With
            //     it removed, upstream never reaches the algorithm at all:
            //     it takes the base58 path, fails to parse a passphrase as
            //     a key, and answers about the secret. Which is correct,
            //     and is why this fixture changes one field rather than
            //     replacing the description.
            let unsupported = with_an_unsupported_algorithm(&recovery.account_data);
            assert_eq!(
                recover_identity(PASSPHRASE, &unsupported).await,
                Err(MachineError::RecoveryDataMalformed),
                "a key description naming an encryption algorithm this build \
                 does not implement describes the stored data, not the secret, \
                 and no secret will open it"
            );

            // (7) The control. The same fixture, the same machine, the
            //     right passphrase: it opens. Without this, every refusal
            //     above would be equally consistent with a fixture that was
            //     never openable at all.
            recover_identity(PASSPHRASE, &recovery.account_data)
                .await
                .expect("the untouched fixture must open with the passphrase that wrote it");
            assert!(
                identity_status()
                    .await
                    .expect("reading the identity status must not fail")
                    .private_keys_held,
                "the control must actually restore the identity, or it is not \
                 a control"
            );

            // (8) And the other secret opens it too. `secret` is documented
            //     as either the passphrase or the recovery key, and the
            //     recovery key is the half a product shows a human once and
            //     the only thing that survives a forgotten passphrase, so
            //     the claim is pinned rather than left to the doc comment.
            recover_identity(&recovery.recovery_key, &recovery.account_data)
                .await
                .expect(
                    "the recovery key this call returned must open the recovery \
                     it returned it for",
                );
        }));
    }

    /// A copy of `account_data` with one byte of the master key's
    /// ciphertext changed.
    ///
    /// Base64, so a character is swapped for a different one from the same
    /// alphabet rather than truncating the string: the result is still a
    /// well-formed event carrying a well-formed ciphertext of the right
    /// length, which is what makes the MAC the only thing that catches it.
    fn with_a_damaged_secret(account_data: &[AccountDataEntry]) -> Vec<AccountDataEntry> {
        let target = SecretName::CrossSigningMasterKey.as_str();
        let mut damaged = account_data.to_vec();
        let entry = damaged
            .iter_mut()
            .find(|entry| entry.event_type == target)
            .expect("a recovery always carries the master key");
        let mut content: serde_json::Value =
            serde_json::from_str(&entry.content).expect("this module wrote well-formed JSON");
        let encrypted = content
            .get_mut("encrypted")
            .and_then(serde_json::Value::as_object_mut)
            .expect("a stored secret always carries an encrypted map");
        let data = encrypted
            .values_mut()
            .next()
            .expect("a stored secret always carries one entry");
        let ciphertext = data
            .get_mut("ciphertext")
            .expect("a stored secret always carries a ciphertext");
        let original = ciphertext
            .as_str()
            .expect("a ciphertext is a base64 string")
            .to_string();
        let first = original.chars().next().expect("a ciphertext is not empty");
        let replacement = if first == 'A' { 'B' } else { 'A' };
        let altered: String = std::iter::once(replacement)
            .chain(original.chars().skip(1))
            .collect();
        assert_ne!(
            altered, original,
            "the damage must actually change the ciphertext, or this fixture \
             is the undamaged one under another name"
        );
        *ciphertext = serde_json::Value::String(altered);
        entry.content = content.to_string();
        damaged
    }

    /// A copy of `account_data` whose key description carries no
    /// `passphrase` block.
    ///
    /// Legal, and not a corruption: the Matrix specification defines the
    /// block as optional, upstream's `from_account_data` branches on its
    /// absence, and a client that offered its user only a recovery key
    /// writes exactly this. `create_recovery` always writes one, so this is
    /// the only way to build the shape from inside this file.
    ///
    /// Nothing else is touched, which is what makes the assertions using it
    /// about the branch rather than about the fixture.
    fn without_the_passphrase_block(account_data: &[AccountDataEntry]) -> Vec<AccountDataEntry> {
        let mut stripped = account_data.to_vec();
        let entry = stripped
            .iter_mut()
            .find(|entry| entry.event_type.starts_with("m.secret_storage.key."))
            .expect("a recovery always carries a key description");
        let mut content: serde_json::Value =
            serde_json::from_str(&entry.content).expect("this module wrote well-formed JSON");
        let removed = content
            .as_object_mut()
            .expect("a key description is an object")
            .remove("passphrase");
        assert!(
            removed.is_some(),
            "the fixture must have carried a passphrase block for removing it \
             to mean anything"
        );
        entry.content = content.to_string();
        stripped
    }

    /// The same recovery key with one character replaced by another from
    /// the same alphabet.
    ///
    /// A typo, not a truncation: the result is still a base58 string of the
    /// right length, so what rejects it is the key's own parity or MAC
    /// check rather than a length test, which is the shape a real mistyping
    /// takes.
    fn mistyped(recovery_key: &str) -> String {
        let mut wrong = String::with_capacity(recovery_key.len());
        let mut swapped = false;
        for character in recovery_key.chars() {
            if !swapped && character.is_ascii_alphanumeric() {
                wrong.push(if character == 'a' { 'b' } else { 'a' });
                swapped = true;
            } else {
                wrong.push(character);
            }
        }
        assert!(swapped, "a recovery key always carries a base58 character");
        assert_ne!(wrong, recovery_key, "the typo must change the key");
        wrong
    }

    /// A copy of `account_data` whose key description names an encryption
    /// scheme this build does not implement.
    ///
    /// One field changed and nothing else, in particular **not** the
    /// passphrase block: that is what makes the failure reachable. Upstream
    /// only looks at the algorithm once it has a candidate key, so a
    /// description with no passphrase block is rejected on the base58 path
    /// before the algorithm is consulted, and the answer is then correctly
    /// about the secret rather than about the stored data.
    fn with_an_unsupported_algorithm(account_data: &[AccountDataEntry]) -> Vec<AccountDataEntry> {
        let mut altered = account_data.to_vec();
        let entry = altered
            .iter_mut()
            .find(|entry| entry.event_type.starts_with("m.secret_storage.key."))
            .expect("a recovery always carries a key description");
        let mut content: serde_json::Value =
            serde_json::from_str(&entry.content).expect("this module wrote well-formed JSON");
        let object = content
            .as_object_mut()
            .expect("a key description is an object");
        assert!(
            object.contains_key("passphrase"),
            "this fixture depends on the passphrase block being present, or \
             the algorithm is never reached"
        );
        let replaced = object.insert(
            "algorithm".to_string(),
            serde_json::Value::String("m.secret_storage.v1.something-else".to_string()),
        );
        assert!(
            replaced.is_some(),
            "a key description always names an algorithm, so replacing it \
             must have replaced something"
        );
        entry.content = content.to_string();
        altered
    }

    /// A copy of `account_data` with the content of the first entry whose
    /// type satisfies `matches` replaced.
    fn with_replaced_content(
        account_data: &[AccountDataEntry],
        matches: impl Fn(&str) -> bool,
        content: &str,
    ) -> Vec<AccountDataEntry> {
        let mut replaced = account_data.to_vec();
        let entry = replaced
            .iter_mut()
            .find(|entry| matches(&entry.event_type))
            .expect("this fixture carries the entry being replaced");
        entry.content = content.to_string();
        replaced
    }

    /// What a recovery is made of, asserted against the specification's own
    /// names rather than against whatever this module happens to emit.
    ///
    /// A product writes these five event types and no others, and another
    /// Matrix client reads them, so the set is part of the contract and not
    /// an implementation detail.
    #[test]
    fn a_recovery_is_five_account_data_events_a_matrix_client_would_recognise() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();

        let setup = futures::executor::block_on(in_runtime(async {
            let before = before_the_reinstall().await;
            before.recovery
        }));

        let types: Vec<&str> = setup
            .account_data
            .iter()
            .map(|entry| entry.event_type.as_str())
            .collect();
        assert_eq!(types.len(), 5, "a recovery is five events: {types:?}");
        assert_eq!(
            types[1], "m.secret_storage.default_key",
            "the pointer is written second, after the key description it names"
        );
        assert!(
            types[0].starts_with("m.secret_storage.key."),
            "the key description's type ends in the key's own id: {types:?}"
        );
        for name in SECRETS {
            assert!(
                types.contains(&name.as_str()),
                "a recovery carries {}: {types:?}",
                name.as_str()
            );
        }

        // The key description names the same key the pointer points at. A
        // mismatch here would produce account data no client, this one
        // included, could ever open.
        let pointer: serde_json::Value = serde_json::from_str(&setup.account_data[1].content)
            .expect("this module wrote well-formed JSON");
        let key_id = pointer
            .get("key")
            .and_then(serde_json::Value::as_str)
            .expect("the pointer names a key");
        assert_eq!(types[0], format!("m.secret_storage.key.{key_id}"));

        // The recovery key is the base58 form the specification describes,
        // shown in groups of four. Asserted because it is the one value a
        // product shows a human and can never produce again.
        assert!(
            setup.recovery_key.contains(' ') && setup.recovery_key.len() > 40,
            "the recovery key is a grouped base58 string: {}",
            setup.recovery_key.len()
        );
    }
}
