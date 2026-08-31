//! This account's signing identity: reading whether it has one, and
//! publishing one when it safely can.
//!
//! An account's signing identity is what lets one device vouch for another
//! without a person comparing anything, and what lets a decrypted event say
//! who sent it rather than only which key it arrived under. Every device of
//! the account signs into it; other users verify the account once instead of
//! device by device.
//!
//! # The whole reason this module is not a one-line wrapper
//!
//! Upstream's `bootstrap_cross_signing(false)` is safe **and** destructive,
//! depending entirely on when it is called:
//!
//! * Called on a device that already holds the complete private identity, it
//!   is idempotent *locally* -- it re-derives the publication of what is
//!   already there and yields the same master key. What it publishes may
//!   still be wrong: a store restored from a backup holds a complete
//!   identity the server has already replaced, and republishing it puts the
//!   old one back over the new. Local idempotence is not safety.
//! * Called on a device whose private identity is incomplete, it **mints a
//!   new one** (`matrix-sdk-crypto-0.18.0/src/machine/mod.rs:676` branches on
//!   `identity.is_empty()`, and a partial identity counts as empty). If the
//!   account already had an identity, publishing the new one replaces it and
//!   resets the trust of every device and every user who had verified the
//!   old one.
//!
//! The second case is not exotic. It is the ordinary shape of a fresh login:
//! new device, empty store, an account that has been in use for years. There
//! is no error and no warning, and the damage is to other people's trust in
//! this user rather than to anything this process can afterwards detect.
//!
//! # The gate, and the question it is careful not to ask
//!
//! The tempting gate is "is the local identity empty". It refuses nothing:
//! it is the same question upstream already asks before minting, so every
//! call it would refuse is a call upstream already treats as a mint.
//!
//! The gate here is two different facts, and both are needed:
//!
//! 1. **Have we asked, and does upstream now know?** Has a `/keys/query`
//!    naming this account been sent and answered in this process, and did
//!    the answer leave upstream's store able to say whether the account has
//!    an identity. Tracked by `session.rs`, which is the only place that can
//!    know it, and recorded when the *response* is accepted rather than when
//!    the request is handed out.
//! 2. **What did the answer say?** Does this machine now hold a public
//!    identity for the account. Read from the store, where the answer to (1)
//!    put it.
//!
//! Fact (1) used to stop at "and was answered", then at "and the answer
//! named this account", and both were defeated by answers upstream had
//! dropped. It is the same store read in both facts now, asked at two
//! different moments and for two different reasons, which is why they are
//! still two facts and not one.
//!
//! Nothing is served before (1), **including a republication by a device
//! that holds the private keys**, because that is exactly the restored-backup
//! case above and only a key query can tell it apart from an ordinary
//! relaunch. Given (1), the call is served when the account has no identity
//! or this device holds the one it has. "Not asked" and "asked, and there is
//! one this device does not hold" are different refusals with different
//! remedies, and [`MachineError::AccountKeysNotFetched`] /
//! [`MachineError::IdentityAlreadyExists`] keep them apart.
//!
//! # What the gate cannot check
//!
//! Fact (1) is "a key query was reported to us as having succeeded". No HTTP
//! status crosses this library's boundary on that call, so a caller that
//! reports a failed query's body as a success supplies that fact falsely and
//! the gate believes it.
//!
//! `session::mark_request_sent` refuses every body it can show is not an
//! answer, and accepts every body shaped like one. **The exact division, and
//! why the remainder cannot be closed from a body, is stated once at
//! `session::refuse_a_non_response` and deliberately not repeated here.**
//! What a maintainer of this file needs from it is the consequence: a body
//! shaped like a key query answer is *accepted*, whatever status it actually
//! arrived with.
//!
//! **Accepted is no longer the same as lifting this gate**, and that is the
//! narrower thing to know. `session::answer_about_this_account` additionally
//! requires that, once upstream has consumed the accepted body, upstream's
//! own store **says whether this account has an identity**. Either the
//! answer asserted a cross-signing key for the account and upstream now
//! holds the identity it asserted, or the answer asserted none and named the
//! account under `device_keys`. So an answer about other users, a body whose
//! only substance is a `failures` map, the empty object, and an answer
//! carrying this account's own published master key that upstream could not
//! assemble into an identity all pass `mark_request_sent` and leave this
//! gate shut.
//!
//! That last one is why the rule reads upstream rather than the body.
//! Upstream needs a master key **and** a self-signing key to store an
//! identity, and a user-signing key too when the user is our own; anything
//! short of that it drops with a `warn!` and no error. Measured against a
//! live Synapse 1.159.0: an account that had published a master key alone
//! answered its own key query with a body carrying that key, a rule that
//! read the body's map keys lifted this gate, and the bootstrap minted a
//! second identity over the published one. Flipping one character of one
//! base64 signature in an otherwise correct answer did the same.
//!
//! Fact (1) can also be **unsettled**: the answer arrived, was accepted, and
//! left upstream still not knowing. `IdentityStatus`'s
//! `account_keys_answer_unsettled` is what says so, and its own doc comment
//! says what a product does about it. Without it the refusal below is
//! indistinguishable from "nobody has asked", whose remedy is to ask again,
//! which against a server that omits the account is a loop with no end.
//!
//! Reporting nothing at all is equally safe here: the gate needs a positive
//! mark to open, so silence leaves it shut. A caller that got a non-2xx
//! should still say so through `session::mark_request_failed`, which is what
//! keeps a refused request resolvable and is the only way to close the same
//! collision on the signing-keys upload, where `{}` really is the whole
//! success response.
//!
//! Fact (1) is "asked at some point in this process", not "asked recently",
//! and that is deliberate for the *publishing* call, which can only ever
//! re-send what a homeserver has already confirmed. It is **not** enough for
//! the *creating* call, whose whole subject is an account that has no
//! identity yet, and which therefore carries a second condition of its own:
//! an answer that settled after it asked. [`PUBLICATION_ASKED_AFTER`] is
//! where that is defined and argued, and why "the most recent answer in the
//! store" is not the same thing.
//!
//! # This library never sees a credential
//!
//! Publishing the identity needs user-interactive authentication at the
//! homeserver, and upstream surfaces none of it -- its own request type is
//! three key fields with no `auth`, while the real endpoint's request has
//! one. So the product owns that loop: send the body this module queues,
//! read the challenge out of the refusal, ask its user, send the same body
//! again with `auth` merged into it. There is deliberately no `auth`
//! parameter on [`bootstrap_identity`], and the reason is not squeamishness:
//! the challenge is only known *after* the first request is refused, so any
//! up-front credential parameter would have to be guessed before the server
//! has said what it wants. `session::mark_request_sent` looks its entry up
//! without removing it, so the retry is an ordinary second send of the same
//! pending request.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex as StdMutex;

use matrix_sdk_crypto::{OlmMachine, UserIdentity};

use crate::machine::{with_machine, MachineError};

/// The store key this crate records an identity it minted and has **not yet
/// seen the homeserver accept** under.
///
/// # The fact nothing else in this process can remember
///
/// `create_identity` writes a minted identity into the crypto store and then
/// hands the publication to the caller. Between those two moments the store
/// holds an identity the account does not have, and it holds it **durably**,
/// because the store is a file and the publication is in a process-local
/// pump. If that request is never sent -- the process is killed, the device
/// is offline, the socket times out, the user backgrounds the app -- the
/// store keeps an identity that no homeserver has ever seen.
///
/// *This store holds an identity* and *this account has an identity* are
/// therefore different facts, and only the store can remember which of them
/// is true, because the server cannot be asked about a publication that
/// never arrived. Upstream keeps exactly this fact for itself, on
/// `PrivateCrossSigningIdentity::shared`, pickled into the store and set by
/// `receive_cross_signing_upload_response` (`machine/mod.rs:640-648`); it is
/// not reachable through any public API, so this crate records the same fact
/// beside it rather than duplicating the reasoning.
///
/// # Prefixed, and holding a key rather than a flag
///
/// The value is the ed25519 master key of the unpublished identity, not a
/// boolean, so a record cannot outlive the identity it describes: if the
/// store's identity later changes -- because the device joined the one the
/// account really has -- the recorded key no longer matches it and the
/// record reads as absent without anything having to remember to clear it.
///
/// The key is namespaced because it shares one custom-value table with
/// upstream's own entries (`Store::set_value`, `store/mod.rs:1160-1174`).
const UNPUBLISHED_IDENTITY_KEY: &str = "org.linagora.rnmc.unpublished_identity";

/// The ed25519 master key of the identity this machine holds, if it holds
/// one, in the same base64 form the record above stores.
async fn own_master_key(machine: &OlmMachine) -> Option<String> {
    machine
        .get_identity(machine.user_id(), None)
        .await
        .ok()
        .flatten()
        .and_then(UserIdentity::own)
        .and_then(|identity| identity.master_key().get_first_key())
        .map(|key| key.to_base64())
}

/// Records that this device has minted the identity it now holds and has not
/// yet seen a homeserver accept it.
///
/// Called by [`create_identity`] straight after the mint, and by nothing
/// else: minting is the only act that can put an identity into this store
/// that the account does not have.
///
/// A store write that fails is not an error the caller can do anything
/// about, and failing the mint over it would leave the identity minted and
/// the caller told it was not. The consequence of losing this record is the
/// state that existed before it: a refusal rather than a wrong publication,
/// which is the direction this module takes everywhere.
pub(crate) async fn note_identity_minted(machine: &OlmMachine) {
    let Some(master_key) = own_master_key(machine).await else {
        return;
    };
    let _ = machine
        .store()
        .set_value(UNPUBLISHED_IDENTITY_KEY, &master_key)
        .await;
}

/// Records that the identity this machine holds is one a homeserver has.
///
/// **Called from exactly one place**, `session::answer_about_this_account`,
/// and only when a `/keys/query` answer asserts the very identity this store
/// holds. The server saying so is the whole of what "published" means here.
///
/// # This comment described a second caller that no longer exists
///
/// It used to name `session::mark_sent` as well -- the moment a signing-keys
/// upload is *reported* as having succeeded. That site was removed, because
/// no HTTP status crosses this library's boundary and the upload's success
/// response is the empty object, so a caller that reported a dropped
/// connection cleared the record for a publication that never left the
/// device. `session.rs`'s own comment at that site says so at length.
///
/// The stale sentence is called out rather than quietly deleted because of
/// where it was. Everything downstream rests on *confirmed means a
/// homeserver's own answer carried the identity back*, and this function is
/// where a reader checking that premise arrives. Told there were two
/// callers, one of them a caller's own report, they would conclude the
/// premise was false.
pub(crate) async fn note_identity_published(machine: &OlmMachine) {
    let _ = machine
        .store()
        .remove_custom_value(UNPUBLISHED_IDENTITY_KEY)
        .await;
}

/// Whether the identity this machine holds is one it minted and has never
/// seen accepted.
///
/// `false` for a store holding no identity, for one whose identity arrived
/// from a homeserver's own answer, for one whose publication was reported,
/// and for a store written by a version of this crate that kept no record.
/// That last default is the safe one and it is deliberate: an unrecorded
/// identity is treated as one the account really has, so a "this account has
/// no identity" answer contradicts it, which is the refusal
/// `tests/identity_bootstrap_contradicted_answer.rs` exists for.
///
/// # What this exempts, stated rather than left to be found
///
/// A `true` here exempts one identity from that contradiction check, so it
/// is worth naming what that costs. The exemption is wrong only if the
/// identity really was published and this record was never cleared, and
/// clearing it takes either a reported upload or any answer that carries the
/// identity. So the state where it misleads needs all three of: a
/// publication that reached the server but was never reported; an identity
/// reset elsewhere afterwards; and then a stale or omitting answer, since an
/// honest one would carry the new identity and clear the record on its way
/// past. A device in that state republishes the identity it holds over the
/// newer one.
///
/// That is strictly narrower than what the sixth round exposed, which was
/// every store holding any identity, and enormously narrower than what the
/// seventh round cost, which was every interrupted sign-up. It is not zero
/// and it is not claimed to be.
pub(crate) async fn identity_is_unpublished(machine: &OlmMachine) -> bool {
    let Some(held) = own_master_key(machine).await else {
        return false;
    };
    machine
        .store()
        .get_value::<String>(UNPUBLISHED_IDENTITY_KEY)
        .await
        .ok()
        .flatten()
        .is_some_and(|recorded| recorded == held)
}

/// Whether the account's private signing keys were held the last time
/// anything looked, so that an arrival can be told from a standing fact.
///
/// Process-wide, like the machine and the flow registry, and deliberately
/// **not** persisted: it is not a record of what this account has, which is
/// [`IdentityStatus::private_keys_held`]'s job, but of what this process has
/// already reported. Seeded from the store the moment a machine is created
/// (`machine::build`), so a relaunch of a device that already holds the keys
/// starts out having nothing new to say.
static PRIVATE_KEYS_HELD: AtomicBool = AtomicBool::new(false);

/// Records what a machine holds at the moment it is created or reopened.
///
/// Called from `machine::build` and from its test reset, and from nowhere
/// else: every other update goes through [`note_private_keys_held`], which
/// is the one that decides whether anything is announced.
pub(crate) fn seed_private_keys_held(held: bool) {
    PRIVATE_KEYS_HELD.store(held, Ordering::SeqCst);
}

/// Records what the machine holds now, and answers whether that is news.
///
/// **True exactly once per arrival.** The two ways a device comes to hold
/// the account's private signing keys are [`bootstrap_identity`], which
/// mints them, and secret gossip from another of our own devices, which
/// lands inside `receive_sync_changes` after this device has verified
/// itself against one of them. Neither is special-cased: the rule is that
/// the first look which finds the keys present, after a look that found
/// them absent, is the arrival.
///
/// `false` is stored as faithfully as `true`, and that is not symmetry for
/// its own sake. Upstream drops a private identity that a key query has
/// contradicted (`identities/manager.rs:418-443`), so the keys really can
/// go away; recording that is what lets a later arrival be announced rather
/// than swallowed as "already reported".
///
/// The caller decides what to do with a `true`. `verification::announce_state_changes`
/// is the only one, and it only ever asks while somebody is listening, so
/// an arrival nobody was subscribed for leaves this latch alone and is
/// announced on the first sync after somebody subscribes.
pub(crate) fn note_private_keys_held(held_now: bool) -> bool {
    held_now && !PRIVATE_KEYS_HELD.swap(held_now, Ordering::SeqCst)
}

/// Where `session`'s settled-answer count stood when [`create_identity`] last
/// queued a key query of its own, or `None` when it has no such question
/// outstanding.
///
/// # What this exists to stop, and why nothing already here could
///
/// [`create_identity`] decides on one fact: *the account has no identity*.
/// It reads that fact out of upstream's store, where the last accepted
/// `/keys/query` answer put it, and **an answer is only ever true of the
/// instant the server computed it.**
///
/// This was described for two releases as a race between that instant and
/// this call, which reads as though acting quickly were enough. It is not,
/// and the difference is the whole of this static. The precondition is **as
/// old as the last answer**, and nothing shortens that on its own:
///
/// * `session::account_keys_answered` is sticky for the process, so once one
///   answer has landed the library never asks again of its own accord;
/// * upstream volunteers an own-account key query only while the account is
///   not yet tracked (`identities/manager.rs:836-852`), which after the first
///   sync it always is;
/// * and [`bootstrap_identity`]'s [`MachineError::IdentityNotKnown`] refusal
///   -- the refusal whose documented remedy is this very call -- queues
///   nothing.
///
/// **So it got worse the more careful a product was.** Measured on
/// continuwuity and on Synapse: a product that drained its pump to empty and
/// reported every answer honestly before deciding had *no* mechanism left to
/// refresh the one fact this call reads, and destroyed another device's live
/// identity. A sloppier product survived the same sequence only because an
/// unreported leftover key query happened to be sitting in its pump and
/// refreshed the fact by accident. A safety property that rewards the
/// accident and punishes the discipline is the wrong way round.
///
/// # What "fresh" has to mean, and why nothing weaker will do
///
/// **An answer that arrived after this call asked for one** -- not the most
/// recent answer in the store, and not an answer from within some window.
///
/// *Most recent in the store* is exactly `account_keys_answered`, and it is
/// exactly what was defeated: there is only ever one "most recent" answer,
/// and after the first one it never changes.
///
/// *Recent enough* would need a clock this library does not have and a
/// constant nobody can justify. It would also refuse in the wrong direction:
/// the legitimate finish of an interrupted publication can take as long as a
/// person needs to answer a homeserver's authentication challenge, and a
/// timeout would brick that while doing nothing about a fast attacker.
///
/// What is left is causal order inside this process, which is observable
/// exactly and needs nothing from outside: this call queued a question at one
/// moment, and an answer about this account settled at a later one. That is
/// what the count in `session::account_answers_settled` measures and what the
/// pair of it and this position compares.
///
/// # What it is worth, stated as a bound rather than as a claim
///
/// One refusal, one pump, one retry, and the window closes for every product
/// rather than only for the ones with something left in the pump.
///
/// **The window is not zero and is not claimed to be.** What remains is the
/// gap between the answer this call demanded landing and the retry that
/// spends it. What is gone is the unbounded part: the answer can no longer
/// predate the decision, and a product cannot make its exposure worse by
/// being thorough.
///
/// **And that remainder is the product's own, in both senses.** An
/// outstanding question stays outstanding until a publication spends it, so a
/// product that pumps the answer and then does other work before retrying is
/// served on an answer as old as its own delay. Nothing here can see that
/// delay: there is no clock in this library, and the only events it observes
/// are calls into it and answers reported to it. What it can and does say is
/// [`MachineError::AccountKeysStale`], at the moment the question has to be
/// asked, so a product that retries promptly has a window the length of one
/// round trip.
///
/// A wall-clock expiry would bound it in seconds and is deliberately not
/// added. It needs a constant nobody can justify, and it refuses in the wrong
/// direction: finishing an interrupted publication legitimately takes as long
/// as a person needs to answer a homeserver's authentication challenge, so
/// the timeout that shortened an attacker's window would brick that.
///
/// # Single-use, which is the half that is easy to leave out
///
/// The position is cleared when a publication is served, so the *next*
/// creation asks again. Without that, one fresh answer would authorise every
/// later call in the process, and the second one could be arbitrarily far
/// from it -- which is the unbounded window again, one call along.
///
/// Process-wide and deliberately not persisted, like `PRIVATE_KEYS_HELD`
/// above and `session::account_keys_answered`: a process that has just
/// reopened a store has asked nothing yet, whatever the process before it
/// did, and refusing until it does costs one round trip in the safe
/// direction.
static PUBLICATION_ASKED_AFTER: StdMutex<Option<u64>> = StdMutex::new(None);

/// Records that [`create_identity`] has just queued a key query of its own,
/// so the answer to it can be told from the one already in hand.
///
/// Overwrites unconditionally, and that is a no-op rather than a choice:
/// this is only ever called on a path that is about to refuse for want of a
/// fresh answer, and such a path is reached only while the count still stands
/// where the last ask left it.
fn note_publication_asked() {
    *PUBLICATION_ASKED_AFTER
        .lock()
        .expect("publication ask poisoned") = Some(crate::session::account_answers_settled());
}

/// Whether an answer about this account has settled since [`create_identity`]
/// asked for one.
///
/// `false` with no ask outstanding, which is the state a process starts in
/// and the state a served publication leaves behind. See
/// [`PUBLICATION_ASKED_AFTER`] for what fresh has to mean and why.
fn publication_answer_is_fresh() -> bool {
    matches!(
        *PUBLICATION_ASKED_AFTER
            .lock()
            .expect("publication ask poisoned"),
        Some(asked_after) if crate::session::account_answers_settled() > asked_after
    )
}

/// Spends the fresh answer a publication was served on, so the next creation
/// asks again.
fn spend_publication_ask() {
    *PUBLICATION_ASKED_AFTER
        .lock()
        .expect("publication ask poisoned") = None;
}

/// Forgets any outstanding ask, for `machine::reset_for_test`.
///
/// The same reason `session::forget_account_keys_answered_for_test` exists:
/// this position is counted against a process-wide count that reset clears,
/// and leaving it set would compare a fresh process's count against the
/// previous one's position. It is cleared *with* that count rather than
/// separately, so the pair cannot come apart.
#[cfg(test)]
pub(crate) fn forget_publication_ask_for_test() {
    spend_publication_ask();
}

/// What this library will say about the account's signing identity.
///
/// Three independent facts, none of which implies another, and the pair that
/// looks redundant is the pair that matters: `identity_known == false` means
/// something completely different depending on `account_keys_fetched`. With
/// it false, it means "nobody has asked". With it true, it means "the server
/// says there is none". Only the second is a basis for minting one, which is
/// why both are reported rather than a single collapsed answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityStatus {
    /// Whether a key query naming this account has been sent **and
    /// answered** in this process.
    ///
    /// Not persisted: a process that has just reopened a store has asked
    /// nothing yet, whatever the process before it did, and the account may
    /// have gained an identity in between. False here is not a claim that
    /// the account has no identity; it is a refusal to guess.
    pub account_keys_fetched: bool,
    /// Whether this machine holds a public signing identity for the account.
    ///
    /// Read only alongside `account_keys_fetched`. A bootstrap sets this
    /// true as a side effect of minting, so it is also how a caller sees
    /// that its own bootstrap took effect.
    pub identity_known: bool,
    /// Whether this device holds the account's complete private signing
    /// keys, and can therefore sign with the identity rather than only
    /// recognise it.
    ///
    /// A device that has joined the identity by self-verifying, or restored
    /// it from server-side storage, holds them too. Incomplete counts as
    /// false: upstream regenerates a partial private identity wholesale.
    ///
    /// **True does not mean the server agrees.** Until `account_keys_fetched`
    /// is also true, these keys may belong to an identity the account has
    /// since replaced -- a restored backup holds a complete one that is
    /// simply out of date. Upstream drops such keys when a key query
    /// contradicts them (`identities/manager.rs:418-443`), so this field is
    /// only trustworthy alongside that one.
    pub private_keys_held: bool,
    /// Whether a key query about this account was answered, and the answer
    /// left the library still unable to say whether the account has an
    /// identity.
    ///
    /// **Read this when `account_keys_fetched` is false, and only then.**
    /// The two together say which of two situations a refusal is in, and
    /// they have different remedies:
    ///
    /// * Both false: nobody has asked yet. The remedy is the documented one
    ///   -- drain `crate::take_outgoing_requests`, send what it hands back,
    ///   report each with `crate::mark_request_sent`, call again.
    /// * This true: a key query naming this account was sent, the server
    ///   answered, the answer was accepted, and upstream still does not know
    ///   whether the account has an identity. **Asking again will do the
    ///   same thing.** Either the answer did not cover this account -- which
    ///   the Matrix specification prescribes for a user a reachable server
    ///   does not know, and which a mixed-case server name in this machine's
    ///   own account id also produces, because a homeserver then treats the
    ///   account as remote -- or it asserted cross-signing keys for the
    ///   account that upstream could not read.
    ///
    /// So the action on this field is to stop looping and look at the
    /// account id: compare the `user_id` this machine was created with
    /// against the canonical one `/login` returned. Nothing is destroyed
    /// while this is true, and nothing will be: a refusal to mint is the
    /// safe direction, and this field is what stops the refusal from being
    /// silent.
    ///
    /// Never true alongside `account_keys_fetched`. Once upstream knows, a
    /// later answer that settles nothing does not un-know it.
    pub account_keys_answer_unsettled: bool,
    /// Whether this device holds an identity it minted and has **not yet
    /// seen the homeserver accept**.
    ///
    /// True from [`create_identity`] until a homeserver's own `/keys/query`
    /// answer carries that identity back, and it survives a relaunch,
    /// because the identity it describes is on disk and the publication was
    /// in memory. A process that is killed, offline, or whose upload times
    /// out in that window reopens its store in exactly this state.
    ///
    /// **The remedy is [`create_identity`] again, deliberately.** It hands
    /// back the same publication that was lost.
    ///
    /// This paragraph named [`bootstrap_identity`] for one release and that
    /// was wrong, and it stayed wrong here for one more after the facade was
    /// corrected and the core was not, which is why it now says so. From
    /// inside a process, an identity we hold and have never seen accepted is
    /// indistinguishable from one the account has since replaced, and no
    /// answer *already in hand* settles that, so finishing is a decision
    /// rather than a retry.
    ///
    /// # This flag reads identically in two situations, and one of them is
    /// destructive
    ///
    /// `true` means *finish your own publication* and it equally means *you
    /// are about to overwrite the identity your other phone made while this
    /// one was offline*. There is no local predicate over this store that
    /// separates them, and nine rounds of looking for one is why there is
    /// not.
    ///
    /// **What separates them is a fresh answer, and [`create_identity`] now
    /// forces one before it publishes.** The first call refuses
    /// [`MachineError::AccountKeysStale`] with the key query already queued;
    /// after the ordinary drain-send-report round the two situations have
    /// stopped being identical and the library reports which one this is:
    ///
    /// * *Finish your own publication*: the answer carries no other
    ///   identity, this flag stays `true`, and the next `create_identity`
    ///   hands back the publication.
    /// * *Your other device published one*: the answer carries it, upstream
    ///   adopts it and drops the private keys that disagree, this flag goes
    ///   **`false`** while `identity_known` stays `true` and
    ///   `private_keys_held` goes `false`, and the next `create_identity`
    ///   refuses [`MachineError::IdentityAlreadyExists`].
    ///
    /// So the flag on its own is still ambiguous at the moment it is read.
    /// What changed is that the ambiguity is now **resolved before anything
    /// is published**, rather than resolved by the publication.
    ///
    /// **Seven calls read this field**, and the list is here because wiring
    /// it into two of them and assuming the rest was the ninth round's
    /// mistake: `bootstrap_identity` and `create_identity` above,
    /// [`crate::create_recovery`] and [`crate::recover_identity`], and the
    /// three doors into a self-verification, [`crate::request_self_flow`],
    /// [`crate::accept_flow`] and [`crate::request_flow`] when it is handed
    /// this account's own identifiers.
    ///
    /// It is reported because it is the one state in which
    /// `identity_known` is true and the account still has no identity, so a
    /// product that shows "encryption is set up" on `identity_known` alone
    /// is wrong here and this is how it can tell. It authorises nothing.
    pub identity_publication_pending: bool,
}

/// Errors must not carry an identifier or key material, so an upstream store
/// failure reports its shape and nothing else -- the same rule and the same
/// fixed string as `machine.rs`'s `store_error_detail`, `identity.rs`'s
/// `store_failed` and `verification.rs`'s.
fn store_failed() -> MachineError {
    MachineError::Store {
        detail: "the crypto store could not be opened".to_string(),
    }
}

pub(crate) async fn read_status(machine: &OlmMachine) -> Result<IdentityStatus, MachineError> {
    // `None` as the timeout, not a duration: with `Some`, upstream waits for
    // an in-flight key query for this account to land
    // (`wait_if_user_pending`, `machine/mod.rs:2646`), and a read of what is
    // known *now* must not block on a request the caller may never send.
    let identity_known = machine
        .get_identity(machine.user_id(), None)
        .await
        .map_err(|_upstream| store_failed())?
        .is_some();

    Ok(IdentityStatus {
        account_keys_fetched: crate::session::account_keys_answered(),
        identity_known,
        private_keys_held: machine.cross_signing_status().await.is_complete(),
        account_keys_answer_unsettled: crate::session::account_keys_answer_unsettled(),
        identity_publication_pending: identity_is_unpublished(machine).await,
    })
}

/// Whether [`bootstrap_identity`] may proceed, given what is known.
///
/// The single place the rule lives, so [`identity_status`] and
/// [`bootstrap_identity`] cannot come to disagree about it.
///
/// # Nothing is served before the server has been asked
///
/// The check on `account_keys_fetched` comes first and has no exception,
/// **including for a device that already holds the private keys.** An
/// earlier version short-circuited on `private_keys_held`, reasoning that
/// upstream cannot mint when the private identity is complete
/// (`cross_signing_status().is_complete()` is exactly the negation of the
/// `PrivateCrossSigningIdentity::is_empty` upstream branches on --
/// `olm/signing/mod.rs:99-138`, `machine/mod.rs:676`) and that a key query
/// therefore could not change the outcome.
///
/// **It can change the outcome, and the case where it does is the case that
/// matters.** A store restored from a backup, or one whose account had its
/// identity reset from another device, holds a *complete* private identity
/// the server has already replaced. Republishing it puts the stale identity
/// back over the newer one, which resets the trust of every device and every
/// user who had verified the newer one -- the same destruction this gate
/// exists to prevent, arrived at from the other direction. Upstream itself
/// only notices on a key query: `IdentityManager::check_private_identity`
/// calls `clear_if_differs` and drops the stale private keys
/// (`identities/manager.rs:418-443`), after which `private_keys_held` is
/// false, `identity_known` is true, and the rule below refuses correctly.
///
/// The cost is one key query per process before its first bootstrap, not one
/// per bootstrap: `account_keys_fetched` stays true for the process
/// lifetime once an answer has been accepted. A caller pays the same
/// drain-send-report round it already pays on a fresh login, and pays it
/// uniformly rather than only in the cases that looked dangerous.
///
/// # The rule, and why it is now two rules
///
/// This used to be one predicate for two acts. Given the gate, it served a
/// call that would **republish** the identity this device holds, and it
/// served a call that would **create** the account's first identity, and a
/// caller could not say which of the two it meant. `bootstrap_identity` was
/// documented as safe to call on every launch, so the create was reached by
/// the ordinary launch path of every device.
///
/// That is what made the timing race destructive. Measured against a live
/// continuwuity: a device queried its own fresh account, the server honestly
/// answered "no identity" because at that instant there was none, another
/// device of the same account published one in the window, and the first
/// device's launch-time `bootstrap_identity` then minted a second identity
/// over it. **No misbehaving server is involved.** The answer was true when
/// it was sent, and no rule reading one answer can tell it from an answer
/// that is still true when it is reported.
///
/// So the second condition is not a better gate. It is that **creating an
/// identity is a different act from publishing one, and the caller has to
/// say which it means.** The library cannot know whether this account is
/// meant to be getting its first identity right now; the product can, and
/// it is the only party that can. [`may_publish`] governs the call a product
/// makes on every launch and it can never create anything; [`may_create`]
/// governs the one destructive act and nothing reaches it by default.
///
/// # `may_publish`
///
/// Served when this process has asked, the account has an identity, and this
/// device holds its private keys. The three refusals are kept apart because
/// their remedies differ: ask again; create one; join the one that exists.
fn may_publish(status: &IdentityStatus) -> Result<(), MachineError> {
    if !status.account_keys_fetched {
        return Err(MachineError::AccountKeysNotFetched);
    }
    if !status.identity_known {
        return Err(MachineError::IdentityNotKnown);
    }
    // **An identity no homeserver has confirmed is not this call's to
    // publish, and this arm is the whole of the ninth round.**
    //
    // The eighth round let it through, on the reasoning that finishing an
    // interrupted publication is publishing rather than creating. Measured
    // on continuwuity and on Synapse, that reasoning destroyed an account's
    // identity with an honest server, an honest answer, no stale data and no
    // product mistake: a device mints, loses the publication, relaunches, is
    // answered truthfully that the account has no identity, and in the
    // ordinary gap before that answer is reported a second device of the
    // same account finishes signing up. The launch-time call then
    // republished over the account's real identity, while `create_identity`
    // refused correctly throughout. The careful call did the damage.
    //
    // The root is that **from inside this process, an identity we hold and
    // have not seen accepted is indistinguishable from one the account has
    // since replaced.** The seventh round refused whenever the store held an
    // identity and bricked honest accounts; the eighth exempted the
    // unpublished one and handed the race back. Those are the same fact from
    // opposite sides, and no predicate over one `/keys/query` answer
    // separates them, because an answer describes the instant the server
    // computed it and nothing later.
    //
    // So the question is not which local rule but what a device may do when
    // it cannot tell, and the answer is: not this, not from here. Putting
    // something the server has never confirmed onto an account is a decision
    // about that account's identity, and this module already has a place
    // where decisions are made. [`create_identity`] finishes it, and the
    // refusal below is the same one a device with no identity at all
    // receives, for the same reason and with the same remedy.
    if status.identity_publication_pending {
        return Err(MachineError::IdentityNotKnown);
    }
    if !status.private_keys_held {
        return Err(MachineError::IdentityAlreadyExists);
    }
    Ok(())
}

/// Whether [`create_identity`] may mint the account's first identity.
///
/// Served when this process has asked and the answer said the account has
/// none. `identity_known` refuses whether or not this device holds the
/// private keys, and that is wider than the old rule on purpose: with an
/// identity known, there is nothing here to create, and the two things a
/// caller might have wanted are `bootstrap_identity` (publish the one this
/// device holds) and `crate::request_self_flow` (join the one it does not).
fn may_create(status: &IdentityStatus) -> Result<(), MachineError> {
    if !status.account_keys_fetched {
        return Err(MachineError::AccountKeysNotFetched);
    }
    // An identity this device minted and has never seen accepted is a
    // *candidate*, not the account's identity, so establishing the account's
    // first identity is still what this call is being asked to do and
    // finishing the publication is how it is done. Upstream re-derives the
    // same three keys rather than minting a second set
    // (`bootstrap_cross_signing` branches on `identity.is_empty()`), so what
    // the account gets is the identity this device already holds.
    //
    // This arm is what keeps the refusal in [`may_publish`] from being the
    // seventh round's brick: there is a way to finish, it is deliberate, and
    // `IdentityStatus::identity_publication_pending` is how a product knows
    // that finishing is what it is deciding on.
    if status.identity_known && !status.identity_publication_pending {
        return Err(MachineError::IdentityAlreadyExists);
    }
    Ok(())
}

/// What this library will say about the account's signing identity right
/// now. Reads only; asks the server nothing and mints nothing.
pub async fn identity_status() -> Result<IdentityStatus, MachineError> {
    with_machine(|machine| Box::pin(read_status(machine))).await?
}

/// Publishes the signing identity **this device already holds**.
///
/// Safe to call on every launch, and that is now true without qualification:
/// **this call cannot create an identity.** It republishes the one this
/// device holds the private keys for, and refuses every other state.
///
/// # What changed, and why the every-launch call gave up its other job
///
/// This used to mint the account's first identity when it judged the account
/// had none. That judgement rests on one `/keys/query` answer, and an answer
/// is only ever true of the instant the server sent it. Measured against a
/// live continuwuity: a device asked about its own fresh account, the server
/// honestly answered "no identity" because at that instant there was none,
/// another device of the same account published one in the window, and this
/// call then minted a second identity over it. The product had done nothing
/// wrong; it had called the function this library tells it to call on every
/// launch.
///
/// No rule reading one answer can tell a true "no identity" from one that
/// was true a moment ago, so the fix is not a better gate. It is that the
/// destructive act now has its own name and nothing arrives at it by
/// default: [`create_identity`] is the only call that mints, and a product
/// reaches it only by deciding to. See [`may_publish`] for the rule and
/// [`may_create`] for the other one.
///
/// The first call in a process is still normally refused once, with the key
/// query that lifts the refusal already queued, and the call after that
/// answer is served.
///
/// # What a caller must do next
///
/// Nothing here reaches the network; this library performs no request. On
/// success, drain [`crate::take_outgoing_requests`] and send what it hands
/// back **in the order it hands it back**, reporting each with
/// [`crate::mark_request_sent`]. The order that matters is device keys,
/// then `signing_keys_upload`, then `signature_upload`, because a signature
/// may reference a key that is not published yet.
///
/// **Four of the batch's entries come from this call, and the batch is
/// longer than four.** Do not assert a length. Observed after a served
/// bootstrap on a fresh machine:
/// `["keys_upload", "signing_keys_upload", "signature_upload",
/// "keys_upload", "keys_query"]` -- five, because the pump also carries
/// whatever else upstream owed at that moment, which here is a key query.
///
/// The four that belong to the bootstrap are a `keys_upload` this call
/// queued, the `signing_keys_upload`, the `signature_upload`, and then a
/// *second* `keys_upload` under a different id carrying the same device
/// keys. The duplicate is upstream's own standing "these device keys are
/// not published yet" request, which `outgoing_requests()` offers
/// independently of the copy `bootstrap_cross_signing` hands back. Sending
/// both is harmless -- the endpoint is idempotent and the second is a no-op
/// at the server -- and the copy this call queues is the one that has to
/// exist, because only a queued request carries a sequence stamp early
/// enough to sort ahead of the signing keys. A caller that would rather not
/// send the same twelve kilobytes twice may send the first `keys_upload`,
/// report it, and find the duplicate absent from the next batch.
///
/// The `signing_keys_upload` request is the one that needs user-interactive
/// authentication. Expect the first attempt to be refused with a challenge,
/// merge an `auth` object into the body, and send it again.
///
/// **The id survives any number of refused attempts, but not another
/// bootstrap.** Nothing about failing an attempt consumes the request:
/// [`crate::mark_request_sent`] removes an entry only on success, so a
/// caller may loop on a 401 as long as its user needs. What does retire the
/// id is calling this function again and draining the pump again, because a
/// second bootstrap re-derives the same three keys and the fresh
/// publication supersedes the stale one -- without that, the pump's pending
/// map would grow by one entry for every bootstrap-and-drain cycle in the
/// process. A held id then reports
/// [`crate::SessionError::UnknownRequest`], which fails closed and costs
/// nothing to recover from: the body is identical, so drain again and use
/// the id from the newer batch. If a user-interactive loop is in flight, do
/// not call this again until it finishes.
///
/// # Report only what a success returned
///
/// **Never report a non-2xx body through [`crate::mark_request_sent`]**,
/// and that includes the 401 challenge above. Send it to
/// [`crate::mark_request_failed`] instead, or report nothing at all, and
/// report the eventual success through `mark_request_sent`. This matters
/// more here than anywhere else on the surface: a failed key query reported
/// as a success is read by the gate below as "the server answered and this
/// account has no identity", which is the one fact that authorises a mint;
/// and the signing-keys upload's success response is an empty object, so a
/// reported challenge would mark an identity published that never was.
///
/// `mark_request_sent` refuses on sight every body it can show is not an
/// answer, and accepts every body shaped like one. **What that shape is, and
/// why the remainder cannot be closed from a body, is stated once at
/// `session::refuse_a_non_response`**; it is not restated here.
///
/// The part that bites at this call is that the empty object is inside the
/// shape for both requests above, and is the whole success response of the
/// signing-keys upload. Only the status tells that answer from a refusal,
/// and the status is yours. See [`crate::mark_request_failed`] for where a
/// non-2xx goes.
///
/// # Refusals
///
/// [`MachineError::AccountKeysNotFetched`] means this process cannot yet say
/// what identity this account has, so it cannot know whether minting or
/// republishing would destroy an existing one. **This call queues that key
/// query before returning it**, so the usual remedy is the ordinary loop:
/// drain the pump, send, report sent, call this again. Holding the private
/// keys is not an exemption; [`may_publish`] says why.
///
/// **That loop has a case where it never terminates, and this variant alone
/// does not say which case you are in.** Read
/// [`IdentityStatus::account_keys_answer_unsettled`]: false means nobody has
/// asked and the loop works; true means a query was sent, the server
/// answered, and the answer settled nothing, so the next round will do
/// exactly what the last one did. That field's own doc comment says what to
/// do instead, and `tests/identity_bootstrap_unsettled_answer.rs` drives
/// five rounds of the loop to show it. Splitting the two into separate
/// variants would be the better surface; it is not done here because
/// splitting one variant into two means **inserting**, which shifts every
/// wire ordinal after it and makes bindings generated before the change
/// decode the wrong refusal in silence. Appending is a different act and is
/// safe -- see [`MachineError::AccountKeysNotFetched`]'s own doc for the
/// correction, and [`MachineError::AccountKeysStale`] for a variant this
/// round appended.
///
/// [`MachineError::IdentityAlreadyExists`] means the answer named an
/// identity this device does not hold the private keys for. There is no
/// remedy through this call and there should not be: this device joins that
/// identity, it does not replace it, and [`crate::request_self_flow`] is how.
///
/// [`MachineError::IdentityNotKnown`] is the refusal this call gained, and
/// it is the one an existing product will meet first: the server was asked
/// and named no identity for this account, so there is nothing here to
/// publish. It is not a failure and nothing is wrong; it is this call
/// declining to make the decision that used to be made silently. The remedy
/// is [`create_identity`], and a product should reach it having decided that
/// this account is meant to be getting its first identity now.
pub async fn bootstrap_identity() -> Result<(), MachineError> {
    with_machine(|machine| {
        Box::pin(async move {
            let status = read_status(machine).await?;

            if let Err(refusal) = may_publish(&status) {
                if refusal == MachineError::AccountKeysNotFetched {
                    // Queued *by* the refusal, so the refusal is recoverable
                    // rather than a dead end. Upstream volunteers an
                    // own-account key query only while the account is not
                    // yet tracked ("We always want to track our own user",
                    // `identities/manager.rs:836-852`), and it will not
                    // re-dirty an account it is already tracking:
                    // `update_tracked_users` inserts into a set and only
                    // flags what was newly inserted (`store/mod.rs:258-273`).
                    // So on a second process for the same store, or on any
                    // process that shared a key before bootstrapping,
                    // nothing would ever ask again and this refusal would be
                    // permanent. Asking out-of-band costs one request and
                    // removes that trap entirely. It is covered by
                    // `tests/identity_bootstrap_recovery.rs`, which
                    // constructs the case upstream volunteers nothing in.
                    let (id, request) =
                        machine.query_keys_for_users(std::iter::once(machine.user_id()));
                    crate::session::queue_account_key_query(id, request);
                }
                return Err(refusal);
            }

            let requests = machine
                .bootstrap_cross_signing(false)
                .await
                .map_err(|_upstream| store_failed())?;

            queue_republication(requests);

            Ok(())
        })
    })
    .await?
}

/// Queues what a publication of this account's identity has to send, in
/// upstream's stated order, which is also the order their sequence stamps
/// put them in when the pump hands them out.
///
/// Two of the three are ordinary action requests; the middle one is the
/// request class the pump could not carry until M4 -- `AnyOutgoingRequest`
/// has no variant for that endpoint, so it can neither come out of
/// `outgoing_requests()` nor go into `queue_action_request`.
///
/// Shared by [`bootstrap_identity`] and [`create_identity`] rather than
/// written twice: the two calls differ in what they are allowed to do, not
/// in what they send, and a copy would let the orders drift apart.
fn queue_publication(requests: matrix_sdk_crypto::CrossSigningBootstrapRequests) {
    if let Some(device_keys) = requests.upload_keys_req {
        crate::session::queue_action_request(device_keys);
    }
    crate::session::queue_signing_keys_request(requests.upload_signing_keys_req);
    crate::session::queue_action_request(requests.upload_signatures_req.into());
}

/// Queues everything a publication sends **except the cross-signing keys
/// themselves**.
///
/// # The one request that can destroy an identity, and the only call allowed
/// to hand it over
///
/// `/keys/device_signing/upload` is the request that replaces an account's
/// cross-signing identity. Nothing else in a publication can: the device-key
/// upload republishes this device's own keys, and the signature upload
/// re-signs this device into the identity the account already has. Both are
/// idempotent and neither can overwrite anything.
///
/// So this exists to make one sentence true without qualification: **the
/// call a product makes on every launch never hands over the request that
/// can replace an identity.** The ninth round tried to make that true with a
/// predicate and closed one arm of a two-armed race. This closes the other by
/// removing the capability rather than guarding it.
///
/// **Measured, on continuwuity three times and on Synapse:** a device that
/// signed up entirely correctly, with `identity_publication_pending` false
/// and nothing stale, restarted, was refused and queued the key query as
/// documented, and had the homeserver answer that query honestly. Another
/// client of the same account reset the identity in the gap before the
/// product reported that answer, which is a first-class user-facing action in
/// every mainstream client. The gate lifted on a truthful answer, and
/// `bootstrap_identity` republished the old identity over the new one, after
/// which the status read byte-identical to before and no signal fired.
///
/// # Why the omitted request is never needed
///
/// `bootstrap_identity` reaches this only with the account's identity
/// **confirmed**: `may_publish` refuses while
/// [`IdentityStatus::identity_publication_pending`] is true, and confirmed
/// means a homeserver's own answer carried that identity back to us. So the
/// server demonstrably has it, and re-uploading it can only either change
/// nothing or replace something. There is no third outcome, and the first is
/// not worth the second.
///
/// The other two requests are still queued, and that is not tidiness. A
/// publication whose signature upload was the part that failed is repaired by
/// exactly this call, and the signature is what ties this device to the
/// account's identity.
fn queue_republication(requests: matrix_sdk_crypto::CrossSigningBootstrapRequests) {
    if let Some(device_keys) = requests.upload_keys_req {
        crate::session::queue_action_request(device_keys);
    }
    crate::session::queue_action_request(requests.upload_signatures_req.into());
}

/// Creates this account's **first** signing identity.
///
/// **This is the one destructive call on this surface, and it is destructive
/// exactly when it is wrong.** An identity minted over one the account
/// already has replaces it, and replacing it resets the trust of every
/// device and every person who ever verified the old one. There is no undo,
/// and nothing afterwards can detect it.
///
/// It exists as its own call because that damage was previously reachable
/// from [`bootstrap_identity`], which this library tells a product to call
/// on every launch. See that function for the measured race that made an
/// honest homeserver enough to do it.
///
/// # What a caller must hold before calling this
///
/// The library's own precondition is [`may_create`]: this process has asked
/// the server, and the answer said the account has no identity.
/// **That precondition is necessary and it is not sufficient**, and this
/// paragraph is the whole reason the call is separate.
///
/// A `/keys/query` answer is only ever true of the instant the server sent
/// it, and another device of the same account can publish an identity after
/// that instant without anything already in hand being able to say so.
/// Measured on a live homeserver, with no misbehaviour anywhere: the server
/// answered "no identity" honestly, a second device published one, and a
/// mint followed. So the caller has to supply the fact the library cannot:
/// **that this account is meant to be getting its first identity now.** A
/// product knows things the library does not -- that the user has just
/// created the account, that this is the sign-up flow rather than a
/// relaunch, that no other session is listed on the account, that a person
/// has been asked and said yes. Calling this on every launch, or as the
/// automatic remedy for [`MachineError::IdentityNotKnown`], puts that
/// decision back where it was and the race back with it.
///
/// # The precondition is as old as the last answer, and this bounds how old
///
/// **This section described a race "between that instant and this call" for
/// two releases, and that wording was wrong in a way that mattered.** It
/// reads as though acting quickly were enough. It was not. The gap was
/// unbounded and it did not shrink with care:
/// [`IdentityStatus::account_keys_fetched`] never goes false again, upstream
/// volunteers no key query for an account it already tracks, and the
/// [`MachineError::IdentityNotKnown`] refusal that routes a product here
/// queues nothing. So a product that had drained its pump to empty and
/// reported every answer honestly -- the diligent one -- had **no**
/// mechanism left to refresh the one fact this call reads. Measured on
/// continuwuity and on Synapse, in exactly that state, it replaced another
/// device's live identity; a less thorough product survived the same
/// sequence only because a leftover key query happened to be sitting in its
/// pump.
///
/// So this call **asks for itself, before it publishes, and serves only once
/// an answer has settled since it asked.** The first call in that state is
/// refused with [`MachineError::AccountKeysStale`], with the query already
/// queued, and the ordinary drain-send-report round serves the next one.
/// [`PUBLICATION_ASKED_AFTER`] is where fresh is defined and argued.
///
/// **What that is worth, as a bound rather than as a claim.** The answer can
/// no longer predate the decision. What remains is the product's own round
/// trip between the answer landing and the retry that spends it, which is in
/// the product's hands and entered deliberately, and which shrinks rather
/// than grows the more carefully a product behaves. That is the opposite of
/// what stood here before.
///
/// # The confirming query afterwards is detection, and only detection
///
/// It also queues a fresh account `/keys/query` *after* the publication, so
/// the product's ordinary pump loop asks the server once more straight
/// after. What that one is worth was overstated here once, and the
/// overstatement was measured, so it is stated precisely now.
///
/// **It covers the branch where the publication did not land**: a device
/// that minted and never published used to hold an identity the account does
/// not have, report `identity_known` and `private_keys_held` like a healthy
/// one, and never ask again, because a served publication queues no query
/// and upstream volunteers none for an account it already tracks. With the
/// query queued, the next answer settles that state, and
/// [`IdentityStatus::identity_publication_pending`] describes it while it
/// lasts.
///
/// **It does not cover the branch where the publication did land**, which is
/// the branch that does the damage. A product that sent the publication,
/// answered the authentication challenge and reported the success has
/// completed the overwrite; the confirming answer then carries *this
/// device's* identity, it matches the store, the positive branch settles,
/// and the status reads as a completely healthy device. Nothing in the
/// status, in any error, or in any later answer says the account's previous
/// identity was replaced. There is no path back and this module does not
/// pretend to offer one. What keeps a caller out of that branch is the
/// fresh-answer condition above and the decision this call exists to
/// require, not this query.
///
/// # What a caller must do next
///
/// The same as [`bootstrap_identity`]: drain [`crate::take_outgoing_requests`]
/// and send what it hands back in the order it hands it back, reporting each
/// with [`crate::mark_request_sent`]. Everything that call documents about
/// the user-interactive authentication loop, about reporting only what a 2xx
/// returned, and about the batch being longer than the requests this call
/// owns, applies here unchanged and is not repeated.
///
/// # Refusals
///
/// [`MachineError::AccountKeysNotFetched`] means this process cannot yet say
/// what identity this account has. As with `bootstrap_identity`, this call
/// queues that key query before returning, and
/// [`IdentityStatus::account_keys_answer_unsettled`] says whether the remedy
/// is to pump and call again or to stop and check the account id.
///
/// [`MachineError::AccountKeysStale`] means this process has been answered,
/// and not since this call asked. The query is queued, so the remedy is the
/// same one round -- drain, send, report, call again -- and against an
/// honest server it terminates, because the answer that lifts it is the same
/// answer that would have lifted the variant above. **Do not read it as a
/// retry with no consequence.** The answer it forces is the one that can
/// come back carrying an identity another of the account's devices published
/// in the meantime, in which case the call after it refuses
/// [`MachineError::IdentityAlreadyExists`] and the account keeps what it
/// has. That refusal is this variant working rather than failing.
///
/// [`MachineError::IdentityAlreadyExists`] means the account already has an
/// identity, so there is nothing here to create. It is returned whether or
/// not this device holds the private keys, because neither case wants this
/// call: holding them, the call is [`bootstrap_identity`]; not holding them,
/// it is [`crate::request_self_flow`].
pub async fn create_identity() -> Result<(), MachineError> {
    with_machine(|machine| {
        Box::pin(async move {
            let status = read_status(machine).await?;

            if let Err(refusal) = may_create(&status) {
                if refusal == MachineError::AccountKeysNotFetched {
                    // Queued by the refusal, for `bootstrap_identity`'s
                    // reason, which its own comment states in full.
                    //
                    // Recorded as *this call's* ask as well, which is what
                    // makes the fresh-answer condition below cost nothing on
                    // the ordinary sign-up path: the query this refusal
                    // queues is one this call asked for, so the answer to it
                    // is fresh by the definition
                    // [`PUBLICATION_ASKED_AFTER`] gives, and the next call
                    // is served. One refusal, one pump, one retry.
                    note_publication_asked();
                    let (id, request) =
                        machine.query_keys_for_users(std::iter::once(machine.user_id()));
                    crate::session::queue_account_key_query(id, request);
                }
                return Err(refusal);
            }

            // **The condition [`may_create`] cannot express, and the reason
            // this call was still destructive after ten rounds.**
            //
            // Everything above is a reading of the last accepted answer, and
            // that answer can be arbitrarily old: the gate flag is sticky,
            // upstream volunteers no query for an account it already tracks,
            // and the refusal that sends a product here queues nothing. A
            // product that had drained its pump to empty and reported
            // everything -- the careful one -- had nothing left that could
            // refresh it, and replaced another device's live identity.
            //
            // So this call asks for itself, before it publishes, and serves
            // only once an answer has settled since it asked.
            // [`PUBLICATION_ASKED_AFTER`] is where fresh is defined and
            // argued, including what this does not close.
            if !publication_answer_is_fresh() {
                note_publication_asked();
                let (id, request) =
                    machine.query_keys_for_users(std::iter::once(machine.user_id()));
                crate::session::queue_account_key_query(id, request);
                return Err(MachineError::AccountKeysStale);
            }

            // Spent before the mint rather than after it, so that one fresh
            // answer authorises one publication whatever happens next. A
            // store failure below then costs one more pump, which is the
            // direction this module takes everywhere.
            spend_publication_ask();

            let requests = machine
                .bootstrap_cross_signing(false)
                .await
                .map_err(|_upstream| store_failed())?;

            // Recorded before the publication is queued, and that order is
            // the point rather than tidiness: between the mint and the
            // upload landing, this store holds an identity the account does
            // not have, and if this process dies in that window the record
            // is the only thing that will say so. Written after the mint
            // because it names the key the mint produced.
            note_identity_minted(machine).await;

            queue_publication(requests);

            // The confirming query. Queued *after* the publication, so the
            // pump hands the publication out first and the ordinary
            // send-and-report loop asks the server again immediately after.
            // See this function's own section on the window: this is
            // detection, not prevention, and it is stated as such.
            let (id, request) = machine.query_keys_for_users(std::iter::once(machine.user_id()));
            crate::session::queue_account_key_query(id, request);

            Ok(())
        })
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::machine::{create_machine, lock_for_test, reset_for_test, MachineConfig};
    use crate::runtime::in_runtime;
    use crate::session::{mark_request_sent, take_outgoing_requests, OutgoingRequest};

    const ACCOUNT: &str = "@alice:example.org";
    const DEVICE: &str = "DEVICEONE";
    const STORE_PASSPHRASE: &str = "test-passphrase";

    /// A real homeserver's real answer for an account it holds no identity
    /// for. Synapse and Dendrite byte for byte, account substituted. Note
    /// what it is: not an omission, but three explicit empty key maps.
    const NO_IDENTITY: &str = r#"{"device_keys":{"@alice:example.org":{}},"failures":{},"master_keys":{},"self_signing_keys":{},"user_signing_keys":{}}"#;

    fn config(store_path: &str) -> MachineConfig {
        MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: DEVICE.to_string(),
            store_path: store_path.to_string(),
            store_passphrase: Some(STORE_PASSPHRASE.to_string()),
        }
    }

    fn names_the_account(body: &str) -> bool {
        let parsed: serde_json::Value = serde_json::from_str(body).expect("JSON");
        parsed
            .get("device_keys")
            .and_then(|users| users.get(ACCOUNT))
            .is_some()
    }

    async fn drain_account_query() -> OutgoingRequest {
        let batch = take_outgoing_requests().await.expect("drain");
        batch
            .iter()
            .find(|r| r.kind == "keys_query" && names_the_account(&r.body))
            .unwrap_or_else(|| {
                panic!(
                    "no account key query; got {:?}",
                    batch.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>()
                )
            })
            .clone()
    }

    /// Turns the publication the mint queued into the `/keys/query` answer a
    /// homeserver that accepted it would send back.
    fn answer_carrying(publication: &str) -> String {
        let up: serde_json::Value = serde_json::from_str(publication).expect("JSON");
        serde_json::json!({
            "device_keys": { ACCOUNT: {} },
            "failures": {},
            "master_keys": { ACCOUNT: up["master_key"] },
            "self_signing_keys": { ACCOUNT: up["self_signing_key"] },
            "user_signing_keys": { ACCOUNT: up["user_signing_key"] },
        })
        .to_string()
    }

    /// A relaunch after an interrupted publication can still publish.
    ///
    /// **This is the shape of the defect the eighth round exists for, and it
    /// needs two processes.** The integration test
    /// `tests/identity_publication_interrupted.rs` drives the record's write
    /// and both of its clearing moments, but it cannot drive this: by the
    /// time it mints, the gate is already open, and the gate is monotonic,
    /// so a rule that refuses the next answer changes nothing it can see.
    /// Sabotaging the fix away left that file green. Only a *second* process,
    /// whose gate starts shut, meets the refusal that bricked the account.
    ///
    /// `machine::reset_for_test` is what makes that reachable from inside
    /// `src/`: it drops the held machine and clears `account_keys_answered`,
    /// so reopening the same store path is a relaunch in every way that
    /// matters here.
    #[test]
    fn a_relaunch_after_an_interrupted_publication_can_still_publish() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();

        let dir = tempfile::tempdir().expect("temp dir");
        let store_path = dir.path().join("store").to_string_lossy().into_owned();

        // ---- The first process: mint, then lose the publication --------
        {
            let store_path = store_path.clone();
            futures::executor::block_on(in_runtime(async move {
                create_machine(config(&store_path)).await.expect("machine");
                assert_eq!(
                    create_identity().await,
                    Err(MachineError::AccountKeysNotFetched)
                );
                let query = drain_account_query().await;
                mark_request_sent(&query.id, NO_IDENTITY)
                    .await
                    .expect("an honest answer about a fresh account");
                create_identity().await.expect("the deliberate mint");

                let minted = read_status_now().await;
                assert!(
                    minted.identity_publication_pending,
                    "the mint must be recorded as unpublished: {minted:?}"
                );
                // Drained and never sent: the process dies here.
                let _ = take_outgoing_requests().await.expect("drain");
            }));
        }

        // ---- The relaunch ----------------------------------------------
        reset_for_test();
        {
            let store_path = store_path.clone();
            futures::executor::block_on(in_runtime(async move {
                create_machine(config(&store_path))
                    .await
                    .expect("the store the first process wrote must reopen");

                let reopened = read_status_now().await;
                assert!(
                    !reopened.account_keys_fetched,
                    "a new process has asked nothing yet: {reopened:?}"
                );
                assert!(
                    reopened.identity_known && reopened.private_keys_held,
                    "and the store holds the identity the first process minted: {reopened:?}"
                );
                assert!(
                    reopened.identity_publication_pending,
                    "and the record that it was never published survived the relaunch,                      which is the whole of the fix: {reopened:?}"
                );

                // The documented remedy, once.
                assert_eq!(
                    bootstrap_identity().await,
                    Err(MachineError::AccountKeysNotFetched)
                );
                let query = drain_account_query().await;
                mark_request_sent(&query.id, NO_IDENTITY)
                    .await
                    .expect("the same honest answer as before");
                // Whether it is honest or raced is not knowable here, and
                // that is the ninth round's point: the assertions below are
                // about the gate lifting, and about which call may act on
                // it.

                let answered = read_status_now().await;
                assert!(
                    answered.account_keys_fetched,
                    "THIS is the assertion the file exists for. Refused here, every write on                      this surface refuses forever, the account can never have cross-signing,                      and the only escape is deleting the store, which is the user's message                      history. Measured on continuwuity and on Synapse: {answered:?}"
                );
                assert!(
                    !answered.account_keys_answer_unsettled,
                    "and the caller must not be told the answer settled nothing: {answered:?}"
                );

                // **The remedy moved in the ninth round, and this is where
                // it moved to.** The eighth round made it
                // `bootstrap_identity`, the call a product already makes on
                // every launch, on the reasoning that finishing a
                // publication is publishing. Measured on continuwuity and on
                // Synapse, that is how an honest raced answer destroyed an
                // account's real identity: this device holds the private
                // keys, so the launch-time call was served, and it
                // republished over an identity a second device had just
                // legitimately published.
                //
                // Finishing is now a decision, like starting. The refusal is
                // the same one a device with no identity gets, so a product
                // that already handles a first sign-up handles this with the
                // same branch.
                assert_eq!(
                    bootstrap_identity().await,
                    Err(MachineError::IdentityNotKnown),
                    "the launch-time call may not publish an identity nothing has \
                     confirmed, however long this device has held it"
                );
                // **What finishing a legitimate interrupted publication now
                // costs, measured here rather than asserted elsewhere.** The
                // answer this process has was asked for by the launch call's
                // refusal, not by this one, so the creation refuses once and
                // queues its own. That is one extra drain-send-report round,
                // and then the publication is handed back exactly as before.
                assert_eq!(
                    create_identity().await,
                    Err(MachineError::AccountKeysStale),
                    "a creation may not decide on an answer it did not ask for, however \
                     honest that answer was"
                );
                let refresh = drain_account_query().await;
                mark_request_sent(&refresh.id, NO_IDENTITY)
                    .await
                    .expect("the query the refusal queued must be answerable");

                create_identity().await.expect(
                    "and the deliberate call must hand back the publication that \
                             was lost, or this is the seventh round's brick again",
                );
                let batch = take_outgoing_requests().await.expect("drain");
                assert!(
                    batch.iter().any(|r| r.kind == "signing_keys_upload"),
                    "which means the upload itself, not merely a success: {:?}",
                    batch.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>()
                );
            }));
        }
        reset_for_test();
    }

    /// An answer that carries the identity clears the record too.
    ///
    /// The second of the two moments a homeserver tells us a publication
    /// landed, and it covers the device whose upload succeeded and whose
    /// report never happened. Without it that device would keep an identity
    /// exempt from the contradiction check for the life of the store.
    ///
    /// Its own test because the exemption is only observable while it lasts,
    /// and the file above needs it to last.
    #[test]
    fn an_answer_that_carries_the_identity_clears_the_record() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();

        let dir = tempfile::tempdir().expect("temp dir");
        let store_path = dir.path().join("store").to_string_lossy().into_owned();

        futures::executor::block_on(in_runtime(async move {
            create_machine(config(&store_path)).await.expect("machine");
            assert_eq!(
                create_identity().await,
                Err(MachineError::AccountKeysNotFetched)
            );
            let query = drain_account_query().await;
            mark_request_sent(&query.id, NO_IDENTITY)
                .await
                .expect("an honest answer");
            create_identity().await.expect("the deliberate mint");
            assert!(read_status_now().await.identity_publication_pending);

            let batch = take_outgoing_requests().await.expect("drain");
            let publication = batch
                .iter()
                .find(|r| r.kind == "signing_keys_upload")
                .expect("the mint queues its publication")
                .clone();
            let confirming = batch
                .iter()
                .find(|r| r.kind == "keys_query" && names_the_account(&r.body))
                .expect("the mint queues its confirming query")
                .clone();

            // The upload landed; the report never happened. The confirming
            // query then comes back carrying the identity the server now has.
            mark_request_sent(&confirming.id, &answer_carrying(&publication.body))
                .await
                .expect("the answer must be accepted");

            let settled = read_status_now().await;
            assert!(
                !settled.identity_publication_pending,
                "the server has told us it has this identity, so the record must go: left                  standing, this identity is exempt from the contradiction check forever and                  a later stale answer could republish it over a newer one: {settled:?}"
            );
            assert!(settled.account_keys_fetched && settled.identity_known);
        }));
        reset_for_test();
    }

    /// Reads the status through the machine, without the public wrapper,
    /// because these tests are already inside a `with_machine` closure's
    /// runtime and the wrapper would take the lock a second time.
    async fn read_status_now() -> IdentityStatus {
        crate::machine::with_machine(|machine| Box::pin(read_status(machine)))
            .await
            .expect("the machine is live")
            .expect("reading the status must not fail")
    }

    /// The two rules, stated once and checked against every combination they
    /// can face, without a store or a machine in sight.
    ///
    /// The integration tests under `tests/` drive the refusals through the
    /// real surface, which is what proves they are reachable. This covers
    /// what those cannot reach cheaply: that no combination of the flags
    /// produces an outcome neither rule names, and that
    /// `account_keys_answer_unsettled` **decides nothing** in either. That
    /// last one is the point of running the fourth flag through the loop: it
    /// is a diagnosis for a caller, not a second gate, and a rule that let it
    /// serve anything would be the whole defect back under a new name.
    ///
    /// **The pair is asserted together, and the property that matters is a
    /// property of the pair**: for every one of the thirty-two states, at
    /// most one of the two calls is served. Publishing and creating are
    /// different acts on the same account, and a state that served both
    /// would mean the split bought nothing.
    ///
    /// `identity_publication_pending` decides between them rather than
    /// deciding nothing, and that is the ninth round. An identity this
    /// device minted and has never seen a homeserver accept is a candidate
    /// rather than the account's identity, so publishing it is not the
    /// launch-time call's to do; finishing it is a decision, and
    /// `may_create` is where decisions are made.
    #[test]
    fn publishing_and_creating_are_served_in_states_that_never_overlap() {
        let mut both_served = Vec::new();
        for account_keys_fetched in [false, true] {
            for identity_known in [false, true] {
                for private_keys_held in [false, true] {
                    for account_keys_answer_unsettled in [false, true] {
                        for identity_publication_pending in [false, true] {
                            let status = IdentityStatus {
                                account_keys_fetched,
                                identity_known,
                                private_keys_held,
                                account_keys_answer_unsettled,
                                identity_publication_pending,
                            };

                            let publish = if !account_keys_fetched {
                                Err(MachineError::AccountKeysNotFetched)
                            } else if !identity_known || identity_publication_pending {
                                Err(MachineError::IdentityNotKnown)
                            } else if !private_keys_held {
                                Err(MachineError::IdentityAlreadyExists)
                            } else {
                                Ok(())
                            };
                            assert_eq!(may_publish(&status), publish, "publish, for {status:?}");

                            let create = if !account_keys_fetched {
                                Err(MachineError::AccountKeysNotFetched)
                            } else if identity_known && !identity_publication_pending {
                                Err(MachineError::IdentityAlreadyExists)
                            } else {
                                Ok(())
                            };
                            assert_eq!(may_create(&status), create, "create, for {status:?}");

                            if publish.is_ok() && create.is_ok() {
                                both_served.push(status);
                            }
                        }
                    }
                }
            }
        }
        assert!(
            both_served.is_empty(),
            "no state may serve both publishing and creating; these did: {both_served:?}"
        );
    }

    /// The rows the milestone exists for, named rather than left to be read
    /// out of the loop above.
    #[test]
    fn neither_call_is_served_before_the_server_has_been_asked() {
        // Asked nothing, hold nothing, know nothing: a gate written as "is
        // the local identity empty" serves this row.
        let unasked = IdentityStatus {
            account_keys_fetched: false,
            identity_known: false,
            private_keys_held: false,
            account_keys_answer_unsettled: false,
            identity_publication_pending: false,
        };
        assert_eq!(
            may_publish(&unasked),
            Err(MachineError::AccountKeysNotFetched)
        );
        assert_eq!(
            may_create(&unasked),
            Err(MachineError::AccountKeysNotFetched)
        );

        // Asked, answered, and the answer settled nothing: the row a server
        // that omits a user it does not know produces, the one a mixed-case
        // server name produces against a real Synapse, and now also the one a
        // restored store meets when an omitting answer contradicts what it
        // already holds. The refusal is the same and must be.
        let unsettled = IdentityStatus {
            account_keys_answer_unsettled: true,
            ..unasked
        };
        assert_eq!(
            may_publish(&unsettled),
            Err(MachineError::AccountKeysNotFetched)
        );
        assert_eq!(
            may_create(&unsettled),
            Err(MachineError::AccountKeysNotFetched)
        );
    }

    /// Asked, but the answer named an identity: **neither** call may mint.
    ///
    /// The row `create_identity` widened. The old single rule served this
    /// state whenever the private keys happened to be held, because it could
    /// not tell a republication from a creation. Now `bootstrap_identity`
    /// serves it, as the republication it is, and `create_identity` refuses
    /// it, because there is nothing here to create.
    #[test]
    fn an_account_that_already_has_an_identity_is_never_created_over() {
        for private_keys_held in [false, true] {
            // `identity_publication_pending: false` throughout: this row is
            // about an identity a homeserver has confirmed. The pending one
            // is the other row, below, and it is deliberately not the same
            // answer.
            let known = IdentityStatus {
                account_keys_fetched: true,
                identity_known: true,
                private_keys_held,
                account_keys_answer_unsettled: false,
                identity_publication_pending: false,
            };
            assert_eq!(
                may_create(&known),
                Err(MachineError::IdentityAlreadyExists),
                "creating over a known identity is the destruction this \
                 module exists to prevent, and holding the private keys is \
                 not an exemption from it: {known:?}"
            );
        }
    }

    /// Asked, and this device holds an identity nothing has confirmed:
    /// **only** creating, which is the ninth round's whole rule.
    ///
    /// The state a lost publication leaves behind. `bootstrap_identity` used
    /// to be served here, and measured on two live homeservers that is how
    /// an honest raced answer destroyed an account's real identity through
    /// the call every product makes on every launch.
    #[test]
    fn an_unconfirmed_identity_is_published_by_nothing() {
        for private_keys_held in [false, true] {
            let pending = IdentityStatus {
                account_keys_fetched: true,
                identity_known: true,
                private_keys_held,
                account_keys_answer_unsettled: false,
                identity_publication_pending: true,
            };
            assert_eq!(
                may_publish(&pending),
                Err(MachineError::IdentityNotKnown),
                "the launch-time call may not put an identity no homeserver has confirmed \
                 onto an account: {pending:?}"
            );
            assert_eq!(
                may_create(&pending),
                Ok(()),
                "and finishing it must stay reachable, or this is the seventh round's \
                 brick again: {pending:?}"
            );
        }
    }

    /// Asked, and the answer said the account has none: **only** creating.
    ///
    /// The mirror of the row above, and the one that says the every-launch
    /// call gave up its other job. `bootstrap_identity` used to mint here.
    #[test]
    fn an_account_with_no_identity_is_published_by_nothing() {
        let none = IdentityStatus {
            account_keys_fetched: true,
            identity_known: false,
            private_keys_held: false,
            account_keys_answer_unsettled: false,
            identity_publication_pending: false,
        };
        assert_eq!(
            may_publish(&none),
            Err(MachineError::IdentityNotKnown),
            "there is nothing to publish, and the call that used to mint here \
             is the one an honest server plus timing turned into a mint over \
             a published identity: {none:?}"
        );
        assert_eq!(may_create(&none), Ok(()));
    }
}
