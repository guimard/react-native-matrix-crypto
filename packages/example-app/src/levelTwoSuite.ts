/**
 * Design doc section 8's level 2 -- a real homeserver and a third-party
 * client -- driven through the **published TypeScript surface**, on the
 * platform a product ships on.
 *
 * # What this proves that the core's own level 2 does not
 *
 * `rust/matrix-crypto-core/tests/level_two_interop.rs` already proves that
 * `matrix-nio` decrypts what this library encrypts, over a real homeserver,
 * in both directions. It drives the **Rust core**. Between that core and a
 * product sit the UniFFI scaffolding, the JSI binding, the generated
 * TypeScript and `facade.ts` itself -- none of which had ever faced a
 * homeserver, and one of which was already wrong: `receiveSyncChanges`'
 * documentation told products to hand over a whole `/sync` response, while
 * the guard eleven lines above it rejected exactly that. A person reading
 * code found it. No test could have, because no test in this repository had
 * ever fed that function a payload a homeserver produced.
 *
 * So every call below is the public facade, unwrapped: `createCryptoMachine`,
 * `takeOutgoingRequests`, `markRequestSent`, `receiveSyncChanges`,
 * `shareScopeKey`, `encryptEvent`, `decryptEvent`. Nothing reaches past it,
 * nothing from `./generated`, and **the library gained nothing to make this
 * work** -- which is the substantive positive result, not an aside.
 *
 * # Never throws, never skips
 *
 * Every name in {@link LEVEL_TWO_STEPS} produces exactly one check on every
 * run, in order, including runs where an earlier step failed. Those report
 * `ok: false` with "not reached", never nothing at all: a step that quietly
 * disappears takes the summary's denominator with it, and a summary that
 * counts fewer steps than it should is indistinguishable from a pass. This
 * milestone has hit that failure under several names.
 *
 * `teardown` is the exception to the stop-on-failure rule, and it is the
 * point of the exception: it runs after a failed step, not instead of being
 * reached. Task 12's level 2 tidied up after its last assertion, so twelve
 * devices and six rooms had to be removed by hand from a shared homeserver.
 *
 * # Two accounts, not one
 *
 * The core's level 2 used one account with two devices, so it never involved
 * a second Matrix user, and the branch `shareScopeKey`'s own documentation
 * calls load-bearing -- marking a *foreign* user tracked so upstream will
 * ever issue a `/keys/query` for them -- was never exercised on real
 * infrastructure. The counterparty here is a different user, which costs
 * nothing on a throwaway homeserver and makes step `sync_teaches_the_machine`
 * mean what it says.
 */

import {
  asCryptoScopeId,
  createCryptoMachine,
  decryptEvent,
  encryptEvent,
  encryptionSlice,
  isCryptoError,
  markRequestSent,
  receiveSyncChanges,
  shareScopeKey,
  takeOutgoingRequests,
  type EventEnvelope,
  type OutgoingRequest,
} from 'react-native-matrix-crypto'
import type { InteropCheck } from 'react-native-matrix-crypto/interop/suite'
import {
  corruptOneCharacter,
  counterpartyOp,
  httpJson,
  sendOutgoing,
  syncOnce,
  type LevelTwoPlan,
} from './levelTwoTransport'

/**
 * The steps this run reports, in order, always all of them.
 *
 * Exported so the harness can reconcile what came back against what was
 * promised, rather than trusting the array it was handed.
 */
export const LEVEL_TWO_STEPS = [
  'machine_created',
  'keys_published',
  'raw_sync_rejected',
  'counterparty_ready',
  'first_share_delivers_nothing',
  'counterparty_publishes_keys',
  'sync_teaches_the_machine',
  'claim_then_share_delivers_key',
  'library_encrypts_nio_decrypts',
  'nio_refuses_corrupted_ciphertext',
  'nio_encrypts_library_decrypts',
  'library_refuses_corrupted_ciphertext',
  'teardown',
] as const

export type LevelTwoStep = (typeof LEVEL_TWO_STEPS)[number]

/**
 * The payloads. Distinct per direction and per control, so no assertion can
 * be satisfied by the wrong event, and long enough that none could occur by
 * chance inside base64.
 *
 * The counterparty is never told any of them.
 */
const LIBRARY_BODY =
  'encrypted by react-native-matrix-crypto through the facade'
const LIBRARY_CONTROL_BODY =
  'the control that must never decrypt at the counterparty'
const NIO_BODY = 'encrypted by matrix-nio for the facade'
const NIO_CONTROL_BODY = 'the control the facade must never decrypt'

const ROOM_EVENT_TYPE = 'm.room.message'
const ENCRYPTED_EVENT_TYPE = 'm.room.encrypted'

/**
 * How `matrix-nio` words a refusal that came from the ratchet rather than
 * from bookkeeping around it.
 *
 * `olm_machine.py`'s `decrypt_megolm_event` raises three different
 * `EncryptionError`s and only one of them means "the ciphertext did not
 * authenticate":
 *
 * * `"Error decrypting megolm event: {vodozemac error}"` -- the session's own
 *   decrypt threw. **This one**, and the colon is what distinguishes it.
 * * `"Error decrypting megolm event, no session found with session id ..."` --
 *   the key never arrived. A comma, and a different fact entirely.
 * * `"Duplicate message index, possible replay attack from ..."` -- raised
 *   *after* a successful decrypt, and the false pass the control was
 *   rewritten to escape.
 *
 * Matching a counterparty's message text is brittle by nature. It is worth
 * it here for the same reason `level_two_interop.rs` gives: the alternative,
 * asserting only that the control did not decrypt, cannot tell the three
 * apart, and telling them apart is the entire value of the control. A
 * reworded upstream breaks this loudly, which is the correct failure.
 *
 * Kept character-for-character identical to the core proof's own
 * `NIO_RATCHET_REFUSAL`, so the two level 2 proofs cannot disagree about
 * what a refusal means without one of them going red.
 */
const NIO_RATCHET_REFUSAL = 'Error decrypting megolm event: '

/** The refusal that means "I have seen this message index", not "this did not authenticate". */
const NIO_REPLAY_REFUSAL = 'Duplicate message index'

/**
 * The passphrase for this run's store.
 *
 * Not a credential and not an example of how to choose one: the store lives
 * in a launch-scoped directory under this app's own private files, and the
 * app is uninstalled between runs. It is a literal for the same reason
 * `cryptoConfig.ts`'s is.
 */
const STORE_PASSPHRASE = 'level-two-facade-run'

/** UTF-8, written out: React Native ships no `TextDecoder`. */
function utf8Decode(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length;) {
    const first = bytes[i]
    let code: number
    let width: number
    if (first < 0x80) {
      code = first
      width = 1
    } else if ((first & 0xe0) === 0xc0) {
      code = first & 0x1f
      width = 2
    } else if ((first & 0xf0) === 0xe0) {
      code = first & 0x0f
      width = 3
    } else {
      code = first & 0x07
      width = 4
    }
    for (let k = 1; k < width && i + k < bytes.length; k += 1) {
      code = (code << 6) | (bytes[i + k] & 0x3f)
    }
    i += width
    if (code > 0xffff) {
      const rest = code - 0x10000
      out += String.fromCharCode(0xd800 + (rest >> 10), 0xdc00 + (rest & 0x3ff))
    } else {
      out += String.fromCharCode(code)
    }
  }
  return out
}

/** The `event_type` a to-device request declares in its own body. */
function declaredEventType(body: string): string {
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>
    return typeof parsed.event_type === 'string' ? parsed.event_type : '<none>'
  } catch {
    return '<unparseable>'
  }
}

/** Whether a to-device request addresses this exact user and device. */
function addresses(body: string, userId: string, deviceId: string): boolean {
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>
    const messages = parsed.messages as Record<string, unknown> | undefined
    const forUser = messages?.[userId] as Record<string, unknown> | undefined
    return forUser?.[deviceId] !== undefined
  } catch {
    return false
  }
}

/**
 * The to-device event type that actually carries a session key.
 *
 * A room key travels wrapped in an Olm session, so the request that carries
 * one declares `m.room.encrypted` -- the Olm-encrypted envelope -- and the
 * `m.room_key` inside it is not visible from here. The request that carries
 * *no* key declares `m.room_key.withheld`, whose content is "I could not
 * send you the key".
 */
const KEY_BEARING_EVENT_TYPE = 'm.room.encrypted'

/**
 * Whether any request in a batch carries the session key itself.
 *
 * **Asserted on the decoded event type, never on `kind` alone.** A
 * `kind === 'to_device'` assertion is satisfied by an `m.room_key.withheld`
 * notice, and that is precisely how design doc section 3ter's defect hid:
 * the failure looks exactly like success from inside the process. The two
 * are only distinguishable one level in, at the event type the body itself
 * declares, and by the device the message is addressed to.
 */
function carriesTheKey(
  batch: OutgoingRequest[],
  userId: string,
  deviceId: string,
): boolean {
  return batch.some(
    request =>
      request.kind === 'to_device' &&
      declaredEventType(request.body) === KEY_BEARING_EVENT_TYPE &&
      addresses(request.body, userId, deviceId),
  )
}

interface StepResult {
  ok: boolean
  detail: string
}

interface Step {
  name: LevelTwoStep
  run: () => Promise<StepResult>
}

/** Rendered without the failure's own text when it is a typed crypto error. */
function describeFailure(e: unknown): string {
  if (isCryptoError(e)) return `rejected with kind "${e.kind}"`
  if (e instanceof Error) return e.message
  return `failed with a non-Error ${typeof e}`
}

export interface LevelTwoOptions {
  plan: LevelTwoPlan
  /** A directory this process may write to, from the host platform. */
  storeDir: string
}

/**
 * Runs the whole level 2 exchange and returns one check per step.
 *
 * Never throws. A step that cannot be attempted reports FAIL; the run always
 * produces {@link LEVEL_TWO_STEPS}`.length` checks.
 */
export async function runLevelTwoSuite(
  options: LevelTwoOptions,
): Promise<InteropCheck[]> {
  const { plan, storeDir } = options
  const scope = asCryptoScopeId(plan.roomId)
  const mutation = plan.mutation

  // State handed between steps. Each is assigned by the step that produces
  // it; a step that never ran leaves its value undefined, and every step
  // after it reports "not reached".
  let since: string | null = null
  let nioDeviceId = ''
  let toDeviceEventsIngested = 0
  /** The counterparty's second event: the control, never decrypted intact. */
  let nioControlEvent: Record<string, unknown> | undefined

  /** One `/sync`, its slice fed to the machine, its raw body returned. */
  const syncAndFeed = async (
    timeoutMs: number,
  ): Promise<Record<string, unknown>> => {
    const body = await syncOnce(plan, since, timeoutMs)
    since = typeof body.next_batch === 'string' ? body.next_batch : since
    const slice = encryptionSlice(body)
    // No cast needed: `slice` is now `SyncDelta`, so this field is already
    // typed `unknown[] | undefined`.
    const toDevice = slice.to_device_events
    toDeviceEventsIngested += toDevice === undefined ? 0 : toDevice.length
    // Fed on every sync, including the empty ones. That is what a product's
    // sync loop does, and a to-device event a run declined to forward is a
    // room key the machine never gets: `/sync` offers each one once.
    await receiveSyncChanges(slice)
    return body
  }

  /** Drains the pump once, sends everything in it, marks each sent. */
  const pumpAndSend = async (): Promise<OutgoingRequest[]> => {
    const batch = await takeOutgoingRequests()
    for (const request of batch) {
      const response = await sendOutgoing(plan, request)
      await markRequestSent(request.id, response.text)
    }
    return batch
  }

  /** Drains the pump until it offers nothing, and says how many rounds it took. */
  const drainToEmpty = async (): Promise<number> => {
    for (let round = 1; round <= 8; round += 1) {
      const batch = await pumpAndSend()
      if (batch.length === 0) return round
    }
    throw new Error(
      'the pump still had work after eight rounds; it is not settling',
    )
  }

  /** Encrypts one payload and returns both the envelope and its content object. */
  const encryptOne = async (
    body: string,
  ): Promise<{ envelope: EventEnvelope; content: Record<string, unknown> }> => {
    const envelope = await encryptEvent(scope, ROOM_EVENT_TYPE, {
      body,
      msgtype: 'm.text',
    })
    const content = JSON.parse(utf8Decode(envelope.ciphertext)) as Record<
      string,
      unknown
    >
    return { envelope, content }
  }

  /** Sends one `m.room.encrypted` content object to the room, returning its event id. */
  const sendToRoom = async (
    content: Record<string, unknown>,
    txn: string,
  ): Promise<string> => {
    const path =
      `/_matrix/client/v3/rooms/${encodeURIComponent(plan.roomId)}` +
      `/send/${ENCRYPTED_EVENT_TYPE}/${encodeURIComponent(txn)}`
    const { status, text } = await httpJson(
      'PUT',
      `${plan.homeserver}${path}`,
      {
        token: plan.accessToken,
        body: JSON.stringify(content),
        timeoutMs: 60_000,
      },
    )
    if (status !== 200)
      throw new Error(`sending the encrypted event returned HTTP ${status}`)
    const eventId = (JSON.parse(text) as Record<string, unknown>).event_id
    if (typeof eventId !== 'string')
      throw new Error('the room send returned no event id')
    return eventId
  }

  const steps: Step[] = [
    {
      name: 'machine_created',
      run: async () => {
        if (storeDir === '') {
          return {
            ok: false,
            detail: 'the host supplied no writable store path',
          }
        }
        await createCryptoMachine({
          userId: plan.userId,
          deviceId: plan.deviceId,
          storePath: `${storeDir}/level-two/${String(Date.now())}`,
          storePassphrase: STORE_PASSPHRASE,
        })
        return {
          ok: true,
          detail:
            'a store was created for the identity the homeserver issued this run',
        }
      },
    },

    {
      name: 'keys_published',
      run: async () => {
        // A fresh device that publishes nothing is invisible to every other
        // client, and nothing below this line could work. The response is
        // the homeserver's own, fed back through `markRequestSent`
        // unwrapped -- a run that synthesised bodies of its own would prove
        // nothing about whether real ones are accepted.
        const batch = await takeOutgoingRequests()
        const upload = batch.find(request => request.kind === 'keys_upload')
        if (upload === undefined) {
          return {
            ok: false,
            detail: `no key upload among ${batch.length} outstanding requests on a fresh machine`,
          }
        }
        const response = await sendOutgoing(plan, upload)
        const counts = (JSON.parse(response.text) as Record<string, unknown>)
          .one_time_key_counts as Record<string, number> | undefined
        await markRequestSent(upload.id, response.text)
        for (const request of batch) {
          if (request.id === upload.id) continue
          const other = await sendOutgoing(plan, request)
          await markRequestSent(request.id, other.text)
        }
        const rounds = await drainToEmpty()
        const published = counts?.signed_curve25519 ?? 0
        return {
          ok: published > 0,
          detail:
            published > 0
              ? `the homeserver accepted this device's keys and holds ${published} one-time keys; ` +
                `the pump settled after ${rounds} further round(s)`
              : 'the homeserver reported no one-time keys after the upload',
        }
      },
    },

    {
      name: 'raw_sync_rejected',
      run: async () => {
        // The step the facade's documentation defect would have failed
        // against. A `/sync` body's top-level names and the five
        // `receiveSyncChanges` reads have no member in common, so the whole
        // response is not "a superset that gets ignored" -- it is rejected
        // before native is reached. A run written from the old
        // documentation would have asserted the opposite and gone red here.
        const body = await syncOnce(plan, null, 0)
        since = typeof body.next_batch === 'string' ? body.next_batch : null
        const keys = Object.keys(body)
        if (keys.length < 2) {
          return {
            ok: false,
            detail: `this /sync body has only ${keys.length} top-level field(s)`,
          }
        }
        const slice = encryptionSlice(body)
        const mapped = Object.keys(slice).length
        if (mapped === 0) {
          return {
            ok: false,
            detail: 'the mapping produced nothing from this /sync body',
          }
        }
        let rejected = ''
        try {
          await receiveSyncChanges(body)
        } catch (e) {
          rejected = isCryptoError(e) ? e.kind : 'a non-typed error'
        }
        // A rejected call has no effect, so the machine has still learned
        // nothing from this sync; feed the mapped form now so its to-device
        // events are not lost. `/sync` offers each of them exactly once.
        await receiveSyncChanges(slice)
        return {
          ok: rejected === 'malformed_payload',
          detail:
            rejected === 'malformed_payload'
              ? `a real /sync body with ${keys.length} top-level fields was rejected with ` +
                `"malformed_payload"; the mapping turns it into ${mapped} recognised field(s)`
              : `the raw /sync body was not rejected with "malformed_payload" (got ${
                  rejected === '' ? 'no rejection at all' : `"${rejected}"`
                })`,
        }
      },
    },

    {
      name: 'counterparty_ready',
      run: async () => {
        // nio logs in and joins the room, and deliberately publishes
        // nothing yet: its key upload is what the homeserver will later
        // report as a device-list change, and that change is what
        // `sync_teaches_the_machine` rests on.
        const reply = await counterpartyOp(plan, {
          op: 'login',
          room_id: plan.roomId,
        })
        nioDeviceId = String(reply.device_id ?? '')
        const joined = reply.joined === true
        return {
          ok: nioDeviceId.length > 0 && joined,
          detail:
            nioDeviceId.length > 0 && joined
              ? 'the third-party client logged in as a second Matrix user and joined the room'
              : `the counterparty reported device id present: ${nioDeviceId.length > 0}, joined: ${joined}`,
        }
      },
    },

    {
      name: 'first_share_delivers_nothing',
      run: async () => {
        // Design doc section 3ter, step 1, and section 7's "the first share
        // to a never-seen user delivers nothing, by construction". The
        // precondition matters as much as the assertion: an empty pump
        // immediately before means the keys query below can only be a
        // consequence of the share.
        //
        // Drained first rather than assumed empty: ingesting the initial
        // `/sync` legitimately arms work of its own (this homeserver reports
        // `device_unused_fallback_key_types`, which upstream answers with a
        // fallback-key upload), and that is the machine behaving correctly,
        // not a leftover.
        const rounds = await drainToEmpty()
        const before = await takeOutgoingRequests()
        if (before.length !== 0) {
          return {
            ok: false,
            detail: `the pump would not settle before the share (${before.length} after ${rounds} rounds)`,
          }
        }
        await shareScopeKey(scope, [plan.nioUserId])
        const batch = await takeOutgoingRequests()
        const query = batch.find(
          request =>
            request.kind === 'keys_query' &&
            request.body.indexOf(plan.nioUserId) !== -1,
        )
        const key = carriesTheKey(batch, plan.nioUserId, nioDeviceId)
        const declared = batch
          .filter(request => request.kind === 'to_device')
          .map(request => declaredEventType(request.body))
        for (const request of batch) {
          const response = await sendOutgoing(plan, request)
          await markRequestSent(request.id, response.text)
        }
        return {
          ok: query !== undefined && !key,
          detail:
            query !== undefined && !key
              ? `the first share to a never-seen user delivered no key-bearing to-device request ` +
                `and armed a keys query for them; the to-device requests it did produce ` +
                `declared [${declared.join(', ')}]`
              : `expected a keys query naming the counterparty and no key-bearing request; got query: ` +
                `${query !== undefined}, key: ${key}, to-device types [${declared.join(', ')}]`,
        }
      },
    },

    {
      name: 'counterparty_publishes_keys',
      run: async () => {
        const reply = await counterpartyOp(plan, { op: 'settle', rounds: 3 })
        const published = reply.published_keys === true
        return {
          ok: published,
          detail: published
            ? 'the third-party client published its device and one-time keys'
            : 'the third-party client reports it has not published its device keys',
        }
      },
    },

    {
      name: 'sync_teaches_the_machine',
      run: async () => {
        // The step this whole run exists for. `receiveSyncChanges` is the
        // layer's known-defective one, and a call that merely resolves
        // proves nothing about it by construction: the core's own payload
        // type defaults every field and ignores unknown keys, so the wrong
        // shape reports success and teaches the machine nothing.
        //
        // So: drain the pump and assert it empty; take what the homeserver
        // actually returned; map it; feed it; and require that the machine
        // now asks `/keys/query` about the *other user*. It had nothing to
        // ask a moment earlier, and nothing but this call happened in
        // between.
        const rounds = await drainToEmpty()
        const before = await takeOutgoingRequests()
        if (before.length !== 0) {
          return {
            ok: false,
            detail: `the pump would not settle before the sync (${before.length} after ${rounds} rounds)`,
          }
        }

        let reported = false
        let changedCount = 0
        for (let attempt = 0; attempt < 6 && !reported; attempt += 1) {
          const body = await syncOnce(plan, since, attempt === 0 ? 0 : 4000)
          since = typeof body.next_batch === 'string' ? body.next_batch : since
          const deviceLists = body.device_lists as
            Record<string, unknown> | null | undefined
          const changed = (deviceLists?.changed as string[] | undefined) ?? []
          changedCount = changed.length
          reported = changed.indexOf(plan.nioUserId) !== -1
          const slice = encryptionSlice(body)
          // No cast needed: `slice` is now `SyncDelta`, so this field is
          // already typed `unknown[] | undefined`.
          const toDevice = slice.to_device_events
          toDeviceEventsIngested += toDevice === undefined ? 0 : toDevice.length
          // The mutation feeds the raw response where the mapping belongs:
          // the shape the facade's documentation used to recommend. The
          // call throws, so the machine learns nothing and this step must
          // go red -- which is the whole point of the mutation.
          if (mutation === 'raw_sync_to_receive') {
            await receiveSyncChanges(body)
          } else {
            await receiveSyncChanges(slice)
          }
        }
        if (!reported) {
          return {
            ok: false,
            detail:
              'no /sync in this window reported the counterparty as changed',
          }
        }

        const after = await takeOutgoingRequests()
        const asked = after.filter(
          request =>
            request.kind === 'keys_query' &&
            request.body.indexOf(plan.nioUserId) !== -1,
        )
        // Handed back, not marked: the query is the input to the next step.
        return {
          ok: asked.length > 0,
          detail:
            asked.length > 0
              ? `the pump was empty, a /sync naming ${changedCount} changed user(s) was mapped and ` +
                `fed, and the machine now asks /keys/query about the other user`
              : `after feeding the mapped /sync the pump offered ${after.length} request(s), none ` +
                'a keys query about the other user',
        }
      },
    },

    {
      name: 'claim_then_share_delivers_key',
      run: async () => {
        // Design doc section 3ter's ordering, on real infrastructure, with
        // both halves asserted on the *decoded event type*: knowing a
        // device exists is not the same as being able to reach it.
        //
        // 1. `/keys/query` -- the machine learns the device exists.
        // 2. share -- produces a `/keys/claim` and, at most, a withheld
        //    notice. Never the key.
        // 3. `/keys/claim` -- an Olm session becomes possible.
        // 4. share again -- now the key itself.
        await pumpAndSend()

        await shareScopeKey(scope, [plan.nioUserId])
        const afterQuery = await takeOutgoingRequests()
        const claim = afterQuery.find(request => request.kind === 'keys_claim')
        const keyTooEarly = carriesTheKey(
          afterQuery,
          plan.nioUserId,
          nioDeviceId,
        )
        const declaredEarly = afterQuery
          .filter(request => request.kind === 'to_device')
          .map(request => declaredEventType(request.body))
        if (claim === undefined || keyTooEarly) {
          return {
            ok: false,
            detail:
              `expected a keys claim and no key-bearing request before it; got claim: ${claim !== undefined}, ` +
              `key: ${keyTooEarly}, to-device types [${declaredEarly.join(', ')}]`,
          }
        }
        let claimed = 0
        for (const request of afterQuery) {
          if (mutation === 'skip_keys_claim' && request.kind === 'keys_claim')
            continue
          const response = await sendOutgoing(plan, request)
          if (request.kind === 'keys_claim') {
            const keys = (JSON.parse(response.text) as Record<string, unknown>)
              .one_time_keys as
              Record<string, Record<string, unknown>> | undefined
            claimed = Object.keys(keys?.[plan.nioUserId] ?? {}).length
          }
          await markRequestSent(request.id, response.text)
        }

        await shareScopeKey(scope, [plan.nioUserId])
        const afterClaim = await takeOutgoingRequests()
        const delivered = carriesTheKey(afterClaim, plan.nioUserId, nioDeviceId)
        const declaredLate = afterClaim
          .filter(request => request.kind === 'to_device')
          .map(request => declaredEventType(request.body))
        for (const request of afterClaim) {
          if (
            mutation === 'withhold_room_key' &&
            request.kind === 'to_device' &&
            declaredEventType(request.body) === KEY_BEARING_EVENT_TYPE
          ) {
            continue
          }
          const response = await sendOutgoing(plan, request)
          await markRequestSent(request.id, response.text)
        }
        return {
          ok: delivered,
          detail: delivered
            ? `the claim returned ${claimed} one-time key(s) for the other device, and only the ` +
              `share after it produced a to-device request declaring ${KEY_BEARING_EVENT_TYPE} ` +
              `for that exact device; ` +
              `before the claim the to-device types were [${declaredEarly.join(', ')}]`
            : `after the claim no to-device request declared ${KEY_BEARING_EVENT_TYPE} for the other ` +
              `device; ` +
              `types were [${declaredLate.join(', ')}]`,
        }
      },
    },

    {
      name: 'library_encrypts_nio_decrypts',
      run: async () => {
        // Direction 1. The counterparty is never told the plaintext: it is
        // handed a room and an event id and reports what it made of it, so
        // a harness that lied would have to guess the string.
        const { envelope, content } = await encryptOne(LIBRARY_BODY)
        if (mutation === 'corrupt_the_event_nio_must_read') {
          content.ciphertext = corruptOneCharacter(String(content.ciphertext))
        }
        const eventId = await sendToRoom(
          content,
          `level-two-facade-${String(Date.now())}`,
        )
        const reply = await counterpartyOp(plan, {
          op: 'collect',
          room_id: plan.roomId,
          event_ids: [eventId],
          require_decrypted: [eventId],
          timeout_s: 90,
        })
        const events = reply.events as Record<string, Record<string, unknown>>
        const outcome = events[eventId]
        if (outcome === undefined) {
          return {
            ok: false,
            detail: 'the counterparty never saw the event at all',
          }
        }
        const decrypted = outcome.decrypted === true
        const bodyMatches = outcome.body === LIBRARY_BODY
        return {
          ok: decrypted && bodyMatches && envelope.algorithm.length > 0,
          detail:
            decrypted && bodyMatches
              ? 'an independent Matrix client decrypted an event this library encrypted, over a ' +
                'real homeserver, and recovered the exact plaintext'
              : `the counterparty reported decrypted: ${decrypted}, body matches: ${bodyMatches}`,
        }
      },
    },

    {
      name: 'nio_refuses_corrupted_ciphertext',
      run: async () => {
        // The control that makes the step above mean something. **Freshly
        // encrypted, not a copy**: a corrupted copy of an already-delivered
        // event carries a megolm message index the recipient has already
        // seen, so it is refused as a replay whatever the ciphertext says,
        // and a control built that way passes even when the corruption is
        // removed. That is exactly how task 12's first control proved
        // nothing.
        const { content } = await encryptOne(LIBRARY_CONTROL_BODY)
        if (mutation !== 'intact_control_to_nio') {
          content.ciphertext = corruptOneCharacter(String(content.ciphertext))
        }
        const eventId = await sendToRoom(
          content,
          `level-two-control-${String(Date.now())}`,
        )
        const reply = await counterpartyOp(plan, {
          op: 'collect',
          room_id: plan.roomId,
          event_ids: [eventId],
          require_decrypted: [],
          timeout_s: 60,
        })
        const events = reply.events as Record<string, Record<string, unknown>>
        const outcome = events[eventId]
        if (outcome === undefined) {
          return {
            ok: false,
            detail: 'the counterparty never saw the control event at all',
          }
        }
        const refused = outcome.decrypted !== true
        const reason = String(outcome.reason ?? '')
        // Positive, and specific to the one refusal that means the ciphertext
        // did not authenticate. A reason that is absent would satisfy a
        // negative assertion vacuously, which is the same shape as the bug
        // this control was rewritten to escape -- and a merely-positive test
        // like `/decrypt/i` would also accept NIO_NO_SESSION_REFUSAL, so the
        // control could silently degrade into "the key never arrived" and
        // stay green. See NIO_RATCHET_REFUSAL for the three wordings.
        const forTheRightReason =
          reason.indexOf(NIO_RATCHET_REFUSAL) !== -1 &&
          reason.indexOf(NIO_REPLAY_REFUSAL) === -1
        return {
          ok: refused && forTheRightReason,
          detail:
            refused && forTheRightReason
              ? 'a freshly encrypted event with one flipped ciphertext character was refused by ' +
                'the counterparty, and refused by the ratchet rather than for a missing key or a ' +
                'repeated message index'
              : `the counterparty reported refused: ${refused}, refused by the ratchet: ` +
                `${forTheRightReason}`,
        }
      },
    },

    {
      name: 'nio_encrypts_library_decrypts',
      run: async () => {
        // Direction 2. Two events, both sent before either is read: the
        // second is the control for the step below and must never be
        // decrypted intact, so it must occupy its own megolm message index.
        const first = await counterpartyOp(plan, {
          op: 'send',
          room_id: plan.roomId,
          body: NIO_BODY,
        })
        const second = await counterpartyOp(plan, {
          op: 'send',
          room_id: plan.roomId,
          body: NIO_CONTROL_BODY,
        })
        const wanted = [String(first.event_id), String(second.event_id)]

        const ingestedBefore = toDeviceEventsIngested
        const nioEvents: Record<string, Record<string, unknown>> = {}
        for (
          let attempt = 0;
          attempt < 12 && Object.keys(nioEvents).length < 2;
          attempt += 1
        ) {
          const body = await syncAndFeed(attempt === 0 ? 0 : 4000)
          const rooms = body.rooms as Record<string, unknown> | undefined
          const join = rooms?.join as
            Record<string, Record<string, unknown>> | undefined
          const timeline = join?.[plan.roomId]?.timeline as
            Record<string, unknown> | undefined
          for (const raw of (timeline?.events as
            Record<string, unknown>[] | undefined) ?? []) {
            const id = raw.event_id
            if (typeof id === 'string' && wanted.indexOf(id) !== -1)
              nioEvents[id] = raw
          }
        }
        const arrived = Object.keys(nioEvents).length
        if (arrived < 2) {
          return {
            ok: false,
            detail: `only ${arrived} of the counterparty's two events arrived`,
          }
        }
        // Kept for the step below, which must corrupt an event this machine
        // has never decrypted intact.
        nioControlEvent = nioEvents[wanted[1]]

        const envelope = await decryptEvent(scope, nioEvents[wanted[0]])
        const plaintext = JSON.parse(utf8Decode(envelope.ciphertext)) as Record<
          string,
          unknown
        >
        const ingested = toDeviceEventsIngested - ingestedBefore
        const ok =
          plaintext.body === NIO_BODY &&
          envelope.eventType === ROOM_EVENT_TYPE &&
          toDeviceEventsIngested > 0
        return {
          ok,
          detail: ok
            ? `this library decrypted an event an independent client encrypted; the room key ` +
              `reached it only through receiveSyncChanges, which ingested ` +
              `${toDeviceEventsIngested} to-device event(s) across the run (${ingested} in this step)`
            : `recovered event type "${envelope.eventType}", body matches: ${
                plaintext.body === NIO_BODY
              }, to-device events ingested: ${toDeviceEventsIngested}`,
        }
      },
    },

    {
      name: 'library_refuses_corrupted_ciphertext',
      run: async () => {
        // The in-direction control, on the counterparty's *second* event,
        // which has never been decrypted intact. Same reasoning as the
        // outbound control: corrupting a copy of an event this machine has
        // already read tests replay detection, not cryptography.
        //
        // The assertion names the exact kind. `classify_megolm_error`
        // routes a missing, stale or wrong-session key to `missing_key`
        // *ahead* of `undecryptable`, so only a genuine MAC or decode
        // failure can produce the kind asserted here.
        const target = nioControlEvent
        if (target === undefined) {
          return { ok: false, detail: 'no counterparty event to corrupt' }
        }
        const content = { ...(target.content as Record<string, unknown>) }
        if (mutation !== 'intact_control_to_library') {
          content.ciphertext = corruptOneCharacter(String(content.ciphertext))
        }
        let kind = ''
        try {
          await decryptEvent(scope, { ...target, content })
        } catch (e) {
          kind = isCryptoError(e) ? e.kind : 'a non-typed error'
        }
        return {
          ok: kind === 'undecryptable',
          detail:
            kind === 'undecryptable'
              ? 'a never-before-decrypted event with one flipped ciphertext character was ' +
                'rejected with kind "undecryptable", the kind a missing key cannot produce'
              : `expected kind "undecryptable", got ${kind === '' ? 'a successful decrypt' : `"${kind}"`}`,
        }
      },
    },
  ]

  /**
   * Runs whatever the outcome, including after a failed step.
   *
   * The homeserver is a container the runner destroys on exit, so nothing
   * this step does is the only thing standing between a failed run and
   * debris. It is here because the access token this run was handed should
   * stop working the moment the run is over, and because "it was revoked"
   * is worth asserting rather than assuming: the step is only green when
   * the same token is afterwards *refused*.
   */
  const teardown: Step = {
    name: 'teardown',
    run: async () => {
      // Best effort, and deliberately not asserted: the counterparty is
      // exactly the thing that may have died, and a teardown that depends
      // on what failed is not a teardown.
      try {
        await counterpartyOp(plan, { op: 'quit' }, 30_000)
      } catch {
        // Reported by its absence in the conductor's own log, not here.
      }
      try {
        const path = `/_matrix/client/v3/rooms/${encodeURIComponent(plan.roomId)}`
        await httpJson('POST', `${plan.homeserver}${path}/leave`, {
          token: plan.accessToken,
          body: '{}',
          timeoutMs: 30_000,
        })
        await httpJson('POST', `${plan.homeserver}${path}/forget`, {
          token: plan.accessToken,
          body: '{}',
          timeoutMs: 30_000,
        })
      } catch {
        // Same: the container's destruction is what guarantees this.
      }

      const loggedOut = await httpJson(
        'POST',
        `${plan.homeserver}/_matrix/client/v3/logout`,
        {
          token: plan.accessToken,
          body: '{}',
          timeoutMs: 30_000,
        },
      )
      const whoami = await httpJson(
        'GET',
        `${plan.homeserver}/_matrix/client/v3/account/whoami`,
        { token: plan.accessToken, timeoutMs: 30_000 },
      )
      const revoked = loggedOut.status === 200 && whoami.status === 401
      return {
        ok: revoked,
        detail: revoked
          ? 'this run logged its own device out, and the token it was given is now refused'
          : `logout returned HTTP ${loggedOut.status} and the token afterwards returned HTTP ${whoami.status}`,
      }
    },
  }

  const checks: InteropCheck[] = []
  let stopped = false
  for (const step of steps) {
    if (stopped) {
      checks.push({
        name: step.name,
        ok: false,
        detail: 'not reached: an earlier step failed',
      })
      continue
    }
    try {
      const result = await step.run()
      checks.push({ name: step.name, ok: result.ok, detail: result.detail })
      if (!result.ok) stopped = true
    } catch (e) {
      checks.push({ name: step.name, ok: false, detail: describeFailure(e) })
      stopped = true
    }
  }
  try {
    const result = await teardown.run()
    checks.push({ name: teardown.name, ok: result.ok, detail: result.detail })
  } catch (e) {
    checks.push({ name: teardown.name, ok: false, detail: describeFailure(e) })
  }
  return checks
}
