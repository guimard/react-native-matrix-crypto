import type { InteropCheck } from './suite'

/**
 * A real cryptographic round trip, driven entirely through the public
 * facade, returned as the same `InteropCheck[]` `runInteropSuite` returns so
 * the same reporter can print both.
 *
 * **This is not design doc section 8's level 1, and it does not discharge
 * that exit criterion.** Level 1 there is two machines, each with its own
 * store, exchanging keys and decrypting each other's events; that is
 * `rust/matrix-crypto-core/tests/two_parties.rs`, which exists and is
 * unaffected by this file. Level 2 is a real homeserver and a third-party
 * client. This suite is one machine decrypting its own event, and it
 * answers a question neither level asks: whether the *chain* -- TypeScript
 * facade, generated bindings, JSI, UniFFI scaffolding, Rust core -- carries
 * the cryptography that a host `cargo test` has already proved the Rust
 * does. M1a shipped nineteen green tests against an assumed UniFFI error
 * shape while the real one differed, and only real native code exposed it.
 *
 * `suite.ts`'s `BridgeBinding` is the model, and this file deliberately does
 * not extend it: that contract is about the probe (a record, some bytes, a
 * typed error, a callback), this one is about the crypto machine, and a
 * binding may well be able to satisfy one and not the other. What the two
 * share is the reporting type and the discipline behind it -- never throw,
 * report a failing check instead, so a partial result is still reportable
 * from an emulator or a simulator.
 *
 * Every member below is structurally typed rather than imported from
 * `../src/facade`, for the same reason `BridgeBinding` restates
 * `runProbe`'s shape instead of importing it: a future binding (wasm,
 * N-API) must be able to satisfy this contract without depending on the
 * React Native facade. That is also why `scope` is a plain `string` here
 * and not the branded `CryptoScopeId` -- the branded type is the facade's
 * compile-time guard for product code, and an adapter applies it on the way
 * in.
 */
export interface CryptoBindingMachineConfig {
  userId: string
  deviceId: string
  storePath: string
  storePassphrase: string | null
}

/** Mirrors the facade's `OutgoingRequest`; see its doc comment for `kind`. */
export interface CryptoBindingRequest {
  id: string
  kind: string
  body: string
}

/**
 * Mirrors the facade's `EventEnvelope`, minus the branded scope and minus
 * `senderVerification` -- this suite asserts on transport and payload, not
 * on sender authenticity, and restating the shape rather than importing it
 * is deliberate. Nothing here exercises the new field; see the backlog.
 */
export interface CryptoBindingEnvelope {
  algorithm: string
  eventType: string
  ciphertext: Uint8Array
  sender: string
}

export interface CryptoBinding {
  createCryptoMachine(config: CryptoBindingMachineConfig): Promise<void>
  takeOutgoingRequests(): Promise<CryptoBindingRequest[]>
  markRequestSent(id: string, responseJson: string): Promise<void>
  shareScopeKey(scope: string, userIds: string[]): Promise<void>
  encryptEvent(scope: string, eventType: string, payload: unknown): Promise<CryptoBindingEnvelope>
  decryptEvent(scope: string, rawEvent: unknown): Promise<CryptoBindingEnvelope>
  /**
   * The `kind` of a typed error, or undefined for anything else. The only
   * thing this suite ever puts in a `detail` when something rejects: an
   * error's `message` is free text that can echo its input (a JSON parse
   * failure quotes the text it choked on), and this suite's output is
   * printed to logcat and to the simulator console.
   */
  errorKind(e: unknown): string | undefined
}

export interface CryptoSuiteOptions {
  /**
   * Where the store goes. The library deliberately chooses no location, so
   * this has to come from the host: a directory the process may write to.
   */
  machine: CryptoBindingMachineConfig
  /** The scope every step below shares, encrypts and decrypts under. */
  scope: string
}

/**
 * The steps this suite reports, in order, always all of them.
 *
 * Exported so a caller can assert the count it got back rather than trusting
 * it: a summary that silently counts fewer steps than the suite has is the
 * failure this milestone has hit repeatedly under other names, and it is
 * only catchable against a number that lives somewhere.
 */
export const CRYPTO_SUITE_STEPS = [
  'machine_created',
  'key_upload_present',
  'first_share_delivers_nothing',
  'pump_marked_sent',
  'round_trip',
  'ciphertext_opaque',
] as const

export type CryptoSuiteStep = (typeof CRYPTO_SUITE_STEPS)[number]

/**
 * What `markRequestSent` must be handed for each `kind`, from the facade's
 * own table on `OutgoingRequest`. Nothing here is a homeserver response --
 * there is no homeserver in this suite -- they are the minimal
 * well-formed bodies each endpoint's response type accepts, which is what
 * the machine needs to advance its own state.
 *
 * A `kind` this table does not know still gets marked, with `{}`: `kind` is
 * an open tag by design, and a request left unmarked is handed out forever.
 */
const RESPONSE_BY_KIND: Readonly<Record<string, string>> = {
  keys_upload: '{"one_time_key_counts":{}}',
  keys_query: '{}',
  keys_claim: '{"one_time_keys":{}}',
  to_device: '{}',
  signature_upload: '{}',
  room_message: '{"event_id":"$probe:example.org"}',
}

const UNKNOWN_KIND_RESPONSE = '{}'

/**
 * The payload every round trip below starts from. Keys in ascending byte
 * order so `JSON.stringify` produces the same bytes the core's own
 * `decrypting_recovers_the_exact_payload_encrypt_event_started_from` test
 * compares against, without this suite also having to reason about key
 * ordering.
 *
 * `body` carries a distinctive marker rather than "hello": the
 * `ciphertext_opaque` step searches the ciphertext for it, and a short
 * common word could plausibly occur inside base64 by chance, which would
 * make that step fail for a reason that is not a defect.
 */
const PROBE_PAYLOAD = { body: 'probe-plaintext-marker', msgtype: 'm.text' } as const

const PROBE_EVENT_TYPE = 'm.room.message'

/** UTF-8, written out rather than assumed: React Native ships no
 * `TextEncoder`/`TextDecoder` (checked against `react-native`'s own
 * `InitializeCore`), and the byte-for-byte assertion below is only
 * meaningful if the bytes it compares are really the payload's own. */
function utf8Encode(text: string): Uint8Array {
  const out: number[] = []
  for (let i = 0; i < text.length; i += 1) {
    let code = text.charCodeAt(i)
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      const low = text.charCodeAt(i + 1)
      if (low >= 0xdc00 && low <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00)
        i += 1
      }
    }
    if (code < 0x80) {
      out.push(code)
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f))
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f))
    } else {
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      )
    }
  }
  return new Uint8Array(out)
}

function utf8Decode(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; ) {
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

/** True when `haystack` contains `needle` as a contiguous byte run. */
function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0 || needle.length > haystack.length) return false
  for (let start = 0; start <= haystack.length - needle.length; start += 1) {
    let match = true
    for (let k = 0; k < needle.length; k += 1) {
      if (haystack[start + k] !== needle[k]) {
        match = false
        break
      }
    }
    if (match) return true
  }
  return false
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false
  }
  return true
}

/**
 * A failure, rendered without the failure's own text.
 *
 * A typed error contributes its `kind`, which the core is careful to keep
 * free of identifiers, plaintext and store paths. Anything else contributes
 * its constructor name only. Neither ever carries a value.
 */
function describeFailure(binding: CryptoBinding, e: unknown): string {
  const kind = binding.errorKind(e)
  if (kind !== undefined) return `rejected with kind "${kind}"`
  const name = e instanceof Error ? e.constructor.name : typeof e
  return `failed with a non-typed ${name}`
}

interface StepResult {
  ok: boolean
  detail: string
}

interface Step {
  name: CryptoSuiteStep
  run: () => Promise<StepResult>
}

/**
 * The round trip, driven through the public facade and nothing else: create
 * a machine on a real store, publish its keys, share a scope key, pump what
 * that produced back into the machine, then encrypt an event and decrypt it
 * again. See this file's own header for what this is not -- it is not
 * section 8's level 1, and it discharges no exit criterion.
 *
 * # Never throws, never skips
 *
 * Every step in {@link CRYPTO_SUITE_STEPS} produces exactly one check, in
 * order, on every run -- including the runs where an earlier step failed and
 * the later ones could not be attempted. Those report `ok: false` with "not
 * reached", never nothing at all: a step that quietly disappears takes the
 * summary's denominator with it, and a summary that counts fewer steps than
 * it should is indistinguishable from a pass.
 *
 * # Why one machine can decrypt its own event
 *
 * `shareScopeKey` stores the inbound session alongside the outbound one, so
 * the machine holds the key it just encrypted with. The core's own
 * `decrypting_recovers_the_exact_payload_encrypt_event_started_from` rests
 * on the same property. This is therefore not a two-party proof --
 * `tests/two_parties.rs` is, and that one runs on the host -- it is a proof
 * that the cryptography survives the whole chain from TypeScript to Rust
 * and back, on the platform a product ships on.
 *
 * # The first share delivers nothing, and that is the contract
 *
 * Design doc section 7: the first `shareScopeKey` for a user this machine
 * has never seen tracks that user and arms a `/keys/query` which has not
 * reached any homeserver, so no device is known and there is nobody to
 * share with. `first_share_delivers_nothing` asserts exactly that, as a
 * property to hold rather than a failure to tolerate.
 */
export async function runCryptoSuite(
  binding: CryptoBinding,
  options: CryptoSuiteOptions,
): Promise<InteropCheck[]> {
  const { machine, scope } = options

  // State handed between steps. Assigned by the step that produces it and
  // read by the ones after it; a step that never ran leaves its own value
  // undefined, and the steps after it never run either.
  let pending: CryptoBindingRequest[] = []
  let encrypted: CryptoBindingEnvelope | undefined

  const steps: Step[] = [
    {
      name: 'machine_created',
      run: async () => {
        if (machine.storePath === '') {
          return {
            ok: false,
            detail: 'the host supplied no writable store path',
          }
        }
        await binding.createCryptoMachine(machine)
        return { ok: true, detail: 'a store was created under the path the host supplied' }
      },
    },
    {
      name: 'key_upload_present',
      run: async () => {
        // Not marked sent here: step 4 marks this batch and the one the
        // share adds to it, together. A fresh device with nothing to
        // publish is invisible to every other client, so nothing below
        // this line could work if it were missing.
        //
        // "Fresh" is a real precondition, not a formality. A machine that
        // has already published its one-time keys offers no upload until a
        // `/sync` tells it how many the server still holds -- upstream tops
        // them up from `one_time_keys_counts`, which reaches the machine
        // only through `receiveSyncChanges`, and this suite fakes no sync.
        // So this step holds on a cold start and legitimately does not on a
        // second run against the same live machine; the failure detail says
        // so rather than leaving a reader to guess.
        pending = await binding.takeOutgoingRequests()
        const ok = pending.some((request) => request.kind === 'keys_upload')
        return {
          ok,
          detail: ok
            ? `the pump offers a key upload among ${pending.length} outstanding requests`
            : `no key upload among ${pending.length} outstanding requests; this step holds on a cold start, against a machine that has not published yet`,
        }
      },
    },
    {
      name: 'first_share_delivers_nothing',
      run: async () => {
        await binding.shareScopeKey(scope, [machine.userId])
        pending = await binding.takeOutgoingRequests()
        const toDevice = pending.filter((request) => request.kind === 'to_device').length
        const queries = pending.filter((request) => request.kind === 'keys_query').length
        const ok = toDevice === 0 && queries > 0
        return {
          ok,
          detail: ok
            ? 'the share delivered nothing and left a keys query outstanding, as section 7 documents'
            : `expected 0 to-device requests and at least one keys query, got ${toDevice} and ${queries}`,
        }
      },
    },
    {
      name: 'pump_marked_sent',
      run: async () => {
        for (const request of pending) {
          await binding.markRequestSent(
            request.id,
            RESPONSE_BY_KIND[request.kind] ?? UNKNOWN_KIND_RESPONSE,
          )
        }
        // Section 7's obligation on the product, discharged here so the
        // step after this one measures the cryptography and not the
        // plumbing: the machine has now been told what it asked to be
        // told, so this is the share that a product would expect to
        // deliver a key.
        await binding.shareScopeKey(scope, [machine.userId])
        return {
          ok: true,
          detail: `marked ${pending.length} requests sent, then shared again per section 7`,
        }
      },
    },
    {
      name: 'round_trip',
      run: async () => {
        encrypted = await binding.encryptEvent(scope, PROBE_EVENT_TYPE, PROBE_PAYLOAD)

        // `encryptEvent`'s ciphertext is the encrypted content as JSON. The
        // event around it is what a homeserver would have delivered:
        // `decryptEvent` takes that whole event, not the content alone.
        const content: unknown = JSON.parse(utf8Decode(encrypted.ciphertext))
        const decrypted = await binding.decryptEvent(scope, {
          sender: encrypted.sender,
          event_id: '$probe:example.org',
          origin_server_ts: 1_700_000_000_000,
          content,
        })

        // Byte for byte against the exact JSON the facade stringified on
        // the way in -- not "equal after a round trip through a value tree
        // that may reorder keys", which a decryptor returning a re-encoded
        // payload would also satisfy.
        const expected = utf8Encode(JSON.stringify(PROBE_PAYLOAD))
        const ok =
          bytesEqual(decrypted.ciphertext, expected) &&
          decrypted.eventType === PROBE_EVENT_TYPE &&
          decrypted.algorithm.length > 0
        return {
          ok,
          detail: ok
            ? `${expected.length} plaintext bytes recovered byte for byte`
            : `recovered ${decrypted.ciphertext.length} bytes, expected ${expected.length}, event type "${decrypted.eventType}"`,
        }
      },
    },
    {
      name: 'ciphertext_opaque',
      run: async () => {
        if (encrypted === undefined) {
          return { ok: false, detail: 'no encrypted event to inspect' }
        }
        // The discriminating half of the round trip: a "cipher" that
        // returned its input would satisfy every assertion above.
        const wholePayload = utf8Encode(JSON.stringify(PROBE_PAYLOAD))
        const marker = utf8Encode(PROBE_PAYLOAD.body)
        const leaks =
          containsBytes(encrypted.ciphertext, wholePayload) ||
          containsBytes(encrypted.ciphertext, marker)
        return {
          ok: !leaks,
          detail: leaks
            ? 'the plaintext is present in the ciphertext'
            : `neither the payload nor its marker appears in ${encrypted.ciphertext.length} ciphertext bytes`,
        }
      },
    },
  ]

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
      checks.push({ name: step.name, ok: false, detail: describeFailure(binding, e) })
      stopped = true
    }
  }

  return checks
}
