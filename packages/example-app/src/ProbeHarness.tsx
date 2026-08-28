import React, { useEffect, useState } from 'react'
import { Text, View } from 'react-native'
import {
  asCryptoScopeId,
  createCryptoMachine,
  decryptEvent,
  encryptEvent,
  getDeviceIdentityKeys,
  isCryptoError,
  markRequestSent,
  runProbe,
  shareScopeKey,
  takeOutgoingRequests,
} from 'react-native-matrix-crypto'
import {
  runInteropSuite,
  type BridgeBinding,
  type InteropCheck,
} from 'react-native-matrix-crypto/interop/suite'
import {
  CRYPTO_SUITE_STEPS,
  runCryptoSuite,
  type CryptoBinding,
} from 'react-native-matrix-crypto/interop/crypto-suite'
import { DEMO_DEVICE_ID, DEMO_SCOPE, DEMO_USER_ID, demoMachineConfig } from './cryptoConfig'

/**
 * Adapts the shipped JSI binding to the shared contract from Task 9b.
 * The checks themselves live in the suite, so the device run and the Node
 * run cannot drift apart.
 *
 * `runProbe`'s own signal callback is forwarded directly -- not read via
 * `onCryptoSignal` -- so this harness's 'signal' check only ever sees the
 * signal from its own call, never `GuidedFlow`'s. Both mount as siblings
 * in App.tsx and both call `runProbe`; before this, the shared global
 * channel meant one's probe call showed up in the other's check too.
 */
function jsiBinding(): BridgeBinding {
  return {
    runProbe(input, payload, onSignal) {
      return runProbe(input, payload, onSignal && ((signal) => onSignal(signal.kind)))
    },
    isCryptoError,
    errorKind: (e) => (isCryptoError(e) ? e.kind : undefined),
  }
}

/**
 * The same adaptation for the crypto half of the contract (Task 10). Every
 * member below is the public facade, unwrapped: no test helper, nothing from
 * `./generated`, nothing this library does not ship to a product. The only
 * work done here is branding the scope, which is exactly what a product
 * writes too.
 */
function jsiCryptoBinding(): CryptoBinding {
  return {
    createCryptoMachine,
    takeOutgoingRequests,
    markRequestSent,
    shareScopeKey: (scope, userIds) => shareScopeKey(asCryptoScopeId(scope), userIds),
    encryptEvent: (scope, eventType, payload) =>
      encryptEvent(asCryptoScopeId(scope), eventType, payload),
    decryptEvent: (scope, rawEvent) => decryptEvent(asCryptoScopeId(scope), rawEvent),
    errorKind: (e) => (isCryptoError(e) ? e.kind : undefined),
  }
}

/**
 * Every check this harness is responsible for producing itself, beyond the
 * probe suite's own. Reconciled against what actually came back before
 * anything is printed: a step that could not run must report FAIL, never
 * disappear. A summary counting eleven of twelve steps and calling it
 * 11/11 is the failure this file exists to make impossible.
 *
 * The probe suite's five checks are not listed: it legitimately collapses
 * to a single 'fatal' check when the binding itself is unusable, so there
 * is no fixed set of names to reconcile against for that half.
 */
const HARNESS_OWNED_CHECKS: readonly string[] = [...CRYPTO_SUITE_STEPS, 'real_crypto']

/**
 * The one genuine cryptographic value M1b proved crossed the chain, kept as
 * its own check.
 *
 * It runs *after* the crypto suite, and with the suite's own identifiers,
 * because M2 changed what it reads: `getDeviceIdentityKeys` now reports the
 * live machine's keys rather than minting a throwaway machine per call, and
 * refuses a caller who names a different user or device than the machine
 * holds. Called before `createCryptoMachine`, or with any other identity,
 * it rejects -- which is why this is no longer a check that can stand on
 * its own at the top of the run.
 */
async function realCryptoCheck(): Promise<InteropCheck> {
  try {
    const keys = await getDeviceIdentityKeys(DEMO_USER_ID, DEMO_DEVICE_ID)
    const ok = keys.ed25519.length === 43 && keys.curve25519.length === 43
    return {
      name: 'real_crypto',
      ok,
      detail: ok
        ? 'the live machine reported two well-formed 43-character identity keys'
        : `unexpected key lengths: ${keys.ed25519.length}/${keys.curve25519.length}`,
    }
  } catch (e) {
    const kind = isCryptoError(e) ? e.kind : undefined
    return {
      name: 'real_crypto',
      ok: false,
      detail: kind ? `rejected with kind "${kind}"` : 'failed with a non-typed error',
    }
  }
}

/**
 * The one run this process performs, memoised at module scope.
 *
 * **This run is only meaningful once per process, and that is a property of
 * the machine, not a shortcut.** The crypto machine is process-wide and
 * created exactly once, and a device publishes its one-time keys exactly
 * once: upstream tops them up in response to a `/sync`'s
 * `one_time_keys_counts`, which reaches the machine only through
 * `receiveSyncChanges`, and this probe deliberately fakes no sync. So a
 * second run in the same process finds a machine that has already
 * published, `key_upload_present` fails on a device that is no longer
 * fresh, and every step after it reports "not reached" -- a correct result
 * for a question nobody meant to ask.
 *
 * Observed for real, not theorised: a Metro fast refresh remounted this
 * component and logged `PROBE_SUMMARY 6/12` and `7/12` after a cold start
 * had already logged `12/12`, in the same process. Memoising the run means
 * a remount re-renders the result it already has instead of manufacturing a
 * second, misleading one -- and CI still gets exactly one summary per app
 * launch, which is the only kind of run this probe claims anything about.
 *
 * `storeDir` is captured by the first call for the same reason: the machine
 * it created is process-wide, so a later, different value could not be
 * honoured even if this re-ran.
 */
let probeRun: Promise<InteropCheck[]> | null = null

export function ProbeHarness({ storeDir }: { storeDir: string }) {
  const [checks, setChecks] = useState<InteropCheck[]>([])

  useEffect(() => {
    let cancelled = false

    const run = async () => {
      const results: InteropCheck[] = []
      try {
        results.push(...(await runInteropSuite(jsiBinding())))
        // Task 10: the same chain, carrying real cryptography rather than
        // an echo. The suite reports every one of its steps on every run,
        // including the ones an earlier failure stopped it reaching.
        results.push(
          ...(await runCryptoSuite(jsiCryptoBinding(), {
            machine: demoMachineConfig(storeDir),
            scope: DEMO_SCOPE,
          })),
        )
        results.push(await realCryptoCheck())
      } catch (e) {
        // Neither suite is supposed to be able to reach this: both report
        // failing checks instead of throwing. If one ever does, the run
        // still has to produce a summary -- a harness that throws prints
        // no PROBE_SUMMARY at all, which reads as "CI found nothing" and
        // not as "everything failed".
        results.push({
          name: 'harness',
          ok: false,
          detail: `the harness itself failed with a ${e instanceof Error ? e.constructor.name : typeof e}`,
        })
      }

      for (const name of HARNESS_OWNED_CHECKS) {
        if (!results.some((c) => c.name === name)) {
          results.push({ name, ok: false, detail: 'not reported: the harness failed before this step' })
        }
      }

      // Printed here rather than in the effect, so it happens once per
      // process alongside the run itself: a remount awaits the same promise
      // and must not re-emit lines CI would count twice.
      for (const c of results) {
        // Machine-readable line scraped by CI. The example app is not the
        // bridge, so it may log; the bridge itself never does. Names and
        // outcomes only -- no plaintext, no key material, no passphrase
        // and no identifier reaches this line.
        console.log(`PROBE_CHECK ${c.name} ${c.ok ? 'PASS' : 'FAIL'} ${c.detail}`)
      }
      console.log(`PROBE_SUMMARY ${results.filter((c) => c.ok).length}/${results.length}`)
      return results
    }

    if (probeRun === null) probeRun = run()
    void probeRun.then((results) => {
      // Only the on-screen list is gated on the component still being
      // mounted: the lines CI scrapes were already emitted by the run
      // itself, so an unmount can never swallow them.
      if (!cancelled) setChecks(results)
    })
    return () => {
      cancelled = true
    }
  }, [storeDir])

  return (
    <View>
      {checks.map((c) => (
        <Text key={c.name}>{`${c.name}: ${c.ok ? 'PASS' : 'FAIL'} (${c.detail})`}</Text>
      ))}
    </View>
  )
}
