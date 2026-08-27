import React, { useEffect, useState } from 'react'
import { Text, View } from 'react-native'
import { getDeviceIdentityKeys, isCryptoError, runProbe } from 'react-native-matrix-crypto'
import {
  runInteropSuite,
  type BridgeBinding,
  type InteropCheck,
} from 'react-native-matrix-crypto/interop/suite'

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

export function ProbeHarness() {
  const [checks, setChecks] = useState<InteropCheck[]>([])

  useEffect(() => {
    runInteropSuite(jsiBinding()).then(async (results) => {
      // M1b-specific: proves a genuine cryptographic value crosses the same
      // chain the probe proved in M1a.
      try {
        const keys = await getDeviceIdentityKeys('@a:server1', 'DEVICE1')
        results.push({
          name: 'real_crypto',
          ok: keys.ed25519.length === 43 && keys.curve25519.length === 43,
          detail: `${keys.ed25519.length}/${keys.curve25519.length}`,
        })
      } catch (e) {
        results.push({ name: 'real_crypto', ok: false, detail: String(e) })
      }

      setChecks(results)
      for (const c of results) {
        // Machine-readable line scraped by CI. The example app is not the
        // bridge, so it may log; the bridge itself never does.
        console.log(`PROBE_CHECK ${c.name} ${c.ok ? 'PASS' : 'FAIL'} ${c.detail}`)
      }
      console.log(`PROBE_SUMMARY ${results.filter((c) => c.ok).length}/${results.length}`)
    })
  }, [])

  return (
    <View>
      {checks.map((c) => (
        <Text key={c.name}>{`${c.name}: ${c.ok ? 'PASS' : 'FAIL'} (${c.detail})`}</Text>
      ))}
    </View>
  )
}
