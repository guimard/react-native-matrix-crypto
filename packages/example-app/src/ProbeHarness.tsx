import React, { useEffect, useState } from 'react'
import { Text, View } from 'react-native'
import { isCryptoError, onCryptoSignal, runProbe } from 'react-native-matrix-crypto'
import {
  runInteropSuite,
  type BridgeBinding,
  type InteropCheck,
} from 'react-native-matrix-crypto/interop/suite'

/**
 * Adapts the shipped JSI binding to the shared contract from Task 9b.
 * The checks themselves live in the suite, so the device run and the Node
 * run cannot drift apart.
 */
function jsiBinding(): BridgeBinding {
  return {
    runProbe,
    onCryptoSignal: (cb) => onCryptoSignal((s) => cb({ kind: s.kind })),
    isCryptoError,
    errorKind: (e) => (isCryptoError(e) ? e.kind : undefined),
  }
}

export function ProbeHarness() {
  const [checks, setChecks] = useState<InteropCheck[]>([])

  useEffect(() => {
    runInteropSuite(jsiBinding()).then((results) => {
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
