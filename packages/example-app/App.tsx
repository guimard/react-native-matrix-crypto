/**
 * Example app for react-native-matrix-crypto.
 *
 * Exercises the shipped JSI Turbo Module end to end by running the shared
 * interop suites (see src/ProbeHarness.tsx) against the real native binding.
 * Deliberately generic: this app has no product-specific configuration.
 *
 * `storeDir` is the one thing this app cannot get from JavaScript.
 * `createCryptoMachine` needs a directory the process may write to, the
 * library deliberately chooses none (a crypto library that picks its own
 * on-disk location writes somewhere the product did not agree to), and
 * React Native has no built-in path API. So this app's own native code
 * supplies it as an initial property of the root component: `filesDir` on
 * Android (MainActivity.kt), the app container's Documents directory on
 * iOS (AppDelegate.swift). No dependency was added to get it, and nothing
 * was added to the library.
 *
 * It is typed optional and defaults to the empty string rather than being
 * assumed present: a host that supplies nothing must make the probe report
 * a failing step, not crash before it can report anything at all.
 *
 * @format
 */

import React from 'react';
import { SafeAreaView, ScrollView, StatusBar, StyleSheet, Text, useColorScheme } from 'react-native';
import { GuidedFlow } from './src/GuidedFlow';
import { ProbeHarness } from './src/ProbeHarness';

// Both GuidedFlow and ProbeHarness are rendered unconditionally, in the same
// tree, every time this component mounts -- neither lives behind a tab or
// any other interaction. ProbeHarness's mount effect is what CI scrapes
// (PROBE_CHECK / PROBE_SUMMARY); if it were only reachable by tapping into a
// secondary view, an app that never runs it would still look like a pass.
function App({ storeDir = '' }: { storeDir?: string }) {
  const isDarkMode = useColorScheme() === 'dark';

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle={isDarkMode ? 'light-content' : 'dark-content'} />
      <ScrollView contentInsetAdjustmentBehavior="automatic" style={styles.container}>
        <Text style={styles.heading}>react-native-matrix-crypto</Text>
        <GuidedFlow storeDir={storeDir} />
        <Text style={styles.heading}>Diagnostics</Text>
        <Text style={styles.subheading}>
          Two interop suites, run automatically on every app start and logged for CI: the probe suite the flow
          above exercises by hand, and a real encryption round trip -- create a machine, publish its keys, share a
          scope key, encrypt, decrypt -- driven entirely through the public API.
        </Text>
        <ProbeHarness storeDir={storeDir} />
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  heading: {
    fontSize: 18,
    fontWeight: '600',
    margin: 16,
  },
  subheading: {
    fontSize: 13,
    marginHorizontal: 16,
    marginBottom: 8,
    opacity: 0.7,
  },
});

export default App;
