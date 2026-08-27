/**
 * Example app for react-native-matrix-crypto.
 *
 * Exercises the shipped JSI Turbo Module end to end by running the shared
 * interop suite (see src/ProbeHarness.tsx) against the real native binding.
 * Deliberately generic: this app has no product-specific configuration.
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
function App() {
  const isDarkMode = useColorScheme() === 'dark';

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle={isDarkMode ? 'light-content' : 'dark-content'} />
      <ScrollView contentInsetAdjustmentBehavior="automatic" style={styles.container}>
        <Text style={styles.heading}>react-native-matrix-crypto</Text>
        <GuidedFlow />
        <Text style={styles.heading}>Diagnostics</Text>
        <Text style={styles.subheading}>
          The same interop suite the flow above exercises by hand, run automatically on every app start and logged
          for CI.
        </Text>
        <ProbeHarness />
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
