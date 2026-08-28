/**
 * The one crypto identity this app uses, shared by both screens.
 *
 * The library holds **one machine per process** (design doc section 3), so
 * two screens cannot each create their own: the second would be turned away
 * with `already_initialised` if its configuration differed. Both
 * `GuidedFlow` and `ProbeHarness` therefore call `createCryptoMachine` with
 * the value below and nothing else, which the library documents as
 * idempotent for a matching configuration.
 *
 * These identifiers are also an assertion, not just an input:
 * `getDeviceIdentityKeys` refuses a caller who disagrees with the live
 * machine about who this device is, so a screen using a different user or
 * device id would be rejected rather than handed someone else's keys.
 */

/**
 * Deliberately fictional Matrix identifiers, `example.org`-shaped, so they
 * read as illustrative rather than as configuration for any real server.
 */
export const DEMO_USER_ID = '@alice:example.org'
export const DEMO_DEVICE_ID = 'DEVICE1'
export const DEMO_SCOPE = '!crypto-demo:example.org'

/**
 * Not a secret, and it must not be read as an example of how to choose one:
 * a real product supplies a passphrase it derived or stored itself. It is a
 * literal here because this app has no user, no keychain and no secret to
 * protect -- every store it creates is thrown away with the app.
 */
const DEMO_PASSPHRASE = 'example-app-probe-passphrase'

/**
 * One store directory per launch.
 *
 * A fixed path would work, but it would make each run depend on what the
 * previous run left behind -- and the probe's second step asserts what a
 * *fresh* device offers to publish. A launch-scoped directory makes every
 * run the documented cold-start path instead of a path that happens to
 * still work on a machine that has already published its keys once. The
 * cost is that stores accumulate under the app's own directory until the
 * app is uninstalled, which is acceptable for an example app and would not
 * be for a product.
 */
const LAUNCH_ID = String(Date.now())

export interface DemoMachineConfig {
  userId: string
  deviceId: string
  storePath: string
  storePassphrase: string
}

/**
 * `storeDir` comes from the host platform, through this app's own native
 * code -- the library deliberately chooses no location, and React Native
 * has no built-in path API. See `App.tsx`.
 *
 * An empty `storeDir` produces an empty `storePath`, which the crypto suite
 * reports as a failing step rather than silently writing somewhere nobody
 * agreed to.
 */
export function demoMachineConfig(storeDir: string): DemoMachineConfig {
  return {
    userId: DEMO_USER_ID,
    deviceId: DEMO_DEVICE_ID,
    storePath: storeDir === '' ? '' : `${storeDir}/crypto-probe/${LAUNCH_ID}`,
    storePassphrase: DEMO_PASSPHRASE,
  }
}
