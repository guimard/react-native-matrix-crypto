# Tests

```sh
yarn --cwd packages/example-app test        # vitest, on this machine, no device
yarn --cwd packages/example-app typecheck
```

Vitest, the same runner `packages/react-native-matrix-crypto` uses, wired into
the `gates` job in `.github/workflows/ci.yml`. It runs the guided walkthrough's
real step functions out of `src/flowRunners.ts`, which is why those functions
live in a module of their own with no `react` or `react-native` import in it.
`src/GuidedFlow.tsx` renders what they report and re-implements none of them.

## What it covers

* **Step 3 reads a settled value.** Step 2 waits, bounded, for its own observer
  callback before it reports, so step 3 can be a plain read. The test drives a
  fake binding whose callback is delivered strictly after the call resolves,
  and asserts that precondition before asserting the result, so a green step 3
  cannot come from a callback that had already arrived.
* **A card that claims a call throws.** Step 8 says a named library function
  rejects with `not_implemented`. `src/cardClaims.test.ts` mocks nothing, calls
  that function through the published entry point, and fails if it stops
  rejecting. It also sweeps the whole public surface and pins the set of
  functions still refused in JavaScript, so implementing any one of them turns
  the build red rather than the card.
* **The signing-identity gate refusing.** Step 6 asks the machine what it knows
  about the account's signing identity and then asks it to publish one, which
  it refuses because nothing has asked a homeserver yet. The native call is
  faked at the same seam step 4's typed error is, so the real facade decides
  the kind. Both halves are tested: the card reports `ok` on the refusal, and
  reports `unexpected` when the bootstrap is served instead. The second is the
  one that matters, because a library that minted an identity there would
  replace whatever the account already had.
* **Cards name functions that exist.** Every `react-native-matrix-crypto`
  import in a card's code snippet is checked against the library's exports.
* **Step ordering, step 2's round trip, step 4's typed error**, and that each
  run starts from an empty signal log rather than accumulating.

## What it cannot reach, and why

**No JSI turbo module.** The published entry point installs a Rust crate onto a
JSI host object and then runs a checksum handshake with it. There is no such
object in Node and no React Native runtime to ask for one, so `vitest.config.mts`
replaces exactly one module in the graph, the generated bootstrap, and leaves
every other line of the library real. If that stub ever stops applying, every
test in the package fails at import; there is no path where it quietly stops
working and the suite still reports success.

Consequently **nothing in this suite establishes that the bridge works**. In
particular these remain exercised only by a human holding a phone, or by
`scripts/run-probe-on-emulator.sh` and `level-two/run_level_two.py`:

* **Steps 1, 5 and 7 of the walkthrough.** Subscribing installs the native
  observer; the identity step opens a real crypto store and reads real keys;
  and step 7 creates a real group session, encrypts one payload and decrypts
  the result to read what the library says about its sender. All three are
  asserted to *fail* in `src/flowRunners.test.ts`, deliberately, so the hole is
  named in the suite rather than hidden by a skip.

  Step 7 is the one that must stay that way. Faking the native encrypt and
  decrypt would make this suite report a `senderVerification` it had written
  itself, and that value is the one the library's own documentation is most
  emphatic must never be manufactured. What the card reports is proven where a
  real event exists: on a device, and against a real homeserver and a
  third-party client in
  `rust/matrix-crypto-core/tests/level_two_identity.rs`.
* **Everything the fake binding stands in for**: that Rust actually reverses
  the bytes, reports its own crate version, rejects empty input, and invokes
  the observer callback back across the boundary at all. The tests fix what
  each step does with those answers, not that the answers are real.
* **`ProbeHarness`, `LevelTwoHarness`, `FoldWatch` and `App.tsx`**, which are
  React components and are not covered here.
* **Signal timing.** `PROBE_SIGNAL_MS` and `PROBE_SIGNAL_NTH` are measurements
  of a real device under a real race. A host machine cannot produce them.
* **That a camera reads the code this library renders.** See below: it needs a
  person, a second client and a lens, and no test can stand in for any of the
  three.

# The camera proof

Verification by scanning a code is proven by tests in three places already:
the core drives all three modes against a bare upstream machine, and
`rust/matrix-crypto-core/tests/level_two_scanned.rs` drives them against a
mautrix-go counterparty over a real homeserver. **Not one of them points a
camera at a screen.** That claim matters more than any of the others for a
product whose users will scan with whatever client they already have, and it
is the one claim a process cannot make about itself.

```sh
# Build a release APK first; the run needs one and will say so if it has none.
(cd packages/example-app/android && ./gradlew :app:assembleRelease -PreactNativeArchitectures=arm64-v8a)

python3 packages/example-app/level-two/run_camera_proof.py
```

That program starts a throwaway homeserver in a container, creates one
account, logs the phone in, hands the app a run plan on the host's loopback,
installs and launches the app, and then **stops and prints what to do**. It
asserts nothing, on purpose: what it is arranging is a person looking at two
screens, and a program that claimed to have checked that would be claiming
something it did not see.

What the person does, in short, with the full version printed by the run
itself:

1. Sign in to Element Web or Element Desktop on this machine, at the
   homeserver URL, account and password the program prints. It is one account
   on a container that is destroyed on exit.
2. In Element, open Settings, Sessions, find the phone's session and choose to
   verify it. **On the phone** the headline changes to *Point the other
   client's camera at this code* and a black-and-white square appears.
3. In Element, choose *Scan QR code* and fill the viewfinder with the phone's
   screen. **On the phone** the headline becomes *The other device says it
   scanned this code* and a green button appears. Nothing is verified yet:
   this is the one moment the mode asks a person anything.
4. Press the green button. **On the phone** the headline becomes *Verified*
   and the square disappears; **in Element** the session is marked verified.

**If it does not scan, that is a finding rather than a nuisance**, and which
of two it was is what matters. A camera that never locks on is a rendering
problem: the symbol is too small, the screen too dim or too reflective. A
camera that locks on and is then rejected is the serious one, because it would
mean the bytes drawn are not the bytes meant.

The screen itself is `src/ScannedCodeWalkthrough.tsx`, and everything it
decides is in `src/scannedCodeRunner.ts`, which imports the published
TypeScript surface and no component. `src/scannedCodeRunner.test.ts` runs that
module's real functions on this machine against a faked native binding, so
the arc, the grid's polarity, the confirmation prompt and the refusal path are
all checked without a device. **What crosses on a device and cannot cross
here is a real payload byte**: every other TypeScript test of this surface
talks to a mock, and this walkthrough is the first thing in `packages/` that
carries the library's own bytes end to end.

This is a new [**React Native**](https://reactnative.dev) project, bootstrapped using [`@react-native-community/cli`](https://github.com/react-native-community/cli).

# Getting Started

> **Note**: Make sure you have completed the [Set Up Your Environment](https://reactnative.dev/docs/set-up-your-environment) guide before proceeding.

## Step 1: Start Metro

First, you will need to run **Metro**, the JavaScript build tool for React Native.

To start the Metro dev server, run the following command from the root of your React Native project:

```sh
# Using npm
npm start

# OR using Yarn
yarn start
```

## Step 2: Build and run your app

With Metro running, open a new terminal window/pane from the root of your React Native project, and use one of the following commands to build and run your Android or iOS app:

### Android

```sh
# Using npm
npm run android

# OR using Yarn
yarn android
```

### iOS

For iOS, remember to install CocoaPods dependencies (this only needs to be run on first clone or after updating native deps).

The first time you create a new project, run the Ruby bundler to install CocoaPods itself:

```sh
bundle install
```

Then, and every time you update your native dependencies, run:

```sh
bundle exec pod install
```

For more information, please visit [CocoaPods Getting Started guide](https://guides.cocoapods.org/using/getting-started.html).

```sh
# Using npm
npm run ios

# OR using Yarn
yarn ios
```

If everything is set up correctly, you should see your new app running in the Android Emulator, iOS Simulator, or your connected device.

This is one way to run your app — you can also build it directly from Android Studio or Xcode.

## Step 3: Modify your app

Now that you have successfully run the app, let's make changes!

Open `App.tsx` in your text editor of choice and make some changes. When you save, your app will automatically update and reflect these changes — this is powered by [Fast Refresh](https://reactnative.dev/docs/fast-refresh).

When you want to forcefully reload, for example to reset the state of your app, you can perform a full reload:

- **Android**: Press the <kbd>R</kbd> key twice or select **"Reload"** from the **Dev Menu**, accessed via <kbd>Ctrl</kbd> + <kbd>M</kbd> (Windows/Linux) or <kbd>Cmd ⌘</kbd> + <kbd>M</kbd> (macOS).
- **iOS**: Press <kbd>R</kbd> in iOS Simulator.

## Congratulations! :tada:

You've successfully run and modified your React Native App. :partying_face:

### Now what?

- If you want to add this new React Native code to an existing application, check out the [Integration guide](https://reactnative.dev/docs/integration-with-existing-apps).
- If you're curious to learn more about React Native, check out the [docs](https://reactnative.dev/docs/getting-started).

# Troubleshooting

If you're having issues getting the above steps to work, see the [Troubleshooting](https://reactnative.dev/docs/troubleshooting) page.

# Learn More

To learn more about React Native, take a look at the following resources:

- [React Native Website](https://reactnative.dev) - learn more about React Native.
- [Getting Started](https://reactnative.dev/docs/environment-setup) - an **overview** of React Native and how setup your environment.
- [Learn the Basics](https://reactnative.dev/docs/getting-started) - a **guided tour** of the React Native **basics**.
- [Blog](https://reactnative.dev/blog) - read the latest official React Native **Blog** posts.
- [`@facebook/react-native`](https://github.com/facebook/react-native) - the Open Source; GitHub **repository** for React Native.
