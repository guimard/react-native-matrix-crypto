# Signal delivery latency on a release build (spec §5.1, B2)

*What produced `SIGNAL_WAIT_MS`, what the before-and-after pair showed, and what is still
unexplained.*

`docs/superpowers/specs/2026-08-28-m3-design.md` §5.1 item B2 asked whether `observer.rs`'s
emission mechanism was what a release build's signal delivery was paying seconds for. §8
required the answer as a before-and-after pair rather than an after alone, and required
that a measurement which does not move say **what else the latency is**.

This file is the measurement. It exists in the tree because the first attempt left its
harness, its arm swapping and its raw samples in a scratch directory, so re-deriving the
budget meant rebuilding all three — which is most of the cost of measuring.
`scripts/measure-signal-latency.sh` is the harness; §5 below is every sample it produced.

---

## 1. The threat this run was built to exclude

An A/B is worth nothing if both arms were the same binary, and this repository is unusually
good at producing that mistake silently:

- `packages/react-native-matrix-crypto/android/CMakeLists.txt` imports the Rust library as
  a **prebuilt** from `android/src/main/jniLibs/`, which `.gitignore` ignores.
- Gradle has **no dependency edge** back to the Rust crate. `:app:assembleRelease`
  repackages whatever `.so` is sitting in `jniLibs/`, however stale.
- So swapping arms means remembering to re-run `ubrn build android` in between. Forgetting
  it produces two APKs that are byte-identical in the only part under test — and two
  statistically indistinguishable distributions, which is what the first run of this
  measurement reported.

That first run could not rule it out from its own output. `coreVersion`, the only build
identifier crossing the bridge, was the crate version: identical on both arms. The
exclusion rested on the operator having run the right commands in the right order, which
is the shape §3.2 rejects everywhere else here — a check that reports success without
having examined its target.

**The fix is in the artifact rather than in the procedure.** `observer::EMIT_BUILD` is a
compile-time FNV-1a hash of the source text of `observer.rs` and `runtime.rs` — the two
files that decide how a signal is delivered — read with `include_str!`, so it is derived
from what the compiler consumed rather than from a version string somebody maintains.
`probe` appends it to `core_version` as semver build metadata; `ProbeHarness.tsx` prints it
as `PROBE_EMIT_BUILD`. Every probe log now says which emission path produced it, including
logs from runs nobody planned as an experiment.

`scripts/measure-signal-latency.sh` refuses to produce a measurement whose arms cannot be
told apart, twice over: it compares the two APKs' `libmatrix_crypto_ffi.so` before it
launches anything, and it aborts if two arms ever report the same `PROBE_EMIT_BUILD`.

For the record, the first run's two APKs were checked afterwards and *did* differ in
`libmatrix_crypto_ffi.so` while carrying an identical JavaScript bundle, so the mistake had
not in fact been made. That check was possible only because those two files happened still
to exist on the machine that built them; it is not something a reader of the repository
could have done, then or now, which is the whole finding. An exclusion that depends on an
artifact nobody else has is not an exclusion.

---

## 2. How to re-run it

The two arms differ in exactly one statement, in `observer.rs`'s `emit`:

```rust
// after  (shipped)
crate::runtime::spawn_blocking_detached(move || observer.on_signal(signal));
// before (M2's emission, one OS thread per signal)
std::thread::spawn(move || observer.on_signal(signal));
```

For each arm, from the repository root, with an emulator or device attached:

```sh
# 1. the Rust slice for the device's ABI -- NOT --and-generate, see ci.yml
(cd packages/react-native-matrix-crypto && \
   yarn exec ubrn -- build android --config ../../ubrn.config.yaml \
     --targets aarch64-linux-android --release)
yarn gate:stubs
# 2. a release APK carrying it
(cd packages/example-app/android && \
   ./gradlew :app:assembleRelease -PreactNativeArchitectures=arm64-v8a --no-daemon)
cp packages/example-app/android/app/build/outputs/apk/release/app-release.apk <arm>.apk
```

Then, once per load condition:

```sh
scripts/measure-signal-latency.sh before.apk after.apk 6 idle.tsv none
scripts/measure-signal-latency.sh before.apk after.apk 5 cpu.tsv  cpu
scripts/measure-signal-latency.sh before.apk after.apk 9 io.tsv   io
```

The arms alternate launch by launch inside each run, so drift in emulator or host state
falls on both equally. A block of A followed by a block of B measures the machine's
afternoon as much as the code.

`none`, `cpu` and `io` are the host's state, not the device's. `cpu` runs one busy loop per
core; `io` runs four write/read loops over bounded files. Both exist because the
observation this budget absorbs was taken while this repository was being built, which
saturates CPU, disk and page cache at once — and a run on an idle host cannot speak to that
tail at all.

---

## 3. What ran

| | |
|---|---|
| Date | 2026-08-29 |
| Device | `emulator-5554`, `sdk_gphone64_arm64`, API 35, `arm64-v8a` |
| Build | release APK, Hermes bytecode bundled (not Metro) |
| Host | Apple Silicon macOS, the same machine that produced the 2026-08-28 numbers |
| Channel | no verification traffic, per §7 Q8 |
| `before` arm | `EMIT_BUILD = 8e8c3246`; `libmatrix_crypto_ffi.so` sha256 `135db8d589ce3f34…` |
| `after` arm | `EMIT_BUILD = 9c223b45`; `libmatrix_crypto_ffi.so` sha256 `c36319c83f24b4af…` |
| Both arms | identical `assets/index.android.bundle` (`b44d6046b5ef4293…`) |

The last row matters as much as the two above it: the arms differ in the Rust library and
in nothing else, so a difference in the numbers could only have come from emission.

The `after` arm's `EMIT_BUILD` is checkable rather than reported: it is what the committed
`observer.rs` and `runtime.rs` hash to, so anyone can recompute it from this commit and get
`9c223b45`. The `before` arm is that same tree with `emit`'s one statement replaced, as in
§2, which is why its value differs.

Every launch reported `PROBE_SUMMARY 12/12`, and every launch's `PROBE_EMIT_BUILD` matched
the arm it was launched from.

---

## 4. Results

| arm | host load | n | min | median | p90 | max |
|---|---|---|---|---|---|---|
| `before` | idle | 6 | 0 | 1 | 2 | 3 |
| `before` | CPU-saturated | 5 | 2 | 5 | 22.6 | 33 |
| `before` | disk-saturated | 9 | 1 | 2 | 25 | 37 |
| **`before`** | **all** | **20** | **0** | **2** | **23.1** | **37** |
| `after` | idle | 6 | 1 | 4.5 | 14 | 16 |
| `after` | CPU-saturated | 5 | 7 | 20 | 45.6 | 56 |
| `after` | disk-saturated | 9 | 1 | 5 | 29.4 | 59 |
| **`after`** | **all** | **20** | **1** | **9.5** | **32.6** | **59** |

**What this design can resolve, and what it cannot.** `Date.now()` has millisecond
granularity and there are 20 launches per arm, so a difference of one or two milliseconds is
below what this can call, and nothing below rests on one. What it can resolve is a change of
*scale* -- the seconds B2 was opened for -- and there is none: every launch on both arms is
milliseconds, the worst anywhere in the run being 59 ms. It can also resolve a difference
between the arms that is consistent across host conditions, and there is one of those; the
medians are 2 ms before and 9.5 ms after.

**Nothing was lost.** All 40 launches delivered their callback and reported
`PROBE_SUMMARY 12/12`. That matters more than the medians do: see section 5.

**The race is real, and is why the bounded wait exists.** The callback landed after the
promise resolved in 20 of the 40 launches. That is the race `interop/suite.ts`'s `waitUntil`
absorbs, and its magnitude here is milliseconds.

**The two arms are not indistinguishable, and the slower one is the new one.** The `after` arm's
median is 9.5 ms against the `before` arm's 2 ms, and its median is the higher of the two in
every host condition separately -- idle 4.5 ms against 1 ms; CPU-saturated 20 ms against 5 ms;
disk-saturated 5 ms against 2 ms. The tails overlap (p90 32.6 ms against 23.1 ms, worst 59 ms
against 37 ms), so the separation is in the body of the distribution rather than in the tail.

There is a mechanism, and it is documented at `observer::emit` rather than guessed here: what
this instrument times is the *first* signal of a cold process, and on that path the first `emit`
is what builds this library's whole tokio runtime -- two workers, a reactor and a timer -- and
then a blocking-pool thread, where `std::thread::spawn` built one bare thread and nothing else.
That is a one-off cost per process, not a per-signal one, and it is milliseconds. It does not
threaten `SIGNAL_WAIT_MS` and it does not change the trade this item made. It does mean "the
measurement did not move" is the wrong summary: it moved, in the direction this item did not
predict.

---

## 5. What this did not settle

**The 1-in-8 failure at a 2000 ms budget remains unexplained.** The reasoning lives in the
spec's §5.1 B2 note and at `SIGNAL_WAIT_MS`, rather than being repeated here; the short of
it is that the original observation used a pass/fail check with no instrument, so it cannot
tell a late callback from a lost one, and the 8-of-8 pass at 15000 ms that was read as
"late, not lost" has a 34% chance of occurring by luck at a 1-in-8 loss rate. This run
refutes a *persistent* loss at that rate. It does not explain the original observation.

What it does remove is a candidate. The `before` arm is the thread-per-signal emission the
seconds were attributed to; it ran under three host conditions including deliberate
saturation, and it produced milliseconds. Emission is not what the fifteen seconds were
paying for.

`SIGNAL_WAIT_MS` is 10000 rather than a number derived from the distribution above,
because the distribution above is precisely the one that excludes the phenomenon the budget
exists to absorb.

---

## 6. Every sample

`label`, `round`, `host load`, `PROBE_SIGNAL_MS`, `PROBE_PROMISE_MS`, `PROBE_EMIT_BUILD`,
`PROBE_SUMMARY`.

```
before	1	none	1	1	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	1	none	1	1	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	2	none	0	0	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	2	none	16	3	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	3	none	3	1	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	3	none	1	1	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	4	none	1	1	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	4	none	2	2	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	5	none	1	1	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	5	none	7	0	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	6	none	1	1	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	6	none	12	3	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	1	cpu	7	6	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	1	cpu	7	1	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	2	cpu	3	2	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	2	cpu	15	1	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	3	cpu	2	2	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	3	cpu	20	1	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	4	cpu	5	5	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	4	cpu	56	32	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	5	cpu	33	4	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	5	cpu	30	21	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	1	io	22	22	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	1	io	15	2	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	2	io	3	3	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	2	io	1	1	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	3	io	2	2	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	3	io	1	1	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	4	io	1	1	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	4	io	59	27	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	5	io	2	1	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	5	io	19	1	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	6	io	37	1	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	6	io	2	2	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	7	io	1	1	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	7	io	22	1	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	8	io	1	0	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	8	io	4	1	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
before	9	io	1	1	0.1.0+emit.8e8c3246	PROBE_SUMMARY 12/12
after	9	io	5	5	0.1.0+emit.9c223b45	PROBE_SUMMARY 12/12
```
