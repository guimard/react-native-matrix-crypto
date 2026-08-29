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
`scripts/measure-signal-latency.sh` is the harness; §8 below is every sample it produced.

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

**Both refusals have been watched happening, and the second one did not work when it was
first written.** `launch_once` wrote its row to stdout and *also* returned the build id on
stdout, so the caller's `$(...)` captured both; the comparison read a string beginning with
the arm's label, which is forced to differ, and was therefore false in every run including
the one it exists to reject. Three tracked files said it worked. That is the same shape as
the finding this whole mechanism was built to close -- a check reporting success without
having examined its target -- one level further in. It now returns through a variable, and
section 4 below records each guard being made to face its case.

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

The `after` arm's `EMIT_BUILD` is checkable rather than reported: it is what
`observer.rs` and `runtime.rs` **as of `3e07bbb`** hash to. Recompute it there and you get
`9c223b45`; the `before` arm is that same tree with `emit`'s one statement replaced, as in
§2, which is why its value differs.

The commit matters, and naming one is not a hedge -- it is the mechanism working as
designed. The fingerprint covers those two files' source text, comments included, so the
doc corrections made after this measurement changed it: at the tip of this branch the same
computation gives `1920fc10`. A fingerprint that survived an edit to the file it fingerprints
would be no use for telling two builds apart. What a reader can check is the pair of claims
above: `3e07bbb` gives `9c223b45`, and `3e07bbb` plus the documented one-statement swap gives
`8e8c3246`. Those are the two values every launch below reported.

Every launch reported `PROBE_SUMMARY 12/12`, and every launch's `PROBE_EMIT_BUILD` matched
the arm it was launched from.

---

## 4. The guards, watched refusing

A guard nobody has seen reject anything is decoration, and one of these was exactly that for
a whole review cycle. Each is recorded here facing the case it exists to reject, and the real
pair being accepted. `adb` is stubbed for these runs (the stub answers only the calls this
harness makes, and lets each arm's reported `PROBE_EMIT_BUILD` be chosen) because the third
case cannot otherwise be manufactured: two builds differing outside the fingerprinted files
come out byte-identical, this toolchain being deterministic. The guard under test is shell
logic, and this tests exactly that.

| case | what it is | outcome |
|---|---|---|
| an APK carrying no `libmatrix_crypto_ffi.so` | wrong ABI, or a stub build | refused, exit 1 |
| two identical APKs | the arm swap that skipped `ubrn build android` | refused, exit 1 |
| different `.so`, same reported build | what the on-disk digest cannot see | refused, exit 1 |
| different `.so`, different builds | the real pair | **accepted**, 4 rows written |

Verbatim, with paths shortened:

```
FAIL: 'nolib.apk' carries no lib/arm64-v8a/libmatrix_crypto_ffi.so.
      This device reports ABI 'arm64-v8a'; an APK built for another one, or a stub
      build that linked nothing, looks like this.

FAIL: both APKs carry the same lib/arm64-v8a/libmatrix_crypto_ffi.so (bb9b060783e52395).
      There is no A/B here: the arms would run identical Rust.

arms differ in lib/arm64-v8a/libmatrix_crypto_ffi.so: before=21f37fab... after=bb9b0607...
FAIL: round 1: both arms reported the same emission build (0.1.0+emit.cafef00d).
      The two APKs differ on disk but the running processes do not
      distinguish themselves, so nothing measured here is an A/B.
```

Facing them also turned up a fourth defect that no amount of reading would have: the `EXIT`
trap called `stop_load` seventy lines before that function was defined, so every one of the
refusals above exited 127 with `stop_load: command not found` instead of the 1 its diagnostic
had just earned. Fixed, and the table above is from the re-run.

**To repeat this.** Cases one and two need only real APKs. Case three needs the stub: a
script named `adb`, first on `PATH`, that answers `wait-for-device`, `uninstall`, `install`,
`logcat -c` and `am start`/`am force-stop` with exit 0; answers
`shell getprop ro.product.cpu.abi` with the ABI the APKs carry; and answers `logcat -d` with
a `PROBE_EMIT_BUILD`, a `PROBE_SIGNAL_MS`, a `PROBE_SIGNAL2_MS` and a `PROBE_SUMMARY 12/12`
line, choosing the build id from the APK basename it last saw installed. Point both arms at
the same id and the run must be refused; point them at different ids and it must be
accepted.

**Named limitation:** that is a manual procedure, not a test anything runs. Nothing in CI
would notice this guard breaking again, and it broke silently once. A self-test driving the
harness against the stub would close it and is not in this branch.

---

## 5. Results

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
`PROBE_SUMMARY 12/12`. That matters more than the medians do: see section 7.

**The race is real, and is why the bounded wait exists.** The callback landed after the
promise resolved in 20 of the 40 launches. That is the race `interop/suite.ts`'s `waitUntil`
absorbs, and its magnitude here is milliseconds.

**The two arms are not indistinguishable, and the slower one is the new one.** The `after` arm's
median is 9.5 ms against the `before` arm's 2 ms, and its median is the higher of the two in
every host condition separately -- idle 4.5 ms against 1 ms; CPU-saturated 20 ms against 5 ms;
disk-saturated 5 ms against 2 ms. The tails overlap (p90 32.6 ms against 23.1 ms, worst 59 ms
against 37 ms), so the separation is in the body of the distribution rather than in the tail.

**How strongly: one star, and the first draft of this file said nothing at all about that.**
Of the 20 interleaved pairs, 12 favour the new path being slower, 6 run the other way and 2
tie. A Wilcoxon signed-rank test over the paired differences gives p ~ 0.04; a paired
sign-flip permutation on the median gives p ~ 0.03; the same permutation on the *mean* gives
p ~ 0.08, the mean being dominated by two outlying pairs at -35 ms and +58 ms. So: real, and
not more than real, from n = 20 per arm at millisecond clock granularity.

**The cause is not established, and section 6 is what is known about it.** The first draft
of this file attributed the gap confidently to the first `emit` building the tokio runtime.
That construction does happen on this path and it is one-off per process -- `observer::emit`
says why -- but it does not account for the shape of these numbers, and asserting it was the
same habit as the round before. What it does mean, either way, is that "the measurement did
not move" is the wrong summary: it moved, in the direction this item did not predict.

---

## 6. The second-signal experiment

The question the 40 launches above cannot answer: is the new path's excess a cost paid once
per process, or one paid on every signal? Every one of those samples is the first signal of
its own cold process -- `launch_once` uninstalls and reinstalls for each launch and the suite
issues exactly one observed call -- so a once-per-process cost lands in every sample and a
shifted median is what either hypothesis predicts.

One extra `emit` separates them. `ProbeHarness.tsx` now times a second observed signal after
both suites have run and reports it as `PROBE_SIGNAL2_MS`; the harness records it alongside
the first. Same two APKs, same fingerprints (`8e8c3246` and `9c223b45`), same interleaving:
22 launches, 11 per arm, 12 idle and 10 CPU-saturated. Every launch reported
`PROBE_SUMMARY 12/12` and printed both lines.

| arm | host load | signal | n | min | median | max |
|---|---|---|---|---|---|---|
| `before` | idle | first | 6 | 0 | 1 | 39 |
| `before` | idle | second | 6 | 0 | 2.5 | 17 |
| `before` | CPU-saturated | first | 5 | 2 | 15 | 73 |
| `before` | CPU-saturated | second | 5 | 0 | 1 | 1 |
| `after` | idle | first | 6 | 1 | 3 | 5 |
| `after` | idle | second | 6 | 0 | 1 | 5 |
| `after` | CPU-saturated | first | 5 | 5 | 24 | 113 |
| `after` | CPU-saturated | second | 5 | 0 | 1 | 1 |

Paired, arm against arm within each round:

| host load | first-signal gap (median) | second-signal gap (median) |
|---|---|---|
| idle | +2 ms | -2 ms |
| CPU-saturated | **+22 ms** | **0 ms** |
| both | +3 ms | 0 ms |

**The excess is confined to the first signal of a process.** Under the CPU saturation where
the first-signal gap is at its widest, the second signal is a median of 1 ms on both arms,
with a maximum of 1 ms on both -- the two emission paths are not distinguishable there at
all. No product pays this per signal.

**It is also not fixed work**, which is the part the first draft got wrong. A constant added
cost `c` would put the new arm's floor at least `c` above the old one's; the floors are 1 ms
and 0 ms across the 40 launches of section 4, and 1 ms and 0 ms again here. Four of those 40
`after` launches delivered end to end in 1 ms. A fixed 7.5 ms cannot hide inside them. What
the gap does instead is grow with contention, from +2 ms idle to +22 ms saturated, which is
what exposure to scheduling looks like and not what a constant amount of work looks like.

**What is left open**: which first-use step dominates. Building the runtime, creating the
first blocking-pool thread, and simply having more handoffs to be descheduled between are all
first-use and all consistent with these numbers, and nothing here separates them. Separating
them needs an instrument inside the core rather than at the JavaScript boundary -- timing
`runtime()` and the pool's first task independently -- which is a different experiment from
this one. It is recorded as open rather than guessed at a third time.

---

## 7. What this did not settle

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

## 8. Every sample

`label`, `round`, `host load`, `PROBE_SIGNAL_MS`, `PROBE_PROMISE_MS`, `PROBE_EMIT_BUILD`,
`PROBE_SUMMARY`.

Seven fields, not the eight the harness writes today: `PROBE_SIGNAL2_MS` became a column when
section 6 was run, which was after these launches. A row from a current run carries it
between `PROBE_SIGNAL_MS` and `PROBE_PROMISE_MS`.

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
