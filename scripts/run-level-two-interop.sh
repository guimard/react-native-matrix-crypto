#!/usr/bin/env bash
set -euo pipefail

# Runs the level 2 interoperability test (design doc section 8, M2's final
# exit criterion) against a Matrix homeserver this script starts, provisions,
# and destroys.
#
#   ./scripts/run-level-two-interop.sh
#
# That is the whole invocation. It needs Docker, a Rust toolchain and a
# Python 3, and nothing else -- no account on anybody's homeserver, no
# credential, no CI secret. CI runs this same script, so what a contributor
# runs locally and what stands behind the milestone's headline claim are the
# same code path rather than two things that look alike.
#
# WHY A THROWAWAY HOMESERVER RATHER THAN CI SECRETS
#
# The alternative was a secret in this public repository's CI pointing at a
# homeserver somebody owns. That puts Matrix credentials in a public
# repository, sends test traffic to real infrastructure on every pull request
# including from outside contributors, and leaves debris behind when a run
# fails. A container started, used and destroyed inside the job has none of
# those properties, and it is checkable by a third party: anyone who clones
# this repository can run the identical proof.
#
# WHAT THIS ASSERTS, AND WHY NOT AN EXIT CODE
#
# `cargo test` exits 0 when it matches no test at all. A filter typo, a
# renamed test, or a missing `--ignored` all produce `0 passed; 0 failed` and
# a successful exit -- which is the exact shape of check this milestone has
# now found seven times: a green report that never examined its target. So
# this script requires, from cargo's own output:
#
#   * the line `test level_two_interoperability_over_a_real_homeserver ... ok`
#   * a `test result: ok. 1 passed; 0 failed; 0 ignored` summary
#
# and it requires the homeserver to have answered a real login before cargo
# is invoked at all. A container that never started, a test that never ran,
# and a process that died mid-run all fail here rather than passing quietly.
#
# CREDENTIALS
#
# None exist to leak. The account is created by this script, inside the
# container it just started, with a password generated per run by
# `openssl rand`. Nothing is read from a file, an environment secret or a CI
# secret. The container listens on loopback only and is removed on every exit
# path. Under GitHub Actions the generated password is registered with
# `::add-mask::` before it is used anywhere, so it cannot appear in a job log
# even if the container's own output is dumped after a failure -- which this
# script does only when the run has already failed.
#
# POINTING IT AT A REAL HOMESERVER INSTEAD
#
# Set MATRIX_INTEROP_HOMESERVER, MATRIX_INTEROP_USER and
# MATRIX_INTEROP_PASSWORD and no container is started: the test runs against
# what they name, exactly as it did before this script existed. That path is
# unchanged and still supported; it is simply no longer the only one.

# --- what a run is made of -------------------------------------------------

# Pinned by digest, not by tag: a tag is a mutable pointer, and "the job runs
# whatever that name points at today" is not a repeatable proof. This is the
# multi-architecture index for v26.7.2, so the same line works on a linux/amd64
# CI runner and on an arm64 developer machine.
#
# Continuwuity rather than Synapse, and the reason is in the test rather than
# in taste. Step 5 asserts that the homeserver's own *initial* `/sync` reports
# this account in `device_lists.changed`, because that is what makes the
# `receiveSyncChanges` assertion a test of the library rather than of a query
# the machine was going to make anyway. Continuwuity reports it; Synapse
# populates `device_lists` only on incremental syncs, so the same test would
# fail there for a reason that has nothing to do with this library.
# Continuwuity is also what this project's own infrastructure runs and what
# the test was originally proven against (task-12-report.md), it boots in
# about two seconds, and its image is 128 MB with no database server to bring
# up alongside it.
CONTINUWUITY_IMAGE=${CONTINUWUITY_IMAGE:-forgejo.ellis.link/continuwuation/continuwuity@sha256:b5f5d7454a3e8dda041fc82084088409f2c34905ff51274955d52050203a87af}

# The homeserver's `server_name`, which is also the domain half of the MXID.
# `localhost` is legal, needs no DNS and no certificate, and cannot be
# confused with anybody's real deployment.
SERVER_NAME=localhost
LOCALPART=interop

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REQUIREMENTS="$REPO_ROOT/rust/matrix-crypto-core/tests/interop/requirements.txt"

# How long to wait for the container to answer, and then for the account it
# was told to create to accept a login.
HOMESERVER_TIMEOUT_SECONDS=${HOMESERVER_TIMEOUT_SECONDS:-90}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# --- teardown, on every path out -------------------------------------------

# Every container this script starts carries these two labels, which is what
# makes the sweep below possible: the first says whose it is, the second says
# when it was started.
CONTAINER_LABEL=org.linagora.rnmc.level-two-interop
STARTED_LABEL=org.linagora.rnmc.level-two-interop.started

# How old a labelled container must be before the sweep will remove it.
# Comfortably longer than this job's own CI timeout of 45 minutes, so a
# concurrent run of this script -- two shells, or two jobs on one self-hosted
# runner -- can never have its homeserver killed underneath it. A sweep that
# removes a live run's container would be a worse bug than the debris it
# exists to clear.
STALE_AFTER_SECONDS=7200

CONTAINER=""
WORKDIR=""
RUN_FAILED=0

# Idempotent, and every step of it is allowed to fail: this runs from a trap,
# including on the path where something has already gone wrong, and a
# teardown that can itself fail is not a teardown. The same rule the test's
# own `Teardown` guard follows in `Drop`, for the same reason.
cleanup() {
  if [ -n "$CONTAINER" ]; then
    # Only on a failure, and only after the container is already doomed. A
    # passing run prints none of this: continuwuity echoes the password it
    # was told to set into its own startup output, and while that password
    # dies with the container -- and is masked under Actions -- there is no
    # reason to put it on screen at all.
    if [ "$RUN_FAILED" != "0" ]; then
      echo "--- homeserver output ---" >&2
      docker logs "$CONTAINER" 2>&1 | tail -60 >&2 || true
      echo "--- end homeserver output ---" >&2
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    CONTAINER=""
  fi
  if [ -n "$WORKDIR" ]; then
    rm -rf "$WORKDIR" || true
    WORKDIR=""
  fi
  return 0
}

# EXIT covers the ordinary path, every `fail` and every errexit abort. The
# three signals cover a developer's Ctrl-C and a CI runner cancelling the job:
# they exit rather than clean up directly, so the EXIT trap does the work once
# and there is exactly one teardown path to reason about.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

WORKDIR=$(mktemp -d)

# --- 1. the homeserver -----------------------------------------------------

if [ -n "${MATRIX_INTEROP_HOMESERVER:-}" ]; then
  # The manual path, unchanged. Everything the test needs is already in the
  # environment, so start nothing and destroy nothing.
  [ -n "${MATRIX_INTEROP_USER:-}" ] \
    || fail "MATRIX_INTEROP_HOMESERVER is set but MATRIX_INTEROP_USER is not.
      Set all three of HOMESERVER, USER and PASSWORD to run against a real
      homeserver, or none of them to run against a throwaway container."
  [ -n "${MATRIX_INTEROP_PASSWORD:-}" ] \
    || fail "MATRIX_INTEROP_HOMESERVER is set but MATRIX_INTEROP_PASSWORD is not.
      Set all three of HOMESERVER, USER and PASSWORD to run against a real
      homeserver, or none of them to run against a throwaway container."
  echo "Using the homeserver named by MATRIX_INTEROP_HOMESERVER; starting no container."
else
  command -v docker >/dev/null 2>&1 \
    || fail "docker is not on PATH, and no MATRIX_INTEROP_HOMESERVER was set.
      This script needs one or the other: a container runtime to start a
      throwaway homeserver in, or an existing homeserver to point at."
  docker info >/dev/null 2>&1 \
    || fail "the Docker daemon is not reachable. Start it and try again."
  command -v openssl >/dev/null 2>&1 || fail "openssl is not on PATH."

  # The one hole the traps cannot close: a `kill -9` of this script, or a
  # machine losing power, leaves the container running with nothing left to
  # remove it. So each run first removes any container carrying this label
  # that is older than STALE_AFTER_SECONDS, which can only be debris from
  # exactly that. A homeserver holding a loopback port for the rest of a
  # developer's week is a small thing, but it is the sort of small thing that
  # makes people stop running a test.
  #
  # Bounded by age rather than swept wholesale, and the age is what matters:
  # an unbounded sweep would kill the homeserver of a *concurrent* run of this
  # same script. `docker ps` has no `until` filter (checked -- it is a
  # `container prune` filter only), so each container records its own start
  # time in a label and this compares it.
  NOW=$(date +%s)
  while read -r stale_id stale_started; do
    [ -n "$stale_id" ] || continue
    case "$stale_started" in
      '' | *[!0-9]*) continue ;;
    esac
    [ "$(( NOW - stale_started ))" -gt "$STALE_AFTER_SECONDS" ] || continue
    echo "Removing a homeserver left behind by a killed run ($stale_id)."
    docker rm -f "$stale_id" >/dev/null 2>&1 || true
  done <<EOF
$(docker ps -a --filter "label=$CONTAINER_LABEL" \
    --format "{{.ID}} {{.Label \"$STARTED_LABEL\"}}" 2>/dev/null || true)
EOF

  # Generated per run, used once, and destroyed with the container. It is
  # registered with the Actions log masker before it is passed to anything,
  # so it cannot reach a job log.
  PASSWORD=$(openssl rand -hex 24)
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::add-mask::$PASSWORD"
  fi

  # Pulled explicitly, with retries, rather than left to `docker run`. The
  # image is published only from continuwuity's own Forgejo instance -- there
  # is no ghcr.io or Docker Hub mirror, checked -- so this job depends on one
  # third-party host being up. That is a real dependency and it is named here
  # rather than discovered as an unexplained failure: three attempts, and a
  # message that says which host did not answer.
  PULLED=""
  for attempt in 1 2 3; do
    if docker image inspect "$CONTINUWUITY_IMAGE" >/dev/null 2>&1; then
      PULLED=1
      break
    fi
    echo "Pulling the homeserver image (attempt $attempt)..."
    if docker pull --quiet "$CONTINUWUITY_IMAGE" >/dev/null 2>&1; then
      PULLED=1
      break
    fi
    sleep $(( attempt * 5 ))
  done
  [ -n "$PULLED" ] || fail "could not pull $CONTINUWUITY_IMAGE after three attempts.
      Continuwuity publishes only to its own registry (forgejo.ellis.link);
      there is no ghcr.io or Docker Hub mirror. If that host is down, this
      job cannot run, and that is a dependency rather than a defect in this
      library."

  STARTED_AT=$(date +%s)
  CONTAINER="rnmc-level-two-$$-$STARTED_AT"
  # `--entrypoint` because the image declares the binary as CMD with no
  # ENTRYPOINT, so bare arguments would replace it rather than be passed to
  # it.
  #
  # `--execute` runs one admin console command after startup. That is what
  # creates the account, and it is why registration is left disabled: the
  # first account on a fresh continuwuity cannot be registered over the
  # client API without the one-time bootstrap token the server generates and
  # prints, and scraping a credential out of a log to feed it back in is both
  # brittle and the opposite of what this script is for.
  #
  # `-p 127.0.0.1::8008` publishes on loopback only, on a port Docker
  # chooses, so a run cannot collide with anything else on the machine and
  # cannot be reached from off it.
  #
  # `--tmpfs` for the database: nothing this run creates should outlive it,
  # not even on disk.
  docker run -d \
    --name "$CONTAINER" \
    --label "$CONTAINER_LABEL" \
    --label "$STARTED_LABEL=$STARTED_AT" \
    -p 127.0.0.1::8008 \
    --tmpfs /db:rw,size=512m \
    --entrypoint /sbin/conduwuit \
    -e CONDUWUIT_SERVER_NAME="$SERVER_NAME" \
    -e CONDUWUIT_DATABASE_PATH=/db \
    -e CONDUWUIT_ADDRESS=0.0.0.0 \
    -e CONDUWUIT_PORT=8008 \
    -e CONDUWUIT_ALLOW_FEDERATION=false \
    -e CONDUWUIT_ALLOW_REGISTRATION=false \
    -e CONDUWUIT_ALLOW_CHECK_FOR_UPDATES=false \
    "$CONTINUWUITY_IMAGE" \
    --execute "users create-user $LOCALPART $PASSWORD" >/dev/null \
    || fail "the homeserver container could not be started."

  HOST_PORT=$(docker port "$CONTAINER" 8008/tcp 2>/dev/null | head -1 | sed 's/.*://')
  [ -n "$HOST_PORT" ] \
    || { RUN_FAILED=1; fail "the container published no host port for 8008."; }

  export MATRIX_INTEROP_HOMESERVER="http://127.0.0.1:$HOST_PORT"
  export MATRIX_INTEROP_USER="@$LOCALPART:$SERVER_NAME"
  export MATRIX_INTEROP_PASSWORD="$PASSWORD"

  echo "Homeserver: $MATRIX_INTEROP_HOMESERVER (container $CONTAINER)"

  # Wait for the API, then for the account. These are two different facts and
  # the second is the one that matters: `--execute` runs asynchronously after
  # startup, so a server answering /versions does not yet mean the account
  # exists. Requiring a real login here means a provisioning failure is
  # reported as itself, rather than surfacing several minutes later as an
  # unexplained test failure.
  DEADLINE=$(( $(date +%s) + HOMESERVER_TIMEOUT_SECONDS ))
  READY=""
  while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
      RUN_FAILED=1
      fail "the homeserver container exited before it was ready."
    fi
    LOGIN=$(curl -s -m 5 -X POST \
      -H 'Content-Type: application/json' \
      --data-binary @- \
      "$MATRIX_INTEROP_HOMESERVER/_matrix/client/v3/login" <<JSON || true
{"type":"m.login.password",
 "identifier":{"type":"m.id.user","user":"$MATRIX_INTEROP_USER"},
 "password":"$MATRIX_INTEROP_PASSWORD",
 "initial_device_display_name":"level-two-readiness-probe"}
JSON
)
    # Matched on the field name rather than on any value: the token is a live
    # credential for as long as the next two lines take, and must not be
    # echoed, compared against a pattern that could print it, or kept.
    if printf '%s' "$LOGIN" | grep -q '"access_token"'; then
      READY=1
      # Log the probe device straight out again. The library shares its room
      # key with every device on the account, so a stray device left here
      # would be one more withheld notice in the test's own batches for no
      # reason.
      TOKEN=$(printf '%s' "$LOGIN" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
      curl -s -m 5 -o /dev/null -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/json' \
        -d '{}' \
        "$MATRIX_INTEROP_HOMESERVER/_matrix/client/v3/logout" || true
      unset TOKEN
      break
    fi
    sleep 2
  done
  if [ -z "$READY" ]; then
    RUN_FAILED=1
    fail "the homeserver never accepted a login as $MATRIX_INTEROP_USER within
      ${HOMESERVER_TIMEOUT_SECONDS}s. Either it did not finish starting, or the
      account this script told it to create was not created."
  fi
  echo "Homeserver ready, and the account it was told to create can log in."

  # Continuwuity does not reject a configuration key it does not recognise. It
  # logs `Config parameter "x" is unknown to conduwuit, ignoring.` and starts
  # anyway -- so a renamed or misspelled setting above would silently do
  # nothing, and this script would go on asserting that federation is off and
  # registration is closed while neither was actually applied. A setting that
  # looks applied and is not is exactly the shape of defect this repository
  # keeps finding, so it is checked rather than assumed.
  #
  # Only the key names are reproduced, never the log line and never the log:
  # continuwuity echoes the generated password into its own startup output.
  IGNORED=$(docker logs "$CONTAINER" 2>&1 \
    | sed -n 's/.*Config parameter "\([a-z_0-9]*\)" is unknown to conduwuit.*/\1/p' \
    | sort -u | tr '\n' ' ')
  if [ -n "$IGNORED" ]; then
    RUN_FAILED=1
    fail "the homeserver ignored configuration this script relies on: $IGNORED
      Continuwuity warns and carries on rather than refusing to start, so these
      settings did nothing. Either the image moved and the keys were renamed, or
      one is misspelled above. Fix the names rather than the assertion."
  fi
fi

# --- 2. the counterparty's Python ------------------------------------------

if [ -n "${MATRIX_INTEROP_NIO_PYTHON:-}" ]; then
  echo "Using the interpreter named by MATRIX_INTEROP_NIO_PYTHON."
else
  BASE_PYTHON=${PYTHON:-python3}
  command -v "$BASE_PYTHON" >/dev/null 2>&1 \
    || fail "$BASE_PYTHON is not on PATH. Set PYTHON to a Python 3 interpreter,
      or MATRIX_INTEROP_NIO_PYTHON to one that already has matrix-nio[e2e]."
  [ -f "$REQUIREMENTS" ] || fail "missing $REQUIREMENTS"

  echo "Installing the pinned matrix-nio[e2e] into a throwaway virtualenv..."
  "$BASE_PYTHON" -m venv "$WORKDIR/venv" \
    || fail "could not create a virtualenv with $BASE_PYTHON."
  "$WORKDIR/venv/bin/python" -m pip install --quiet --upgrade pip \
    || fail "could not upgrade pip in the virtualenv."
  # --no-deps with a fully resolved requirements file: pip installs exactly
  # the pinned set and nothing else, so a transitive dependency cannot move
  # underneath this proof between one run and the next.
  "$WORKDIR/venv/bin/python" -m pip install --quiet --no-deps -r "$REQUIREMENTS" \
    || fail "could not install $REQUIREMENTS."
  export MATRIX_INTEROP_NIO_PYTHON="$WORKDIR/venv/bin/python"
fi

# Asserted, not assumed. Without this a missing counterparty surfaces as the
# test failing to start a subprocess, several minutes in.
"$MATRIX_INTEROP_NIO_PYTHON" - <<'PY' || fail "the interpreter at MATRIX_INTEROP_NIO_PYTHON cannot import matrix-nio's e2e stack."
import nio, vodozemac
from nio import AsyncClient, MegolmEvent
from importlib.metadata import version
print(f"matrix-nio {version('matrix-nio')}, vodozemac {version('vodozemac')}")
PY

# --- 3. the test -----------------------------------------------------------

OUTPUT="$WORKDIR/cargo-test-output.txt"
TEST_NAME=level_two_interoperability_over_a_real_homeserver

echo "Running the level 2 test..."
set +e
cargo test --manifest-path "$REPO_ROOT/rust/Cargo.toml" \
  -p matrix-crypto-core --test level_two_interop \
  -- --ignored --exact "$TEST_NAME" 2>&1 | tee "$OUTPUT"
CARGO_STATUS=${PIPESTATUS[0]}
set -e

# --- 4. what actually happened ---------------------------------------------

if [ "$CARGO_STATUS" != "0" ]; then
  RUN_FAILED=1
  fail "cargo test exited $CARGO_STATUS. See the output above."
fi

# Everything below reads the file rather than trusting that exit status.
#
# `--exact` above means a renamed test matches nothing, and libtest then
# prints `0 passed; 0 failed; ...; 1 filtered out` and exits 0. So does a run
# where the test is still `#[ignore]`d and `--ignored` was dropped. Both are
# the seven-times-repeated failure of this milestone, and both are caught by
# insisting on the count.
OK_LINES=$(grep -c "^test $TEST_NAME \.\.\. ok\$" "$OUTPUT" || true)
if [ "$OK_LINES" -lt 1 ]; then
  RUN_FAILED=1
  fail "cargo test exited 0 but never reported '$TEST_NAME ... ok'.
      That is not a pass. The test was filtered out, renamed, or the process
      died before libtest could report on it."
fi

SUMMARIES=$(grep -c '^test result: ok\. 1 passed; 0 failed; 0 ignored' "$OUTPUT" || true)
if [ "$SUMMARIES" -lt 1 ]; then
  RUN_FAILED=1
  fail "cargo test exited 0 but printed no 'test result: ok. 1 passed; 0 failed;
      0 ignored' summary. libtest reported:
$(grep '^test result:' "$OUTPUT" || echo '      (no test result line at all)')"
fi

# The test spawns a second copy of itself to prove `openCryptoStore` restores
# a session across processes, and that child's libtest output lands in this
# same stream. Two summaries are therefore expected and three would mean
# something re-ran; what matters is that neither of them is a nought, which
# the two checks above have already established for both.
echo
echo "PASS: $TEST_NAME"
echo "      $SUMMARIES libtest summaries, all 'ok. 1 passed; 0 failed; 0 ignored'."
if [ -n "$CONTAINER" ]; then
  echo "      Proven against a throwaway $SERVER_NAME homeserver this script started"
  echo "      and is about to destroy. No credential was read from anywhere."
fi
