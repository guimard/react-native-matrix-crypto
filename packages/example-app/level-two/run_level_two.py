#!/usr/bin/env python3
"""Level 2 interoperability, through the published TypeScript surface.

Design doc section 8's second level -- "does a real Matrix client decrypt
what we encrypt, and can we decrypt what it sends" -- was already proven
against the **Rust core** by `rust/matrix-crypto-core/tests/level_two_interop.rs`.
Between that core and a product sit the UniFFI scaffolding, the JSI binding,
the generated TypeScript and `facade.ts`, none of which had ever faced a
homeserver -- and one of which was already wrong, in exactly the function
this run exercises hardest. This is that proof, moved up to the layer a
product actually calls, running on an emulator.

WHAT THIS PROGRAM IS

Everything on the host side of that run, in one process with one teardown
path:

  1. a throwaway Matrix homeserver in a container, created here and
     destroyed here;
  2. two accounts and an encrypted room on it, created here;
  3. `matrix-nio` as the third-party counterparty, driven op by op;
  4. a small HTTP service on the host's loopback that hands the app its run
     plan and relays each counterparty op;
  5. the emulator: install, launch, and read back what the app printed;
  6. the assertion, on the app's own summary line.

The app owns every cryptographic assertion. This program owns sequencing,
infrastructure and cleanup, and asserts only two things itself: that a
summary line was found, and that the run's device is gone from the
homeserver afterwards.

CREDENTIALS, AND WHERE THEY ARE VISIBLE

There is nothing durable to manage, and that is the point of the container.
Every account here is created by this program, on a homeserver that does not
outlive it, with a password generated per run. The app is handed a
device-scoped access token in the body of a loopback HTTP response: never a
file, never an initial property (see the rule in MainActivity.kt), never a
log line -- and that last claim is checked on every run, not asserted, by
`assert_nothing_leaked`. The run revokes the token itself, as an asserted
step, and destroying the container revokes everything else by removing the
homeserver that issued it.

Three local channels do carry a value while a run is in flight. They are
named here rather than left to be discovered, because a threat model that
lists only the channel you closed is worse than none:

  * `docker logs` and `docker inspect .Config.Env` carry both account
    passwords in cleartext, for the life of the container. Continuwuity's
    admin console echoes a password it was told to set into its own startup
    output regardless of log level, and the env file this program writes
    becomes the container's environment. `scripts/run-level-two-interop.sh`
    documents the same fact for the same reason. This program never reads or
    prints either -- and when it does dump container output on a bring-up
    failure it redacts both passwords first, and refuses to print at all if
    the redaction did not take.
  * The mode-600 env file in this run's temporary directory, until teardown
    deletes it. Deleted from a `finally`, an `atexit` hook, and swept by name
    at startup, the same three ways the container is.
  * `GET http://127.0.0.1:8449/plan` serves the access token to any process
    on this machine, unauthenticated, for the life of the run. There is no
    fix available: the app must ask before it has anything to authenticate
    with. The mitigation is the structural one -- the token authenticates
    only to a homeserver inside a container that dies a minute later.

What is *not* a channel: `ps`. The passwords reach `docker run` through
`--env-file`, never through `-e`, so they are not in any process's argv.

TEARDOWN

Everything this run creates on a server lives inside the container, on a
tmpfs, so `docker rm --force` is a complete teardown rather than a list to
remember. That removal happens in a `finally`, in an `atexit` hook, and
under a SIGTERM handler; the container is also force-removed by name and
swept by label at *startup*, so a run killed outright cannot leak into the
next one. The temporary directory -- which holds the mode-600 env file and
the counterparty's store -- is defended the same three ways, and swept at
startup too. A failing run tears down exactly as a passing one does: task
12's level 2 tidied up after its last assertion instead, and twelve devices
and six rooms had to be removed by hand from a shared homeserver.

One thing teardown deliberately does not touch: the app stays installed on
the emulator, with the crypto store this run created in its private files
directory. It is removed by the next run's `adb uninstall`, which is also
what makes each run the cold start its first step asserts. The store is
encrypted, and everything it could decrypt died with the container.

USAGE

    <python-with-matrix-nio> packages/example-app/level-two/run_level_two.py \
        [--apk PATH] [--mutation NAME]

The interpreter must have `matrix-nio[e2e]` installed; this program does not
provision one and should not. `--mutation` sabotages exactly one assertion
in the app's suite, to prove that assertion can fail; a mutated run prints
`LEVEL2_MUTATED_SUMMARY` and can never be mistaken for a clean one.
"""

import argparse
import asyncio
import atexit
import http.client
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- Fixed configuration ----------------------------------------------------

# Pinned by DIGEST, not by tag: a homeserver that changes under a proof
# changes what the proof means, and a tag can be re-pushed to point at
# different bytes. `:sha-59c2649` names a source commit and looks like a pin
# without being one -- an earlier version of this file used it and this
# comment claimed it was a digest, which is the kind of sentence this
# milestone exists to stop shipping.
#
# The same digest `scripts/run-level-two-interop.sh` pins for the core's
# level 2, so both proofs run against identical bytes.
HOMESERVER_IMAGE = (
    "forgejo.ellis.link/continuwuation/continuwuity"
    "@sha256:b5f5d7454a3e8dda041fc82084088409f2c34905ff51274955d52050203a87af"
)

CONTAINER_NAME = "rnmc-level-two-homeserver"

# The conductor's port on the host. Fixed, and it has to be: the app must
# know where to ask before it has anything to ask with, so this number is a
# constant in `src/levelTwoTransport.ts` too. Checked free before the run,
# with a plain failure if it is not.
CONDUCTOR_PORT = 8449

# The homeserver's port is NOT fixed: Docker picks a free one and the plan
# carries it to the app, so a run cannot collide with anything else on the
# machine -- including `scripts/run-level-two-interop.sh`, which stands up
# its own homeserver for the core's level 2 and may be running at the same
# time. Both publish on 127.0.0.1 only, so neither is reachable off the host.
EMULATOR_HOST_ALIAS = "10.0.2.2"

# Set on the container and read by `sweep_containers`, which runs before this
# program creates anything, so a container left behind by a run that was
# killed outright is removed even if its name had since been changed. Its own
# sibling, `scripts/run-level-two-interop.sh`, filters on a different label,
# so neither sweep can take the other's container out from under it.
CONTAINER_LABEL = "org.linagora.rnmc.level-two-facade"

SERVER_NAME = "level-two.test"
LIBRARY_LOCALPART = "libraryparty"
NIO_LOCALPART = "nioparty"

PACKAGE = "com.exampleapp"
ACTIVITY = ".MainActivity"
DEFAULT_APK = "packages/example-app/android/app/build/outputs/apk/release/app-release.apk"

# How long to wait for the app's summary after launch. The run creates a real
# encrypted store, publishes keys, does two Megolm round trips and four
# controls, over HTTP, on an emulator. Slow is normal; silent is not.
SUMMARY_TIMEOUT_SECONDS = int(os.environ.get("LEVEL_TWO_TIMEOUT_SECONDS", "420"))

SUMMARY_PATTERN = re.compile(r"^LEVEL2_(MUTATED_)?SUMMARY \d+/\d+")

# How many steps the app's suite must report. Pinned HERE, on the outside,
# not read off the summary the app printed.
#
# Without this line the runner checks only that everything reported passed,
# and the denominator is whatever the artifact under test says it is: drop a
# step from `LEVEL_TWO_STEPS` and the run prints `LEVEL2_SUMMARY 12/12` and
# this program calls it a pass. That is exactly the "a summary that counts
# fewer steps than it should is indistinguishable from a pass" failure the
# suite's own header says this milestone has hit under several names, one
# level up: the thing being measured was declaring its own denominator.
#
# `scripts/run-probe-on-emulator.sh` already established the convention with
# `EXPECTED_SUMMARY="PROBE_SUMMARY 12/12"`, and for the same reason. If you
# add or remove a step, change this number in the same commit -- this program
# failing until you do is the point.
EXPECTED_STEPS = 13

# Every mutation the app's suite carries, and the step each must turn red.
# Named here as well as in the suite so the runner can say what it expects
# rather than leaving a reader to work it out.
MUTATIONS = {
    "none": None,
    "corrupt_the_event_nio_must_read": "library_encrypts_nio_decrypts",
    "intact_control_to_nio": "nio_refuses_corrupted_ciphertext",
    "intact_control_to_library": "library_refuses_corrupted_ciphertext",
    "raw_sync_to_receive": "sync_teaches_the_machine",
    "skip_keys_claim": "claim_then_share_delivers_key",
    "withhold_room_key": "library_encrypts_nio_decrypts",
}


def log(message):
    """The runner's own output. Never carries a token or a password."""
    print(f"[level-two] {message}", flush=True)


class RunFailed(Exception):
    """A failure this program is reporting, not a bug in it."""


# --- Homeserver HTTP --------------------------------------------------------


class Homeserver:
    """Plain HTTP against the throwaway homeserver.

    Deliberately small and deliberately quiet: no request body and no
    response body is ever formatted into an exception message. A `/login`
    error body can echo the request, and a `/keys/upload` body *is* key
    material.
    """

    def __init__(self, base_url):
        self.base_url = base_url

    def call(self, method, path, token=None, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.base_url + path, data=data, method=method,
            headers={"Content-Type": "application/json"},
        )
        if token is not None:
            request.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read() or b"{}")
            except json.JSONDecodeError:
                return error.code, {}
        except (urllib.error.URLError, OSError, http.client.HTTPException):
            # Status 0 means "no answer at all", which is what a homeserver
            # that has bound its port but not finished starting looks like:
            # the connection is accepted and then closed without a response.
            # Callers that poll treat it as "not ready yet".
            return 0, {}

    def login(self, localpart, password, display_name):
        status, body = self.call("POST", "/_matrix/client/v3/login", body={
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": localpart},
            "password": password,
            "initial_device_display_name": display_name,
        })
        if status != 200:
            # The body is deliberately not reproduced: a login error body can
            # echo the request that produced it.
            raise RunFailed(f"login for {localpart!r} returned HTTP {status}")
        return body["access_token"], body["user_id"], body["device_id"]


# --- The counterparty -------------------------------------------------------


class Counterparty:
    """`matrix-nio`, driven one operation at a time.

    Why Python and not a second `OlmMachine`: level 1 drives the same
    protocol state machine this library holds, so a consistent misreading of
    the Matrix spec passes it cleanly. `matrix-nio` implements its own
    Olm/Megolm session lifecycle, device tracking and key-sharing decisions,
    so it has to agree with us on the wire without sharing the code that
    produces either side of it.

    The independence is at the protocol level, not all the way down: nio
    0.26 moved its ratchet to `vodozemac`, the same crate
    `matrix-sdk-crypto` uses. A defect inside `vodozemac` itself would pass
    both sides. Everything above it -- event shapes, `/keys/*` payloads,
    to-device routing, the megolm event body -- is two independent
    implementations agreeing or not.

    **It is never told what it is supposed to find.** `collect` receives a
    room, a list of event ids and which of them must decrypt, and reports
    what it made of each. The plaintext the app compares against never
    crosses to this side, so a harness that lied would have to guess the
    string.
    """

    # nio marks every device it has not verified as unverified and refuses by
    # default to send a room key to one. M2 verifies nothing on either side
    # -- our own outbound half is `CollectStrategy::AllDevices` for the same
    # reason (spec section 7.2) -- so the counterparty is held to the same
    # standard rather than a stricter one it would fail on.
    IGNORE_UNVERIFIED = True

    def __init__(self, homeserver, user_id, password, store_path):
        self.homeserver = homeserver
        self.user_id = user_id
        self.password = password
        self.store_path = store_path
        self.client = None

    async def op_login(self, command):
        import logging

        from nio import AsyncClient, AsyncClientConfig, LoginResponse

        # nio logs every failed decryption at error level, so the corrupted
        # control -- an event this run *requires* to fail -- prints two
        # alarming lines in the middle of a passing run. Silenced because the
        # refusal is already reported structurally, in `op_collect`'s reply,
        # which is where the app asserts on it. Nothing is lost: a reason
        # that never arrives fails the control's own positive assertion.
        logging.getLogger("nio").setLevel(logging.CRITICAL)

        self.client = AsyncClient(
            self.homeserver.base_url, self.user_id, store_path=self.store_path,
            config=AsyncClientConfig(encryption_enabled=True, store_sync_tokens=False,
                                     request_timeout=60, max_timeouts=3),
        )
        response = await self.client.login(self.password, device_name="level-two-facade-nio")
        if not isinstance(response, LoginResponse):
            return {"ok": False, "error": f"login failed: {type(response).__name__}"}

        # Joined over plain HTTP rather than with `AsyncClient.join`, which
        # sends an empty request body this homeserver rejects with
        # M_BAD_JSON ("EOF while parsing a value"). A disagreement between
        # the counterparty and the homeserver about an unencrypted endpoint,
        # nothing to do with this library, and worked around here rather
        # than chased.
        path = "/_matrix/client/v3/join/" + urllib.parse.quote(command["room_id"], safe="")
        status, _ = self.homeserver.call("POST", path, self.client.access_token, {})
        return {"ok": True, "device_id": self.client.device_id, "joined": status == 200}

    async def settle(self, rounds=3, timeout_ms=1000):
        """One turn of nio's own key pump: sync, publish keys, query devices.

        `sync_forever` does this internally; a bare `sync` does not, and this
        run drives every step explicitly so an unpublished key is a visible
        missing step rather than a silent absence.
        """
        for _ in range(rounds):
            await self.client.sync(timeout=timeout_ms, full_state=False)
            if self.client.should_upload_keys:
                await self.client.keys_upload()
            if self.client.should_query_keys:
                await self.client.keys_query()

    async def op_settle(self, command):
        await self.settle(rounds=int(command.get("rounds", 3)))
        # Asserted against the homeserver rather than against nio's own
        # opinion of itself: `should_upload_keys` going false says nio thinks
        # it has published, and the app's next step depends on the keys
        # actually being there.
        status, body = self.homeserver.call(
            "POST", "/_matrix/client/v3/keys/query", self.client.access_token,
            {"device_keys": {self.user_id: []}},
        )
        published = (
            status == 200
            and self.client.device_id in body.get("device_keys", {}).get(self.user_id, {})
        )
        return {"ok": True, "published_keys": published}

    async def op_send(self, command):
        """nio encrypts and sends. Direction 2 of the proof."""
        from nio import RoomSendResponse

        if command["room_id"] not in self.client.rooms:
            await self.settle(rounds=2)
        response = await self.client.room_send(
            command["room_id"], "m.room.message",
            {"msgtype": "m.text", "body": command["body"]},
            ignore_unverified_devices=self.IGNORE_UNVERIFIED,
        )
        if not isinstance(response, RoomSendResponse):
            return {"ok": False, "error": f"send failed: {type(response).__name__}"}
        return {"ok": True, "event_id": response.event_id}

    async def op_collect(self, command):
        """Syncs until the named events arrive, and reports what nio made of each.

        `event_ids` is everything to observe; `require_decrypted` is the
        subset that must actually decrypt before this returns early. An event
        still a `MegolmEvent` after the sync that carried it is retried on
        every later round, because a room key can arrive in a later sync than
        the message it unlocks. So "not decrypted" here means nio kept
        failing for the whole window with the key already in hand -- which is
        what a corrupted control must produce and an intact event must not.
        """
        from nio import MegolmEvent

        room_id = command["room_id"]
        wanted = set(command["event_ids"])
        must_decrypt = set(command.get("require_decrypted", []))
        deadline = asyncio.get_event_loop().time() + float(command.get("timeout_s", 90))

        done = {}
        pending = {}
        reasons = {}

        def outstanding():
            return (wanted - set(done) - set(pending)) or (must_decrypt - set(done))

        while outstanding() and asyncio.get_event_loop().time() < deadline:
            response = await self.client.sync(timeout=3000, full_state=False)
            rooms = getattr(response, "rooms", None)
            if rooms is not None and room_id in rooms.join:
                for event in rooms.join[room_id].timeline.events:
                    event_id = getattr(event, "event_id", None)
                    if event_id is None or event_id not in wanted or event_id in done:
                        continue
                    if isinstance(event, MegolmEvent):
                        pending[event_id] = event
                    else:
                        done[event_id] = {
                            "decrypted": True, "type": type(event).__name__,
                            "body": getattr(event, "body", None), "retried": False,
                        }
            for event_id, event in list(pending.items()):
                try:
                    decrypted = self.client.decrypt_event(event)
                    done[event_id] = {
                        "decrypted": True, "type": type(decrypted).__name__,
                        "body": getattr(decrypted, "body", None), "retried": True,
                    }
                    pending.pop(event_id)
                except Exception as error:  # noqa: BLE001 -- reported, not handled
                    reasons[event_id] = f"{type(error).__name__}: {error}"

        for event_id in pending:
            done[event_id] = {
                "decrypted": False, "type": "MegolmEvent",
                "reason": reasons.get(event_id, "never attempted"),
            }
        return {"ok": True, "events": done, "missing": sorted(wanted - set(done))}

    async def op_quit(self, command):
        if self.client is not None:
            # Logged out, not merely closed: this device's access token must
            # not outlive the run, and the device goes with it.
            try:
                await self.client.logout()
            finally:
                await self.client.close()
            self.client = None
        return {"ok": True}

    async def dispatch(self, command):
        handler = getattr(self, "op_" + str(command.get("op")), None)
        if handler is None:
            return {"ok": False, "error": f"unknown op {command.get('op')!r}"}
        return await handler(command)


# --- The conductor's HTTP service ------------------------------------------


class Conductor:
    """Serves the run plan and relays counterparty ops, on loopback only.

    The app polls `/plan` on every launch. Nothing answering means "this is
    an ordinary launch": the app runs its usual probe and prints
    `PROBE_SUMMARY`, exactly as it did before this run existed. A conductor
    answering means a person deliberately started one.
    """

    def __init__(self, plan, counterparty, loop):
        self.plan = plan
        self.counterparty = counterparty
        self.loop = loop
        self.server = None
        self.ops_served = 0

    def start(self):
        conductor = self

        class Handler(BaseHTTPRequestHandler):
            def _reply(self, status, payload):
                encoded = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def do_GET(self):  # noqa: N802 -- BaseHTTPRequestHandler's own naming
                if self.path != "/plan":
                    self._reply(404, {"ok": False, "error": "no such path"})
                    return
                self._reply(200, conductor.plan)

            def do_POST(self):  # noqa: N802
                if self.path != "/op":
                    self._reply(404, {"ok": False, "error": "no such path"})
                    return
                length = int(self.headers.get("Content-Length", "0"))
                command = json.loads(self.rfile.read(length) or b"{}")
                conductor.ops_served += 1
                future = asyncio.run_coroutine_threadsafe(
                    conductor.counterparty.dispatch(command), conductor.loop)
                try:
                    self._reply(200, future.result(timeout=300))
                except Exception as error:  # noqa: BLE001 -- reported to the app
                    self._reply(200, {"ok": False,
                                      "error": f"{type(error).__name__}: {error}"})

            def log_message(self, *_args):
                """Silent.

                The default handler writes every request line to stderr, and
                a request line is the one place a path with a room id in it
                would land in this program's output.
                """

        # 127.0.0.1, not 0.0.0.0: the emulator reaches the host's loopback
        # through its own 10.0.2.2 alias, so binding wider would expose the
        # plan -- and the access token in it -- to the network for nothing.
        self.server = ThreadingHTTPServer(("127.0.0.1", CONDUCTOR_PORT), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


# --- Infrastructure ---------------------------------------------------------


def run_command(argv, timeout=300):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


def require(condition, message):
    if not condition:
        raise RunFailed(message)


def port_is_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        return probe.connect_ex(("127.0.0.1", port)) != 0


def remove_container():
    """Force-removes the homeserver, by name, whatever state it is in."""
    run_command(["docker", "rm", "--force", CONTAINER_NAME], timeout=120)


def sweep_containers():
    """Removes any container this program left behind, by its own label.

    The fixed name plus the force-remove above is what actually protects the
    ordinary paths. This exists so the label is read by something rather than
    only set -- and it catches a container from a run whose name was changed
    under it, which the name alone would not.
    """
    listed = run_command(
        ["docker", "ps", "-aq", "--filter", f"label={CONTAINER_LABEL}"], timeout=60)
    stale = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    for container in stale:
        run_command(["docker", "rm", "--force", container], timeout=120)
    return len(stale)


def sweep_workdirs(keep=None):
    """Removes this program's temporary directories, including orphans.

    The container is defended three ways -- a `finally`, an `atexit` hook and
    a force-remove at startup -- and until this existed the temporary
    directory had only the `finally`. That is the wrong asymmetry: the
    directory is where the mode-600 env file with both account passwords
    lives, so the hard-kill path the container is most defended on was the
    one path that left a credential on disk indefinitely.
    """
    root = tempfile.gettempdir()
    removed = 0
    try:
        entries = os.listdir(root)
    except OSError:
        return 0
    for entry in entries:
        if not entry.startswith("rnmc-level-two-"):
            continue
        path = os.path.join(root, entry)
        if keep is not None and os.path.abspath(path) == os.path.abspath(keep):
            continue
        shutil.rmtree(path, ignore_errors=True)
        removed += 1
    return removed


def show_homeserver_output(passwords):
    """Prints the container's own last words, with both passwords removed.

    Only on a bring-up failure, and only after redaction: continuwuity echoes
    a password it was told to set into its own startup output, so the raw log
    is exactly the thing that must not reach a terminal or a CI transcript.
    A passing run prints none of this.

    The redaction is checked rather than trusted. If either value survives
    it, this prints nothing at all and says so -- a diagnostic is worth less
    than a credential, and a redaction that quietly failed is the shape of
    control this milestone keeps finding.
    """
    raw = run_command(["docker", "logs", "--tail", "40", CONTAINER_NAME], timeout=60)
    output = (raw.stdout or "") + (raw.stderr or "")
    if not output.strip():
        return
    for password in passwords.values():
        output = output.replace(password, "<redacted>")
    if any(password in output for password in passwords.values()):
        log("the homeserver's output is withheld: a password survived redaction")
        return
    log("--- homeserver output (passwords redacted) ---")
    print(output.rstrip(), flush=True)
    log("--- end homeserver output ---")


def start_homeserver(workdir, passwords):
    """Starts the throwaway homeserver and waits for it to answer.

    Configured entirely through environment variables, so there is no
    container config file in this repository for anyone to have to keep in
    step -- and no place for a password to be committed by accident.

    Both accounts are created by `admin_execute` at boot rather than through
    `/register`. Registration on this homeserver is token-gated even with
    open registration turned on: it mints its own single-use token for the
    first account and prints it to the container log, so registering would
    mean scraping a log to get a credential. Creating the accounts from the
    configuration is both simpler and quieter.

    The environment goes in a mode-600 file rather than on the `docker run`
    command line, where `ps` would show every password to every user on this
    machine. That closes the narrower of two same-audience channels and not
    the wider one: whatever is in this file becomes the container's
    environment, so `docker inspect .Config.Env` shows it, and continuwuity
    echoes a password it was told to set into its own startup output whatever
    the log level, so `docker logs` shows it too. Both die with the
    container; neither is closable from here; see this module's own
    CREDENTIALS section, and `scripts/run-level-two-interop.sh`, which knew
    the second half first.
    """
    remove_container()
    # Pulled explicitly rather than left to `docker run`, so "the image is
    # not here and cannot be fetched" is reported as itself instead of as a
    # homeserver that never answered. Continuwuity publishes only to its own
    # Forgejo registry, which is a single point of failure worth naming.
    #
    # Skipping the pull when the image is already local is only safe because
    # HOMESERVER_IMAGE is a digest: a cached digest is the same bytes by
    # definition. It would NOT be safe for a tag, which is what this
    # short-circuit silently did before the pin was corrected.
    if run_command(["docker", "image", "inspect", HOMESERVER_IMAGE], timeout=60).returncode != 0:
        log(f"pulling {HOMESERVER_IMAGE}")
        pulled = run_command(["docker", "pull", HOMESERVER_IMAGE], timeout=900)
        require(pulled.returncode == 0,
                "could not pull the homeserver image. Continuwuity publishes only to "
                "forgejo.ellis.link, so a failure here is usually that registry being "
                f"unreachable:\n      {pulled.stderr.strip()}")

    env_path = os.path.join(workdir, "homeserver.env")
    admin = json.dumps([
        f"users create-user {LIBRARY_LOCALPART} {passwords[LIBRARY_LOCALPART]}",
        f"users create-user {NIO_LOCALPART} {passwords[NIO_LOCALPART]}",
    ])
    lines = [
        f"CONTINUWUITY_SERVER_NAME={SERVER_NAME}",
        "CONTINUWUITY_DATABASE_PATH=/var/lib/continuwuity",
        "CONTINUWUITY_PORT=8008",
        "CONTINUWUITY_ADDRESS=0.0.0.0",
        # Registration stays off: nothing registers. Both accounts come from
        # `admin_execute` below, which is also the only way to make the
        # *first* account on a fresh continuwuity without scraping the
        # one-time bootstrap token it prints to its own log.
        "CONTINUWUITY_ALLOW_REGISTRATION=false",
        "CONTINUWUITY_ALLOW_FEDERATION=false",
        "CONTINUWUITY_ALLOW_CHECK_FOR_UPDATES=false",
        "CONTINUWUITY_ADMIN_EXECUTE_ERRORS_IGNORE=false",
        f"CONTINUWUITY_ADMIN_EXECUTE={admin}",
        "CONTINUWUITY_LOG=warn",
    ]
    handle = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w") as env_file:
        env_file.write("\n".join(lines) + "\n")

    # `--tmpfs` for the database, so nothing this homeserver holds ever
    # touches a disk. `-p 127.0.0.1::8008` lets Docker choose the host port,
    # so a run collides with nothing and is reachable from nowhere but this
    # machine.
    result = run_command([
        "docker", "run", "--detach", "--name", CONTAINER_NAME,
        "--label", CONTAINER_LABEL,
        "--publish", "127.0.0.1::8008",
        "--tmpfs", "/var/lib/continuwuity:rw,size=512m",
        "--env-file", env_path,
        HOMESERVER_IMAGE, "/sbin/conduwuit",
    ])
    require(result.returncode == 0, f"could not start the homeserver: {result.stderr.strip()}")

    published = run_command(["docker", "port", CONTAINER_NAME, "8008/tcp"]).stdout.strip()
    port = published.rsplit(":", 1)[-1] if published else ""
    require(port.isdigit(), "the container published no host port for 8008")

    homeserver = Homeserver(f"http://127.0.0.1:{port}")
    deadline = time.time() + 90
    while time.time() < deadline:
        running = run_command(
            ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME]).stdout.strip()
        if running != "true":
            show_homeserver_output(passwords)
            raise RunFailed("the homeserver container exited before it was ready")
        status, _ = homeserver.call("GET", "/_matrix/client/versions")
        if status == 200:
            log(f"homeserver up on 127.0.0.1:{port} (container {CONTAINER_NAME})")
            return homeserver, port
        time.sleep(1)
    show_homeserver_output(passwords)
    raise RunFailed("the homeserver never answered /_matrix/client/versions within 90s")


def adb(*args, timeout=300):
    return run_command(["adb", *args], timeout=timeout)


def install_and_launch(apk):
    """Installs the app fresh and launches it.

    Uninstalled rather than reinstalled: the run's first step asserts what a
    *fresh* machine offers to publish, so it must not inherit anything a
    previous run left in the app's data directory.
    """
    require(adb("wait-for-device", timeout=120).returncode == 0, "no device or emulator answered adb")
    for _ in range(60):
        if adb("shell", "getprop", "sys.boot_completed").stdout.strip() == "1":
            break
        time.sleep(5)
    require(adb("shell", "getprop", "sys.boot_completed").stdout.strip() == "1",
            "the emulator never reported sys.boot_completed=1")
    model = adb("shell", "getprop", "ro.product.model").stdout.strip()
    api = adb("shell", "getprop", "ro.build.version.sdk").stdout.strip()
    log(f"emulator: {model} (API {api})")

    adb("uninstall", PACKAGE)
    result = adb("install", apk, timeout=600)
    require(result.returncode == 0, f"installing the APK failed: {result.stderr.strip()}")
    adb("logcat", "-c")
    result = adb("shell", "am", "start", "-n", f"{PACKAGE}/{ACTIVITY}")
    require(result.returncode == 0, f"launching the app failed: {result.stderr.strip()}")


def probe_lines():
    result = adb("logcat", "-d", "-v", "raw", "ReactNativeJS:V", "*:S", timeout=120)
    return [line.strip("\r") for line in result.stdout.splitlines()]


def assert_nothing_leaked(plan, passwords):
    """Reads the whole system log back and asserts none of this run's values is in it.

    The rule the two native entry points carry -- no passphrase, no key
    material, no user or device identifier may travel as an initial property,
    because React Native prints the whole map to the system log on startup --
    has no gate behind it, and this run is the first thing in this repository
    to hand the app a real credential. So the claim is checked rather than
    asserted: every value this run minted is searched for across *every* tag
    in logcat, not only the app's own.

    Reports how many lines matched and which category, never the value.

    `-b all` rather than the default buffer set: the default is main, system
    and crash, and "nothing reached the log" should mean the log, not the
    part of it this program happened to ask for.
    """
    dump = adb("logcat", "-b", "all", "-d", "-v", "brief", timeout=180).stdout
    lines = dump.splitlines()
    watched = [
        ("the access token", plan["accessToken"]),
        ("the library account's password", passwords[LIBRARY_LOCALPART]),
        ("the counterparty's password", passwords[NIO_LOCALPART]),
        ("the library account's user id", plan["userId"]),
        ("the counterparty's user id", plan["nioUserId"]),
        ("the library device's id", plan["deviceId"]),
        ("the room id", plan["roomId"]),
    ]
    # An empty watched value would match nothing and quietly shrink what this
    # check covers, while the line below still claimed the full count. That is
    # a check reporting success without examining what it claims to, which is
    # the failure this whole run is built to make impossible.
    missing = [label for label, value in watched if not value]
    require(not missing,
            "these values were empty and so could not be searched for: "
            + ", ".join(missing)
            + ".\n      This check cannot report on a value it was not given.")

    leaked = []
    for label, value in watched:
        hits = sum(1 for line in lines if value in line)
        if hits:
            leaked.append(f"{label} ({hits} line(s))")
    require(not leaked,
            "values from this run reached the system log: " + ", ".join(leaked)
            + ".\n      Nothing this run mints may be printable. Find what printed it.")
    log(f"nothing leaked: none of this run's {len(watched)} values appears anywhere in "
        f"{len(lines)} logcat lines, across every buffer")


def wait_for_summary():
    """Waits for the app's summary line, or says plainly that none appeared.

    Not "the process exited 0": `am start` detaches immediately. Not "no FAIL
    line appeared": an app that crashed on launch and an app that was never
    installed both print no FAIL line either, and reading that absence as
    success is the failure this repository keeps rediscovering.
    """
    deadline = time.time() + SUMMARY_TIMEOUT_SECONDS
    while time.time() < deadline:
        lines = probe_lines()
        summaries = [line for line in lines if SUMMARY_PATTERN.match(line)]
        if summaries:
            return summaries, lines
        if run_command(["adb", "shell", "pidof", PACKAGE]).returncode != 0:
            crash = adb("logcat", "-d", "-v", "brief", "AndroidRuntime:E", "*:S").stdout
            if crash.strip():
                log("--- AndroidRuntime ---")
                print(crash, flush=True)
                raise RunFailed(f"{PACKAGE} is no longer running and printed no summary")
        time.sleep(5)
    lines = probe_lines()
    log("--- AndroidRuntime ---")
    print(adb("logcat", "-d", "-v", "brief", "AndroidRuntime:E", "*:S").stdout, flush=True)
    for line in lines:
        if line.startswith("LEVEL2_"):
            print(line, flush=True)
    raise RunFailed(
        f"no summary line appeared within {SUMMARY_TIMEOUT_SECONDS}s. This is NOT a pass: the "
        "app either never started, crashed before the run, or stopped forwarding console output."
    )


# --- The run ----------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apk", default=DEFAULT_APK)
    parser.add_argument("--mutation", default="none", choices=sorted(MUTATIONS))
    arguments = parser.parse_args()

    require(shutil.which("docker") is not None, "docker is not on PATH")
    require(shutil.which("adb") is not None, "adb is not on PATH")
    require(os.path.isfile(arguments.apk) and os.path.getsize(arguments.apk) > 0,
            f"no APK at {arguments.apk!r}. Build one first:\n"
            "      (cd packages/example-app/android && "
            "./gradlew :app:assembleRelease -PreactNativeArchitectures=<abi>)")
    try:
        import nio  # noqa: F401
    except ImportError:
        raise RunFailed(
            "this interpreter has no matrix-nio. Run this program with a Python that has "
            "`matrix-nio[e2e]` installed; it does not provision one and should not."
        )
    require(port_is_free(CONDUCTOR_PORT),
            f"something is already listening on 127.0.0.1:{CONDUCTOR_PORT}, which is the port "
            "the app asks for its run plan on")

    # SIGTERM does not raise on its own, so `finally` would not run for a
    # `kill`. SIGINT already raises KeyboardInterrupt.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    atexit.register(remove_container)

    # Before anything is created: remove what a previous run may have been
    # killed before removing. Containers by label as well as by name, and
    # temporary directories, which until now nothing swept.
    swept_containers = sweep_containers()
    swept_workdirs = sweep_workdirs()
    if swept_containers or swept_workdirs:
        log(f"swept {swept_containers} orphaned container(s) and "
            f"{swept_workdirs} orphaned temporary director(ies) from an earlier run")

    workdir = tempfile.mkdtemp(prefix="rnmc-level-two-")
    # Registered immediately, so the window in which a hard kill could leave
    # the env file behind is the same nil window the container already had.
    atexit.register(shutil.rmtree, workdir, True)
    passwords = {
        LIBRARY_LOCALPART: secrets.token_urlsafe(24),
        NIO_LOCALPART: secrets.token_urlsafe(24),
    }
    conductor = None
    counterparty = None
    loop = None
    loop_thread = None
    homeserver = None
    library_token = None
    library_device = None

    try:
        homeserver, homeserver_port = start_homeserver(workdir, passwords)

        library_token, library_user, library_device = homeserver.login(
            LIBRARY_LOCALPART, passwords[LIBRARY_LOCALPART], "level-two-facade-library")
        nio_user = f"@{NIO_LOCALPART}:{SERVER_NAME}"
        log("both accounts exist; the library's device is logged in")

        # A real encrypted room. `m.room.encryption` is not decoration: the
        # homeserver reports a user's device-list change only to users who
        # share an encrypted room with them, and the app's
        # `sync_teaches_the_machine` step rests on exactly that report.
        status, room = homeserver.call("POST", "/_matrix/client/v3/createRoom", library_token, {
            "name": "level-two-facade",
            "preset": "private_chat",
            "invite": [nio_user],
            "initial_state": [{
                "type": "m.room.encryption", "state_key": "",
                "content": {"algorithm": "m.megolm.v1.aes-sha2"},
            }],
        })
        require(status == 200, f"creating the room returned HTTP {status}")
        room_id = room["room_id"]
        log("an encrypted room exists, with the counterparty invited")

        counterparty = Counterparty(
            homeserver, nio_user, passwords[NIO_LOCALPART],
            os.path.join(workdir, "nio-store"))
        os.makedirs(counterparty.store_path, exist_ok=True)

        loop = asyncio.new_event_loop()
        loop_thread = threading.Thread(target=loop.run_forever, daemon=True)
        loop_thread.start()

        plan = {
            # The emulator's own view of this host. The app never learns the
            # host's real address, and does not need to.
            "homeserver": f"http://{EMULATOR_HOST_ALIAS}:{homeserver_port}",
            "conductor": f"http://{EMULATOR_HOST_ALIAS}:{CONDUCTOR_PORT}",
            "userId": library_user,
            "deviceId": library_device,
            "accessToken": library_token,
            "roomId": room_id,
            "nioUserId": nio_user,
            "mutation": arguments.mutation,
        }
        conductor = Conductor(plan, counterparty, loop)
        conductor.start()
        log(f"conductor listening on 127.0.0.1:{CONDUCTOR_PORT}; mutation: {arguments.mutation}")

        install_and_launch(arguments.apk)
        summaries, lines = wait_for_summary()
        assert_nothing_leaked(plan, passwords)

        print(flush=True)
        log("--- what the app printed ---")
        for line in lines:
            if line.startswith("LEVEL2_"):
                print(line, flush=True)
        log("--- end ---")
        print(flush=True)

        require(len(summaries) == 1,
                f"expected exactly one summary line, found {len(summaries)}:\n"
                + "\n".join(summaries)
                + "\n      The harness memoises its run, so a launch prints exactly one; more "
                "than one means something re-ran it and the result is ambiguous.")
        summary = summaries[0]
        log(f"summary: {summary}")

        expected_prefix = ("LEVEL2_SUMMARY" if arguments.mutation == "none"
                           else "LEVEL2_MUTATED_SUMMARY")
        require(summary.startswith(expected_prefix),
                f"expected a {expected_prefix} line for mutation {arguments.mutation!r}, got: {summary}")

        passed, total = (int(part) for part in summary.split()[1].split("/"))

        # Before anything about pass or fail: the denominator, checked against
        # a number that lives out here rather than one the app chose.
        require(total == EXPECTED_STEPS,
                f"the run reported {total} steps and this program expects {EXPECTED_STEPS}.\n"
                "      The set of level 2 steps changed. Update EXPECTED_STEPS in\n"
                "      packages/example-app/level-two/run_level_two.py in the same commit that\n"
                "      changed it -- this failing until you do is the point.")

        # And that every promised step actually reported a verdict. The app
        # reconciles its own results against its own list; this checks the same
        # thing from outside, so a harness that printed a summary without
        # printing the checks behind it cannot pass either.
        verdicts = [line for line in lines if line.startswith("LEVEL2_CHECK ")]
        require(len(verdicts) == EXPECTED_STEPS,
                f"the run printed {len(verdicts)} LEVEL2_CHECK lines for a summary of "
                f"{total}; expected {EXPECTED_STEPS}.")

        if arguments.mutation == "none":
            require(passed == total, f"{total - passed} step(s) failed. See the FAIL lines above.")
            log(f"PASS: every one of the {total} steps passed, through the published surface")
        else:
            target = MUTATIONS[arguments.mutation]
            red = [line for line in lines
                   if line.startswith(f"LEVEL2_CHECK {target} FAIL")]
            require(bool(red),
                    f"mutation {arguments.mutation!r} was applied but {target!r} still passed. "
                    "The control it sabotages proves nothing.")
            require(passed < total, "a mutated run reported every step passing")
            log(f"PASS (mutation): {arguments.mutation} turned {target} red, as it must")

    finally:
        report = []
        if conductor is not None:
            report.append(f"conductor stopped after {conductor.ops_served} op(s)")
            conductor.stop()
        if counterparty is not None and counterparty.client is not None and loop is not None:
            # The app asks the counterparty to log itself out as part of its
            # own teardown. This is the fallback for the runs where it never
            # got that far -- the counterparty is exactly the thing that may
            # have died, so this does not depend on it having survived.
            try:
                asyncio.run_coroutine_threadsafe(
                    counterparty.op_quit({}), loop).result(timeout=60)
                report.append("counterparty logged out")
            except Exception:  # noqa: BLE001 -- teardown must not raise
                report.append("counterparty did not log out cleanly")
        if loop is not None:
            loop.call_soon_threadsafe(loop.stop)
            if loop_thread is not None:
                loop_thread.join(timeout=10)

        # The load-bearing one. Everything the run created -- both accounts,
        # every device, every access token, the room and its history -- lives
        # inside this container and nowhere else, so removing it is a
        # complete teardown rather than a list of things to remember.
        device_gone = None
        if homeserver is not None and library_device is not None:
            # Asked before the container goes: "the app revoked its own
            # token" is the app's claim, and this checks it from outside.
            try:
                token, _, _ = homeserver.login(
                    LIBRARY_LOCALPART, passwords[LIBRARY_LOCALPART], "level-two-facade-audit")
                status, body = homeserver.call("GET", "/_matrix/client/v3/devices", token)
                device_gone = status == 200 and all(
                    device.get("device_id") != library_device
                    for device in body.get("devices", []))
            except Exception:  # noqa: BLE001 -- teardown must not raise
                device_gone = None
        remove_container()
        report.append(f"container {CONTAINER_NAME} removed")
        shutil.rmtree(workdir, ignore_errors=True)
        report.append("temporary directory (nio store, homeserver env file) removed")
        log("teardown: " + "; ".join(report))
        if device_gone is True:
            log("teardown: the run's device was already gone from the homeserver before removal")
        elif device_gone is False:
            log("teardown: WARNING -- the run's device was still present; the app did not revoke it")


if __name__ == "__main__":
    try:
        main()
    except RunFailed as failure:
        log(f"FAIL: {failure}")
        sys.exit(1)
