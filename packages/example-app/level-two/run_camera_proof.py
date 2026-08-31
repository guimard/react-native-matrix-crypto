#!/usr/bin/env python3
"""The one claim no in-process test can make, set up for a person to make.

WHAT THIS IS FOR

Everything else about verification by scanning a code is proven by tests:
the core drives all three modes against a bare upstream machine
(`rust/matrix-crypto-core/tests/qr_*.rs`), and
`rust/matrix-crypto-core/tests/level_two_scanned.rs` drives them against a
mautrix-go counterparty over a real homeserver. Not one of those points a
camera at a screen. **A foreign scanner reading the symbol this library
renders is the claim that matters most for a product whose users will scan
with whatever client they already have, and it is the one claim a process
cannot make about itself.**

So this program does everything up to the moment a person is needed, and
then stops and says what to do. It starts a throwaway homeserver, logs the
phone in, hands the app a run plan, launches it, and prints the steps. The
app then draws a real code, produced by `getVerificationCode` on the
published TypeScript surface, and waits.

IT ASSERTS NOTHING, ON PURPOSE

Every other runner in this repository ends in an assertion. This one cannot:
what it is arranging is a person looking at two screens, and a program that
claimed to have checked that would be claiming something it did not see. It
prints what the person should see at each point instead, and leaves the
verdict to them.

WHAT THE PERSON NEEDS

  * an Android device or emulator on `adb`;
  * a release APK of this example app;
  * a second Matrix client **that can scan a QR code**, signed in to the
    same account on the homeserver this program starts.

    **Element Web and Element Desktop cannot.** Both show a code and both
    can be scanned, but neither offers a scanner, so neither can play this
    half of the flow. An earlier version of this file said they worked.
    Finding out that they do not cost a session, and it is written here so
    that it costs nobody another one.

    What has actually done it: **Element Classic 1.6.62** on Android, on a
    second emulator whose back camera was a USB webcam pointed at the
    screen showing the code. Any mobile client with a working scanner
    should do. Only that one has been observed, and this file does not
    claim more than it saw.

    That second client has to reach the homeserver too, and this program
    deliberately does not arrange it. It runs `adb reverse` for the one
    device it installs the app on and for nothing else: a second emulator
    needs its own `adb reverse`, and a physical phone needs the container
    reachable from the network that phone is on.

CREDENTIALS

One account, created inside a container that does not outlive this program,
with a password generated per run. **That password is printed**, and that is
a deliberate difference from every sibling here: the person has to type it
into another client, so a program that hid it would be unusable. It names an
account on a homeserver bound to loopback that is destroyed on exit. Nothing
is read from a file, an environment secret or a CI secret, and nothing
outlives the run.
"""

import argparse
import atexit
import http.server
import json
import os
import shutil
import signal
import socketserver
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reused rather than reimplemented: the container bring-up, the account
# creation, the sweeps and the adb helpers are the level 2 conductor's, and a
# second copy of them would be a second thing to keep correct. This module
# imports cleanly -- everything it does at import time is constants.
from run_level_two import (  # noqa: E402
    CONDUCTOR_PORT,
    DEFAULT_APK,
    LIBRARY_LOCALPART,
    NIO_LOCALPART,
    PACKAGE,
    SERVER_NAME,
    RunFailed,
    adb,
    install_and_launch,
    log,
    port_is_free,
    remove_container,
    require,
    start_homeserver,
    sweep_containers,
    sweep_workdirs,
)

import secrets  # noqa: E402


class PlanServer:
    """Serves one run plan on the host's loopback, and nothing else.

    The level 2 conductor's own server also relays counterparty operations.
    There is no counterparty here -- the other side is a person with a
    client of their own -- so this is the plan and a 404 for everything else.
    """

    def __init__(self, plan):
        self.plan = plan
        self.server = None

    def start(self):
        plan = self.plan

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 -- BaseHTTPRequestHandler's own naming
                if self.path != "/plan":
                    self.send_error(404)
                    return
                encoded = json.dumps(plan).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_args):
                """Silent: a request line is one more place a path could land."""

        # 127.0.0.1, not 0.0.0.0. The device reaches it through `adb reverse`,
        # so binding wider would expose the access token in the plan to the
        # network for nothing.
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", CONDUCTOR_PORT), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


def announce(homeserver_port, password, user_id):
    """What the person does, and what they should see at each point."""
    print()
    print("=" * 72)
    print("  THE CAMERA PROOF IS SET UP. THE REST IS YOURS.")
    print("=" * 72)
    print()
    print("  The phone is logged in and the app is running. It is now waiting")
    print("  for another client on the same account to start a verification.")
    print()
    print("  1. On your SECOND CLIENT, one that can scan a QR code, sign in:")
    print()
    print(f"       homeserver   http://127.0.0.1:{homeserver_port}")
    print(f"       account      {user_id}")
    print(f"       password     {password}")
    print()
    print("     Element will ask you to pick a custom homeserver. Paste the URL")
    print("     above; it does not resolve a .well-known and does not need to.")
    print()
    print("     IT MUST BE ABLE TO SCAN. Element Web and Element Desktop cannot:")
    print("     they show a code and can be scanned, but neither has a scanner.")
    print("     Element Classic 1.6.62 on Android has done this; that is the one")
    print("     that has been observed, on an emulator with a webcam as its back")
    print("     camera. A second emulator needs its own `adb reverse` to reach")
    print("     the homeserver, which this program does not arrange for it.")
    print()
    print("     THE ACCOUNT IS BRAND NEW AND HAS NO SIGNING IDENTITY. A code")
    print("     carries cross-signing keys, so none can exist until the account")
    print("     has one, and this app cannot create it: it has no authentication")
    print("     loop. Let Element create it. When it offers to set up recovery,")
    print("     or to verify this session, accept, and let it finish before")
    print("     going on. If the phone says `identity_not_known` at step 2, this")
    print("     is the step that has not happened.")
    print()
    print("  2. Element will offer to verify its new session. Skip that: it is")
    print("     asking about ITSELF. Instead open Settings, Sessions, find the")
    print("     session whose name is the phone, and choose Verify.")
    print()
    print("     ON THE PHONE you should see the headline change from")
    print('       \"Waiting for your other client to start a verification.\"')
    print('     to "Point the other client\u2019s camera at this code."')
    print("     and a black-and-white square appear. If the phone instead says")
    print("     it cannot show a code, the kind it names is the whole answer:")
    print("     `identity_not_known` means this account has published no signing")
    print("     identity yet, and `code_not_offered` means the other client did")
    print("     not offer to scan.")
    print()
    print("  3. In Element, choose \"Scan QR code\" and point the camera at the")
    print("     phone. Fill the viewfinder with the square and hold still.")
    print()
    print("     ON THE PHONE the headline becomes")
    print('       \"The other device says it scanned this code.\"')
    print("     and a green button appears. That is the moment the protocol")
    print("     exists for: nothing has been verified yet, and the person is")
    print("     being asked whether the device that scanned was really theirs.")
    print()
    print("  4. Press the green button on the phone.")
    print()
    print("     ON THE PHONE the headline becomes \"Verified.\" and the square")
    print("     disappears. ON ELEMENT the session is marked verified.")
    print()
    print("     THAT IS THE PROOF. A camera that has never seen this code read")
    print("     what this library drew, and the flow completed.")
    print()
    print("  IF IT DOES NOT SCAN, that is a finding rather than a nuisance, and")
    print("  it is worth writing down which of these it was: the camera never")
    print("  locked on (the symbol is too small, too dim, or the screen is too")
    print("  reflective), or it locked on and Element rejected what it read.")
    print("  The second is the one that matters: it would mean the bytes drawn")
    print("  are not the bytes meant.")
    print()
    print("  Press Ctrl-C here when you are done. The homeserver, the account")
    print("  and everything on it are destroyed on the way out.")
    print()
    sys.stdout.flush()


def stream_app_log():
    """Prints what the app says, so the terminal shows the same story.

    Never a value: the app's own screen carries the identifiers, and this
    stream is only here so the operator can see progress without holding the
    phone up to their face.
    """
    process = None
    try:
        import subprocess

        process = subprocess.Popen(
            ["adb", "logcat", "-v", "raw", "ReactNativeJS:V", "*:S"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        for line in process.stdout:
            if line.startswith("SCANNED_CODE"):
                print(f"  [phone] {line.rstrip()}", flush=True)
    except KeyboardInterrupt:
        raise
    finally:
        if process is not None:
            process.terminate()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apk", default=DEFAULT_APK)
    arguments = parser.parse_args()

    require(shutil.which("docker") is not None, "docker is not on PATH")
    require(shutil.which("adb") is not None, "adb is not on PATH")
    require(os.path.isfile(arguments.apk) and os.path.getsize(arguments.apk) > 0,
            f"no APK at {arguments.apk!r}. Build one first:\n"
            "      (cd packages/example-app/android && "
            "./gradlew :app:assembleRelease -PreactNativeArchitectures=<abi>)")
    require(port_is_free(CONDUCTOR_PORT),
            f"something is already listening on 127.0.0.1:{CONDUCTOR_PORT}, which is the "
            "port the app asks for its run plan on")

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    atexit.register(remove_container)

    swept_containers = sweep_containers()
    swept_workdirs = sweep_workdirs()
    if swept_containers or swept_workdirs:
        log(f"swept {swept_containers} orphaned container(s) and "
            f"{swept_workdirs} orphaned temporary director(ies) from an earlier run")

    workdir = tempfile.mkdtemp(prefix="rnmc-level-two-")
    atexit.register(shutil.rmtree, workdir, True)
    # Two accounts because `start_homeserver` creates two; only the first is
    # used here, and the second is left alone rather than given a job it does
    # not have.
    # `token_hex`, not `token_urlsafe`. The url-safe alphabet contains `-`,
    # the account is created by handing this string to the homeserver's admin
    # command inside the container, and its parser reads a leading `-` as a
    # flag: roughly one run in thirty died at account creation with an error
    # about an unknown option. Hex has no such character, and it is what
    # `scripts/run-level-two-interop.sh` has always used. A person also has
    # to type this one into another client by hand, and hex is kinder to type
    # than a url-safe string with case and punctuation in it.
    passwords = {
        LIBRARY_LOCALPART: secrets.token_hex(24),
        NIO_LOCALPART: secrets.token_hex(24),
    }
    plan_server = None
    try:
        homeserver, homeserver_port = start_homeserver(workdir, passwords)
        token, user_id, device_id = homeserver.login(
            LIBRARY_LOCALPART, passwords[LIBRARY_LOCALPART], "camera-proof-phone")
        log("the phone's account is logged in")

        # `adb reverse` rather than the emulator's 10.0.2.2 alias, so the same
        # command works for a real device on a cable and for an emulator. The
        # app tries 10.0.2.2 first and 127.0.0.1 second, and this makes the
        # second reach this host either way.
        require(adb("reverse", f"tcp:{CONDUCTOR_PORT}", f"tcp:{CONDUCTOR_PORT}").returncode == 0,
                "adb reverse for the plan port failed; is a device connected?")
        require(adb("reverse", f"tcp:{homeserver_port}", f"tcp:{homeserver_port}").returncode == 0,
                "adb reverse for the homeserver port failed")
        atexit.register(lambda: adb("reverse", "--remove-all"))

        plan = {
            "mode": "scanned-code",
            "homeserver": f"http://127.0.0.1:{homeserver_port}",
            "conductor": f"http://127.0.0.1:{CONDUCTOR_PORT}",
            "userId": user_id,
            "deviceId": device_id,
            "accessToken": token,
            # The level 2 plan's remaining fields, empty rather than absent:
            # the app's own type carries them, and a plan that dropped them
            # would be a second shape for a reader to hold in their head.
            "roomId": "",
            "nioUserId": "",
            "mutation": "none",
        }
        plan_server = PlanServer(plan)
        plan_server.start()
        log(f"the run plan is being served on 127.0.0.1:{CONDUCTOR_PORT}")

        install_and_launch(arguments.apk)
        log("the app is installed and running")
        # Long enough for the app to fetch the plan, create its machine and
        # publish its keys before the person is told to go and look at it.
        time.sleep(8)

        announce(homeserver_port, passwords[LIBRARY_LOCALPART], user_id)
        stream_app_log()
    except KeyboardInterrupt:
        print()
        log("stopping at your request")
    except RunFailed as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    finally:
        if plan_server is not None:
            plan_server.stop()
        adb("shell", "am", "force-stop", PACKAGE)
        remove_container()
        shutil.rmtree(workdir, ignore_errors=True)
        log(f"the homeserver and the account on it are gone ({SERVER_NAME})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
