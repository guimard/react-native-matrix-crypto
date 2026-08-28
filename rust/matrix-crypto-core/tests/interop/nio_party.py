#!/usr/bin/env python3
"""The third-party counterparty for level 2 interoperability (design doc section 8).

# Why this file is Python and not Rust

Level 1 (`tests/two_parties.rs`) drives a second `matrix_sdk_crypto::OlmMachine`
directly, so both parties run the same protocol state machine this library
holds. A consistent misreading of the Matrix E2EE spec passes that test
cleanly. `matrix-nio` implements its own Olm/Megolm session lifecycle, device
tracking and key-sharing decisions in Python, so it has to agree with us on
the wire without sharing the code that produces either side of it.

The independence is at the protocol level, not all the way down: nio 0.26.0
moved its ratchet from libolm to `vodozemac`, which is the same crate
`matrix-sdk-crypto` uses (`rust/Cargo.lock`: vodozemac 0.10.0). A defect
inside `vodozemac` itself would pass both sides. Everything above it -- event
shapes, `/keys/*` payloads, to-device routing, the megolm event body -- is two
independent implementations agreeing or not.

# Protocol

Newline-delimited JSON on stdin, one JSON reply per line on stdout. The Rust
test owns the sequencing; this process only does what it is told, so a failure
is attributable to a step rather than to a race between two long-running
clients.

Nothing is ever printed outside that protocol, and nothing is written to disk
except nio's own crypto store, in a temporary directory the caller supplies
and removes.

# Credentials

The password arrives in the environment (`MATRIX_INTEROP_PASSWORD`) and is
read once, into a local, at login. It is never written to a file, never echoed
into a reply, and never placed on a command line, where `ps` would show it.
"""

import asyncio
import json
import os
import sys
import traceback

from nio import (
    AsyncClient,
    AsyncClientConfig,
    LoginResponse,
    MegolmEvent,
    RoomSendResponse,
)

# nio marks every device it has not verified as unverified, and refuses by
# default to send a room key to one. M2 verifies nothing on either side -- our
# own outbound half is `CollectStrategy::AllDevices` for the same reason (spec
# section 7.2) -- so the counterparty is held to the same standard rather than
# a stricter one it would fail on. This is the nio-side mirror of that
# decision, named here rather than passed silently at the call site.
IGNORE_UNVERIFIED = True


class Party:
    def __init__(self):
        self.client = None

    async def op_login(self, cmd):
        homeserver = os.environ["MATRIX_INTEROP_HOMESERVER"]
        user_id = os.environ["MATRIX_INTEROP_USER"]
        store_path = os.environ["MATRIX_INTEROP_NIO_STORE"]
        password = os.environ["MATRIX_INTEROP_PASSWORD"]

        self.client = AsyncClient(
            homeserver,
            user_id,
            store_path=store_path,
            config=AsyncClientConfig(
                encryption_enabled=True,
                store_sync_tokens=False,
                request_timeout=60,
                max_timeouts=3,
            ),
        )
        response = await self.client.login(
            password, device_name="level-two-interop-nio"
        )
        del password
        if not isinstance(response, LoginResponse):
            return {"ok": False, "error": f"login failed: {response}"}

        await self.settle(rounds=3)
        return {
            "ok": True,
            "user_id": self.client.user_id,
            "device_id": self.client.device_id,
        }

    async def settle(self, rounds=3, timeout_ms=1000):
        """One turn of nio's own key pump: sync, publish keys, query devices.

        `AsyncClient.sync_forever` does this internally; a bare `sync` does
        not, and this test drives every step explicitly so an unpublished key
        is a visible missing step rather than a silent absence.
        """
        for _ in range(rounds):
            await self.client.sync(timeout=timeout_ms, full_state=False)
            if self.client.should_upload_keys:
                await self.client.keys_upload()
            if self.client.should_query_keys:
                await self.client.keys_query()

    async def op_settle(self, cmd):
        await self.settle(rounds=int(cmd.get("rounds", 3)))
        return {"ok": True}

    async def op_send(self, cmd):
        """nio encrypts and sends. Direction 2 of the proof."""
        response = await self.client.room_send(
            cmd["room_id"],
            "m.room.message",
            {"msgtype": "m.text", "body": cmd["body"]},
            ignore_unverified_devices=IGNORE_UNVERIFIED,
        )
        if not isinstance(response, RoomSendResponse):
            return {"ok": False, "error": f"send failed: {response}"}
        return {"ok": True, "event_id": response.event_id}

    async def op_collect(self, cmd):
        """Sync until the named events have arrived, and report what nio made of each.

        `event_ids` is everything to observe; `require_decrypted` is the
        subset that must actually decrypt before this returns early. Both are
        needed in one call because a sync token only advances forwards: an
        event consumed by one `collect` is not offered to the next, so the
        deliberately corrupted control event has to be watched in the same
        call as the intact one it is the control for.

        An event that is still a `MegolmEvent` after the sync that carried it
        is retried on every later round, because the room key can arrive in a
        later sync than the message it unlocks. So "not decrypted" here means
        nio kept failing for the whole window with the key already in hand --
        which is what the corrupted control must produce, and what an intact
        event must not.
        """
        room_id = cmd["room_id"]
        wanted = set(cmd["event_ids"])
        must_decrypt = set(cmd.get("require_decrypted", []))
        deadline = asyncio.get_event_loop().time() + float(cmd.get("timeout_s", 90))

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
                            "decrypted": True,
                            "type": type(event).__name__,
                            "body": getattr(event, "body", None),
                            "retried": False,
                        }

            for event_id, event in list(pending.items()):
                try:
                    decrypted = self.client.decrypt_event(event)
                    done[event_id] = {
                        "decrypted": True,
                        "type": type(decrypted).__name__,
                        "body": getattr(decrypted, "body", None),
                        "retried": True,
                    }
                    pending.pop(event_id)
                except Exception as error:  # noqa: BLE001 -- reported, not handled
                    reasons[event_id] = f"{type(error).__name__}: {error}"

        for event_id in pending:
            done[event_id] = {
                "decrypted": False,
                "type": "MegolmEvent",
                "reason": reasons.get(event_id, "never attempted"),
            }

        return {
            "ok": True,
            "events": done,
            "missing": sorted(wanted - set(done)),
        }

    async def op_quit(self, cmd):
        if self.client is not None:
            # Logged out, not merely closed: this device's access token must
            # not outlive the test run. The device itself goes with it.
            try:
                await self.client.logout()
            finally:
                await self.client.close()
        return {"ok": True}


async def main():
    party = Party()
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin
    )

    while True:
        line = await reader.readline()
        if not line:
            return
        command = json.loads(line)
        op = command.get("op")
        handler = getattr(party, f"op_{op}", None)
        if handler is None:
            reply = {"ok": False, "error": f"unknown op {op!r}"}
        else:
            try:
                reply = await handler(command)
            except Exception:  # noqa: BLE001 -- the Rust side asserts on this
                reply = {"ok": False, "error": traceback.format_exc(limit=8)}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
        if op == "quit":
            return


if __name__ == "__main__":
    asyncio.run(main())
