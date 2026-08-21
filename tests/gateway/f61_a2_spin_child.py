"""Subprocess child for the F6.1 A2-03 no-yield-spin regression tests.

Not a pytest module: the parent tests run this file under sys.executable
with an OS-level deadline, because the failure class under test — a
no-yield hot loop in the WeCom listen path — starves every in-process
watchdog: asyncio.wait_for timeouts are event-loop callbacks and never
fire, and live SIGINT was observed swallowed (2026-08-16 v2 incident).
Only the parent process can bound it.

Subcommands:
  driver-lifecycle  one send-disconnect attempt against the REAL
                    WeComAdapter lifecycle (real _listen_loop parked in a
                    fake socket's receive); prints ONE JSON report line:
                    the driver record plus post-attempt lifecycle state
                    (listen task, socket, session, running flag).
  listen-spin       run the REAL _listen_loop against an already-closed
                    socket with reopen always failing. Pre-fix this is a
                    silent 100%-CPU spin (zero log lines); post-fix it is
                    a paced reconnect path (periodic "WebSocket error"
                    warnings on stderr) the parent observes, then
                    terminates with SIGTERM.
"""

import asyncio
import importlib.util
import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

_spec = importlib.util.spec_from_file_location(
    "f61_a2_driver", REPO_ROOT / "scripts" / "f61_a2_driver.py"
)
driver = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(driver)

import aiohttp  # noqa: E402

from gateway.config import PlatformConfig  # noqa: E402
from gateway.platforms.wecom import WeComAdapter  # noqa: E402


class FakeWs:
    """Stand-in for aiohttp.ClientWebSocketResponse; never touches network.

    receive() parks until close() is called, then reports CLOSED — the
    same interleaving the live adapter saw when the driver closed the
    socket under a parked listener.
    """

    def __init__(self, closed=False):
        self.closed = closed
        self.sent = []
        self.receive_entered = False
        self._close_seen = asyncio.Event()

    async def send_json(self, payload):
        self.sent.append(payload)

    async def receive(self):
        self.receive_entered = True
        await self._close_seen.wait()
        return SimpleNamespace(type=aiohttp.WSMsgType.CLOSED, data=None)

    async def close(self):
        self.closed = True
        self._close_seen.set()


def _adapter() -> WeComAdapter:
    adapter = WeComAdapter(
        PlatformConfig(
            enabled=True, extra={"bot_id": "synthetic", "secret": "synthetic"}
        )
    )
    adapter._youpet_bridge = None  # the driver never bridges Core
    return adapter


async def driver_lifecycle() -> None:
    adapter = _adapter()
    ws = FakeWs()
    adapter._ws = ws
    adapter._running = True
    adapter._open_connection = driver._no_reconnect  # same wiring as run()
    adapter._listen_task = asyncio.create_task(adapter._listen_loop())
    for _ in range(200):  # bounded wait: listener parked in receive()
        if ws.receive_entered:
            break
        await asyncio.sleep(0.01)
    result = await driver.attempt_send_disconnect(adapter, chat_id="t", content="hi")
    print(
        json.dumps(
            {
                "result": result,
                "receive_entered": ws.receive_entered,
                "listen_task_is_none": adapter._listen_task is None,
                "ws_is_none": adapter._ws is None,
                "running": adapter._running,
                "session_is_none": adapter._session is None,
                "heartbeat_task_is_none": adapter._heartbeat_task is None,
                "pending_empty": adapter._pending_responses == {},
            },
            sort_keys=True,
            default=str,
        ),
        flush=True,
    )


async def listen_spin() -> None:
    adapter = _adapter()
    adapter._ws = FakeWs(closed=True)  # peer-closed socket under a running loop
    adapter._running = True

    async def fail_reopen(*_args, **_kwargs):
        raise RuntimeError("reconnect unavailable in test")

    adapter._open_connection = fail_reopen
    await adapter._listen_loop()


def main() -> None:
    logging.basicConfig(level=logging.INFO)  # adapter warnings land on stderr
    if sys.argv[1] == "driver-lifecycle":
        asyncio.run(driver_lifecycle())
    elif sys.argv[1] == "listen-spin":
        asyncio.run(listen_spin())
    else:
        raise SystemExit(f"unknown subcommand {sys.argv[1]}")


if __name__ == "__main__":
    main()
