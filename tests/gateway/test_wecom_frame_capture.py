"""Tests for the env-gated WeCom callback frame capture hook (F6.1 evidence).

The hook is default-off; when requested it writes raw inbound callback frames
verbatim, and any requested-but-failed capture blocks the live run instead of
silently producing unrecorded callbacks.
"""

import json
import os
import stat
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

# The capture hook is POSIX-only by design (dirfd, O_NOFOLLOW, file modes);
# the production code fail-closes elsewhere, and these tests exercise
# symlinks and POSIX modes that CONTRIBUTING.md rules 8-9 exclude on Windows.
pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Frame capture requires POSIX dirfd and file modes",
)

CANARY = "CANARY-SECRET-MARKER-9f3a"
CAPTURE_ENV_VAR = "YOUPET_WECOM_FRAME_CAPTURE_DIR"


def _adapter(extra=None):
    from gateway.config import PlatformConfig
    from gateway.platforms.wecom import WeComAdapter

    return WeComAdapter(PlatformConfig(enabled=True, extra=extra or {}))


def _make_capture_dir(tmp_path, mode=0o700, name="capture"):
    path = tmp_path / name
    path.mkdir()
    os.chmod(path, mode)
    return path


def _frame_capture(monkeypatch, capture_dir, **kwargs):
    from gateway.platforms.wecom_frame_capture import FrameCapture

    monkeypatch.setenv(CAPTURE_ENV_VAR, str(capture_dir))
    return FrameCapture(**kwargs)


def _adapter_with_capture(monkeypatch, tmp_path, **capture_kwargs):
    capture_dir = _make_capture_dir(tmp_path)
    monkeypatch.setenv(CAPTURE_ENV_VAR, str(capture_dir))
    adapter = _adapter()
    if capture_kwargs:
        adapter._frame_capture.close()
        from gateway.platforms.wecom_frame_capture import FrameCapture

        adapter._frame_capture = FrameCapture(**capture_kwargs)
    return adapter, capture_dir


class _FakeWs:
    def __init__(self, frames):
        self._frames = list(frames)
        self.closed = False

    async def receive(self):
        return self._frames.pop(0)


CALLBACK_RAW = (
    '{"cmd":"aibot_msg_callback","headers":{"req_id":"req-1"},'
    '"body":{"msgid":"m-1","from":{"userid":"u-1"},'
    '"text":{"content":"hi"}}}'
)


class TestDefaultOff:
    def test_env_unset_disables_capture(self, monkeypatch, tmp_path):
        monkeypatch.delenv(CAPTURE_ENV_VAR, raising=False)
        capture_dir = _make_capture_dir(tmp_path)
        from gateway.platforms.wecom_frame_capture import FrameCapture

        capture = FrameCapture()

        assert capture.enabled is False
        assert capture.requested is False
        assert capture.capture('{"cmd":"aibot_msg_callback"}') is False
        # Zero behavior change: the would-be directory is never consulted.
        assert list(capture_dir.iterdir()) == []

    def test_adapter_capture_helper_passes_through_when_off(self, monkeypatch):
        monkeypatch.delenv(CAPTURE_ENV_VAR, raising=False)
        adapter = _adapter()

        allowed = adapter._capture_callback_frame(
            '{"cmd":"aibot_msg_callback"}', {"cmd": "aibot_msg_callback"}
        )

        assert allowed is True  # default-off must never drop live callbacks
        assert adapter._frame_capture.enabled is False
        assert adapter._frame_capture.captured_count == 0


class TestCallbackOnlyGating:
    @pytest.mark.parametrize("cmd", ["aibot_msg_callback", "aibot_callback"])
    def test_callback_commands_are_captured(self, monkeypatch, tmp_path, cmd):
        adapter, capture_dir = _adapter_with_capture(monkeypatch, tmp_path)
        raw = '{"cmd": "%s", "body": {"text": {"content": "x"}}}' % cmd

        assert adapter._capture_callback_frame(raw, json.loads(raw)) is True

        assert len(list(capture_dir.iterdir())) == 1

    @pytest.mark.parametrize(
        "payload",
        [
            {"cmd": "ping"},
            {"cmd": "aibot_event_callback"},
            {"cmd": "aibot_send_msg"},
            {"cmd": "aibot_subscribe"},
            {"errcode": 0, "headers": {"req_id": "send-1"}},
        ],
    )
    def test_non_callback_frames_are_never_captured(self, monkeypatch, tmp_path, payload):
        adapter, capture_dir = _adapter_with_capture(monkeypatch, tmp_path)

        assert adapter._capture_callback_frame(json.dumps(payload), payload) is True

        assert list(capture_dir.iterdir()) == []


class TestRawByteFidelity:
    def test_written_bytes_match_wire_bytes(self, monkeypatch, tmp_path):
        adapter, capture_dir = _adapter_with_capture(monkeypatch, tmp_path)
        # Whitespace and key order a json.dumps round-trip would destroy.
        raw = '{  "cmd":"aibot_msg_callback", "body": {"b":1,  "a":2} }'

        assert adapter._capture_callback_frame(raw, json.loads(raw)) is True

        (path,) = capture_dir.iterdir()
        assert path.read_bytes() == raw.encode("utf-8")

    def test_bytes_input_written_verbatim(self, monkeypatch, tmp_path):
        capture_dir = _make_capture_dir(tmp_path)
        capture = _frame_capture(monkeypatch, capture_dir)
        raw = b'{"cmd":"aibot_msg_callback","body":{"x":"\xe4\xbd\xa0"}}'

        assert capture.capture(raw) is True

        (path,) = capture_dir.iterdir()
        assert path.read_bytes() == raw


class TestFileHygiene:
    def test_files_are_created_0600(self, monkeypatch, tmp_path):
        capture_dir = _make_capture_dir(tmp_path)
        capture = _frame_capture(monkeypatch, capture_dir)

        assert capture.capture('{"cmd":"aibot_msg_callback"}') is True

        (path,) = capture_dir.iterdir()
        assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600

    def test_hostile_umask_still_yields_0600(self, monkeypatch, tmp_path):
        capture_dir = _make_capture_dir(tmp_path)
        capture = _frame_capture(monkeypatch, capture_dir)
        previous = os.umask(0o777)
        try:
            assert capture.capture('{"cmd":"aibot_msg_callback"}') is True
        finally:
            os.umask(previous)

        (path,) = capture_dir.iterdir()
        assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600

    def test_filenames_carry_no_identifiers(self, monkeypatch, tmp_path):
        capture_dir = _make_capture_dir(tmp_path)
        capture = _frame_capture(monkeypatch, capture_dir)
        raw = (
            '{"cmd":"aibot_msg_callback","body":{"msgid":"%s",'
            '"chatid":"chat-%s","from":{"userid":"user-%s"}}}'
            % (CANARY, CANARY, CANARY)
        )

        assert capture.capture(raw) is True

        (path,) = capture_dir.iterdir()
        assert CANARY not in path.name
        basename, dot, suffix = path.name.partition(".")
        assert suffix == "json" and dot == "."
        seq, dash, uniq = basename.removeprefix("frame-").partition("-")
        assert basename.startswith("frame-") and dash == "-"
        assert seq.isdigit() and len(uniq) == 8


class TestDirectoryValidation:
    def test_missing_dir_disables_capture(self, monkeypatch, tmp_path, caplog):
        monkeypatch.setenv(CAPTURE_ENV_VAR, str(tmp_path / ("nope-" + CANARY)))
        from gateway.platforms.wecom_frame_capture import FrameCapture

        capture = FrameCapture()

        assert capture.enabled is False
        assert capture.requested is True
        assert capture.capture('{"cmd":"aibot_msg_callback"}') is False
        assert "dir-missing" in caplog.text
        assert CANARY not in caplog.text  # the operator path is not logged

    def test_empty_env_value_rejected(self, monkeypatch, caplog):
        monkeypatch.setenv(CAPTURE_ENV_VAR, "")
        from gateway.platforms.wecom_frame_capture import FrameCapture

        capture = FrameCapture()

        assert capture.requested is True
        assert capture.enabled is False
        assert "dir-empty" in caplog.text

    def test_relative_dir_rejected(self, monkeypatch, caplog):
        monkeypatch.setenv(CAPTURE_ENV_VAR, "relative/capture")
        from gateway.platforms.wecom_frame_capture import FrameCapture

        assert FrameCapture().enabled is False
        assert "dir-not-absolute" in caplog.text

    def test_symlink_dir_rejected(self, monkeypatch, tmp_path, caplog):
        real = _make_capture_dir(tmp_path, name="real")
        link = tmp_path / "link"
        link.symlink_to(real)
        monkeypatch.setenv(CAPTURE_ENV_VAR, str(link))
        from gateway.platforms.wecom_frame_capture import FrameCapture

        assert FrameCapture().enabled is False
        assert "dir-symlink" in caplog.text

    def test_file_path_rejected(self, monkeypatch, tmp_path, caplog):
        file_path = tmp_path / "not-a-dir"
        file_path.write_text("x")
        monkeypatch.setenv(CAPTURE_ENV_VAR, str(file_path))
        from gateway.platforms.wecom_frame_capture import FrameCapture

        assert FrameCapture().enabled is False
        assert "dir-not-directory" in caplog.text

    @pytest.mark.parametrize("mode", [0o750, 0o705, 0o777])
    def test_group_or_world_accessible_dir_rejected(
        self, monkeypatch, tmp_path, caplog, mode
    ):
        capture_dir = _make_capture_dir(tmp_path, mode=mode)
        monkeypatch.setenv(CAPTURE_ENV_VAR, str(capture_dir))
        from gateway.platforms.wecom_frame_capture import FrameCapture

        assert FrameCapture().enabled is False
        assert "dir-not-owner-only" in caplog.text

    def test_non_writable_owner_only_dir_rejected_at_init(
        self, monkeypatch, tmp_path, caplog
    ):
        capture_dir = _make_capture_dir(tmp_path, mode=0o500)
        capture = _frame_capture(monkeypatch, capture_dir)

        assert capture.requested is True
        assert capture.enabled is False
        assert "dir-not-writable" in caplog.text
        assert list(capture_dir.iterdir()) == []

    def test_non_owned_dir_rejected(self, monkeypatch, tmp_path, caplog):
        capture_dir = _make_capture_dir(tmp_path)
        monkeypatch.setenv(CAPTURE_ENV_VAR, str(capture_dir))
        monkeypatch.setattr(
            "gateway.platforms.wecom_frame_capture._current_uid",
            lambda: os.lstat(capture_dir).st_uid + 1,
        )
        from gateway.platforms.wecom_frame_capture import FrameCapture

        assert FrameCapture().enabled is False
        assert "dir-not-owned" in caplog.text


class TestLimits:
    def test_oversize_frame_skipped_with_label_only_log(
        self, monkeypatch, tmp_path, caplog
    ):
        capture_dir = _make_capture_dir(tmp_path)
        capture = _frame_capture(monkeypatch, capture_dir, max_frame_bytes=16)
        raw = '{"cmd":"aibot_msg_callback","big":"%s"}' % CANARY

        assert capture.capture(raw) is False

        assert list(capture_dir.iterdir()) == []
        assert "frame-oversize" in caplog.text
        assert CANARY not in caplog.text

    def test_count_limit_stops_capture_and_logs_once(
        self, monkeypatch, tmp_path, caplog
    ):
        capture_dir = _make_capture_dir(tmp_path)
        capture = _frame_capture(monkeypatch, capture_dir, max_frames=2)

        assert capture.capture('{"cmd":"aibot_msg_callback","n":1}') is True
        assert capture.capture('{"cmd":"aibot_msg_callback","n":2}') is True
        assert capture.capture('{"cmd":"aibot_msg_callback","n":3}') is False
        assert capture.capture('{"cmd":"aibot_msg_callback","n":4}') is False

        assert len(list(capture_dir.iterdir())) == 2
        assert caplog.text.count("capture-limit-reached") == 1


class TestPartialWrite:
    def test_failed_write_leaves_no_fragment(self, monkeypatch, tmp_path, caplog):
        capture_dir = _make_capture_dir(tmp_path)
        capture = _frame_capture(monkeypatch, capture_dir)
        real_write = os.write
        calls = {"n": 0}

        def flaky_write(fd, data):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_write(fd, data[:5])
            raise OSError("injected write failure")

        monkeypatch.setattr(os, "write", flaky_write)
        raw = '{"cmd":"aibot_msg_callback","body":"%s"}' % CANARY

        assert capture.capture(raw) is False

        # Neither the final name nor the staging file may survive.
        assert list(capture_dir.iterdir()) == []
        assert "frame-write-error" in caplog.text
        assert CANARY not in caplog.text


class TestDirectoryReplacement:
    def test_replacing_validated_dir_cannot_redirect_writes(
        self, monkeypatch, tmp_path
    ):
        capture_dir = _make_capture_dir(tmp_path)
        capture = _frame_capture(monkeypatch, capture_dir)
        moved = tmp_path / "moved"
        capture_dir.rename(moved)
        attacker = tmp_path / "attacker"
        attacker.mkdir()
        os.symlink(attacker, capture_dir)  # original path now a symlink

        assert capture.capture('{"cmd":"aibot_msg_callback"}') is True

        # The write is inode-bound: it lands in the moved directory and never
        # through the replacement symlink.
        assert list(attacker.iterdir()) == []
        assert len(list(moved.iterdir())) == 1
        capture.close()


class TestPublishSafety:
    @pytest.mark.asyncio
    async def test_probe_unlink_failure_keeps_capture_disabled(
        self, monkeypatch, tmp_path, caplog
    ):
        import gateway.platforms.wecom as wecom_module

        capture_dir = _make_capture_dir(tmp_path)
        monkeypatch.setenv(CAPTURE_ENV_VAR, str(capture_dir))
        monkeypatch.setattr(wecom_module, "AIOHTTP_AVAILABLE", True)
        monkeypatch.setattr(wecom_module, "HTTPX_AVAILABLE", True)

        def failing_unlink(*args, **kwargs):
            raise OSError("injected unlink failure")

        # The platform probe compares os.unlink by identity against
        # os.supports_dir_fd, so forcing the fault in also needs the platform
        # check pinned to True — the target here is the writability probe.
        monkeypatch.setattr(
            "gateway.platforms.wecom_frame_capture._capture_platform_supported",
            lambda: True,
        )
        monkeypatch.setattr(os, "unlink", failing_unlink)
        from gateway.platforms.wecom_frame_capture import FrameCapture

        capture = FrameCapture()

        # Probe success requires the full create→fchmod→close→unlink chain;
        # an unlink failure must not yield a false success.
        assert capture.requested is True
        assert capture.enabled is False
        assert "dir-not-writable" in caplog.text
        # Residue is left for the run's residue-free gate to catch.
        assert [p.name for p in capture_dir.iterdir() if p.name.startswith(".write-probe-")]

        adapter = _adapter({"bot_id": "bot-1", "secret": "secret-1"})
        assert await adapter.connect() is False
        assert adapter.fatal_error_code == "wecom_frame_capture_dir_invalid"

    def test_preexisting_staging_is_never_unlinked(self, monkeypatch, tmp_path):
        capture_dir = _make_capture_dir(tmp_path)
        monkeypatch.setattr(
            "gateway.platforms.wecom_frame_capture.uuid",
            SimpleNamespace(uuid4=lambda: SimpleNamespace(hex="0123456789abcdef")),
        )
        capture = _frame_capture(monkeypatch, capture_dir)
        sentinel = capture_dir / ".frame-0001-01234567.json.tmp"
        sentinel.write_text("sentinel-staging")

        # O_EXCL fails on the sentinel; the error path must not unlink a
        # staging file this invocation did not create.
        assert capture.capture('{"cmd":"aibot_msg_callback"}') is False

        assert sentinel.read_text() == "sentinel-staging"
        assert list(capture_dir.iterdir()) == [sentinel]

    def test_preexisting_final_is_never_overwritten(self, monkeypatch, tmp_path):
        capture_dir = _make_capture_dir(tmp_path)
        monkeypatch.setattr(
            "gateway.platforms.wecom_frame_capture.uuid",
            SimpleNamespace(uuid4=lambda: SimpleNamespace(hex="0123456789abcdef")),
        )
        capture = _frame_capture(monkeypatch, capture_dir)
        sentinel = capture_dir / "frame-0001-01234567.json"
        sentinel.write_text("older-evidence")

        # Publish is no-clobber: os.link fails EEXIST instead of POSIX
        # rename's silent replace.
        assert capture.capture('{"cmd":"aibot_msg_callback"}') is False

        assert sentinel.read_bytes() == b"older-evidence"
        # Our own staging link was cleaned up; only the sentinel remains.
        assert list(capture_dir.iterdir()) == [sentinel]

    def test_staging_unlink_failure_is_degraded_success(
        self, monkeypatch, tmp_path, caplog
    ):
        capture_dir = _make_capture_dir(tmp_path)
        capture = _frame_capture(monkeypatch, capture_dir)
        real_unlink = os.unlink

        def flaky_unlink(name, **kwargs):
            if str(name).endswith(".tmp"):
                raise OSError("injected unlink failure")
            return real_unlink(name, **kwargs)

        # Patch after construction so the init probe ran unimpeded.
        monkeypatch.setattr(os, "unlink", flaky_unlink)
        raw = '{"cmd":"aibot_msg_callback"}'

        # The publish (hard link) already succeeded: evidence is durable, so
        # the capture counts as a degraded success and stays observable.
        assert capture.capture(raw) is True
        assert capture.captured_count == 1

        finals = [p for p in capture_dir.iterdir() if p.name.startswith("frame-")]
        stagings = [p for p in capture_dir.iterdir() if p.name.endswith(".tmp")]
        assert len(finals) == 1
        assert finals[0].read_bytes() == raw.encode("utf-8")
        assert len(stagings) == 1  # residue the run's residue-free gate must catch
        assert "staging-unlink-failed" in caplog.text


class TestCaptureRequestedConnectGate:
    @pytest.mark.asyncio
    async def test_invalid_capture_dir_blocks_connect(self, monkeypatch, tmp_path):
        import gateway.platforms.wecom as wecom_module

        monkeypatch.setattr(wecom_module, "AIOHTTP_AVAILABLE", True)
        monkeypatch.setattr(wecom_module, "HTTPX_AVAILABLE", True)
        monkeypatch.setenv(CAPTURE_ENV_VAR, str(tmp_path / "missing"))
        adapter = _adapter({"bot_id": "bot-1", "secret": "secret-1"})

        assert await adapter.connect() is False
        assert adapter.fatal_error_code == "wecom_frame_capture_dir_invalid"

    @pytest.mark.asyncio
    async def test_empty_capture_env_blocks_connect(self, monkeypatch):
        import gateway.platforms.wecom as wecom_module

        monkeypatch.setattr(wecom_module, "AIOHTTP_AVAILABLE", True)
        monkeypatch.setattr(wecom_module, "HTTPX_AVAILABLE", True)
        monkeypatch.setenv(CAPTURE_ENV_VAR, "")
        adapter = _adapter({"bot_id": "bot-1", "secret": "secret-1"})

        assert await adapter.connect() is False
        assert adapter.fatal_error_code == "wecom_frame_capture_dir_invalid"

    @pytest.mark.asyncio
    async def test_non_writable_capture_dir_blocks_connect(
        self, monkeypatch, tmp_path
    ):
        import gateway.platforms.wecom as wecom_module

        monkeypatch.setattr(wecom_module, "AIOHTTP_AVAILABLE", True)
        monkeypatch.setattr(wecom_module, "HTTPX_AVAILABLE", True)
        monkeypatch.setenv(
            CAPTURE_ENV_VAR, str(_make_capture_dir(tmp_path, mode=0o500))
        )
        adapter = _adapter({"bot_id": "bot-1", "secret": "secret-1"})

        assert await adapter.connect() is False
        assert adapter.fatal_error_code == "wecom_frame_capture_dir_invalid"

    @pytest.mark.asyncio
    async def test_platform_without_dirfd_support_blocks_connect(
        self, monkeypatch, tmp_path, caplog
    ):
        import gateway.platforms.wecom as wecom_module

        monkeypatch.setattr(wecom_module, "AIOHTTP_AVAILABLE", True)
        monkeypatch.setattr(wecom_module, "HTTPX_AVAILABLE", True)
        monkeypatch.setattr(
            "gateway.platforms.wecom_frame_capture._capture_platform_supported",
            lambda: False,
        )
        monkeypatch.setenv(CAPTURE_ENV_VAR, str(_make_capture_dir(tmp_path)))
        adapter = _adapter({"bot_id": "bot-1", "secret": "secret-1"})

        assert adapter._frame_capture.requested is True
        assert adapter._frame_capture.enabled is False
        assert "platform-unsupported" in caplog.text
        assert await adapter.connect() is False
        assert adapter.fatal_error_code == "wecom_frame_capture_dir_invalid"


class TestDispatchGating:
    @pytest.mark.asyncio
    async def test_callback_dropped_when_capture_channel_lost(
        self, monkeypatch, tmp_path, caplog
    ):
        import aiohttp

        adapter, capture_dir = _adapter_with_capture(monkeypatch, tmp_path)
        adapter._frame_capture.close()  # simulate a lost capture channel at runtime
        adapter._dispatch_payload = AsyncMock()
        adapter._ws = _FakeWs(
            [
                SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=CALLBACK_RAW),
                SimpleNamespace(type=aiohttp.WSMsgType.CLOSED, data=None),
            ]
        )
        adapter._running = True

        with pytest.raises(RuntimeError, match="closed"):
            await adapter._read_events()

        adapter._dispatch_payload.assert_not_awaited()
        assert list(capture_dir.iterdir()) == []
        assert "capture-requested-but-failed" in caplog.text

    @pytest.mark.asyncio
    async def test_callback_dropped_when_capture_limit_exhausted(
        self, monkeypatch, tmp_path
    ):
        import aiohttp

        adapter, capture_dir = _adapter_with_capture(monkeypatch, tmp_path, max_frames=0)
        adapter._dispatch_payload = AsyncMock()
        adapter._ws = _FakeWs(
            [
                SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=CALLBACK_RAW),
                SimpleNamespace(type=aiohttp.WSMsgType.CLOSED, data=None),
            ]
        )
        adapter._running = True

        with pytest.raises(RuntimeError, match="closed"):
            await adapter._read_events()

        adapter._dispatch_payload.assert_not_awaited()
        assert list(capture_dir.iterdir()) == []


class TestReadEventsWiring:
    @pytest.mark.asyncio
    async def test_read_events_captures_callback_only(self, monkeypatch, tmp_path):
        import aiohttp

        adapter, capture_dir = _adapter_with_capture(monkeypatch, tmp_path)
        adapter._on_message = AsyncMock()
        adapter._ws = _FakeWs(
            [
                SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data=CALLBACK_RAW),
                SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data='{"cmd":"ping"}'),
                SimpleNamespace(
                    type=aiohttp.WSMsgType.TEXT,
                    data='{"errcode":0,"headers":{"req_id":"send-1"}}',
                ),
                SimpleNamespace(type=aiohttp.WSMsgType.CLOSED, data=None),
            ]
        )
        adapter._running = True

        with pytest.raises(RuntimeError, match="closed"):
            await adapter._read_events()

        (path,) = capture_dir.iterdir()
        assert path.read_bytes() == CALLBACK_RAW.encode("utf-8")
        adapter._on_message.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_read_events_skips_unparseable_without_capture(
        self, monkeypatch, tmp_path
    ):
        import aiohttp

        adapter, capture_dir = _adapter_with_capture(monkeypatch, tmp_path)
        adapter._dispatch_payload = AsyncMock()
        adapter._ws = _FakeWs(
            [
                SimpleNamespace(type=aiohttp.WSMsgType.TEXT, data="not-json"),
                SimpleNamespace(type=aiohttp.WSMsgType.CLOSED, data=None),
            ]
        )
        adapter._running = True

        with pytest.raises(RuntimeError, match="closed"):
            await adapter._read_events()

        assert list(capture_dir.iterdir()) == []
        adapter._dispatch_payload.assert_not_awaited()
