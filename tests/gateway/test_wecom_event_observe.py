"""Tests for the env-gated WeCom event-callback observation point (A1-07).

The observation point sits before the silent return of the
``aibot_event_callback`` branch in ``_dispatch_payload``. It emits exactly
one whitelist label per event when YOUPET_WECOM_EVENT_OBSERVE is enabled,
and is a strict no-op otherwise.
"""

import logging
from unittest.mock import AsyncMock

import pytest

OBSERVE_ENV_VAR = "YOUPET_WECOM_EVENT_OBSERVE"
CANARY = "CANARY-SECRET-MARKER-7d2f"


def _adapter():
    from gateway.config import PlatformConfig
    from gateway.platforms.wecom import WeComAdapter

    return WeComAdapter(PlatformConfig(enabled=True))


class TestDefaultOff:
    @pytest.mark.asyncio
    async def test_unset_env_produces_no_log_and_no_behavior_change(
        self, monkeypatch, caplog
    ):
        monkeypatch.delenv(OBSERVE_ENV_VAR, raising=False)
        adapter = _adapter()
        payload = {
            "cmd": "aibot_event_callback",
            "body": {"event_type": "disconnected_event", "reason": CANARY},
        }
        with caplog.at_level(logging.INFO):
            result = await adapter._dispatch_payload(payload)
        assert result is None
        assert "event_class" not in caplog.text
        assert CANARY not in caplog.text

    @pytest.mark.asyncio
    async def test_zero_value_counts_as_off(self, monkeypatch, caplog):
        monkeypatch.setenv(OBSERVE_ENV_VAR, "0")
        adapter = _adapter()
        payload = {"cmd": "aibot_event_callback", "body": {"event_type": "disconnected_event"}}
        with caplog.at_level(logging.INFO):
            await adapter._dispatch_payload(payload)
        assert "event_class" not in caplog.text


class TestDisconnectedEvent:
    @pytest.mark.asyncio
    async def test_official_wire_shape_logs_exactly_one_whitelist_line(
        self, monkeypatch, caplog
    ):
        monkeypatch.setenv(OBSERVE_ENV_VAR, "1")
        adapter = _adapter()
        # Canonical shape per the official long-connection document.
        payload = {
            "cmd": "aibot_event_callback",
            "headers": {"req_id": CANARY},
            "body": {
                "msgid": CANARY,
                "create_time": 1700000000,
                "aibotid": CANARY,
                "msgtype": "event",
                "event": {"eventtype": "disconnected_event"},
            },
        }
        with caplog.at_level(logging.INFO):
            await adapter._dispatch_payload(payload)
        assert caplog.text.count("event_class=disconnected_event") == 1
        assert CANARY not in caplog.text

    @pytest.mark.asyncio
    async def test_enter_chat_official_shape_gets_own_label(self, monkeypatch, caplog):
        monkeypatch.setenv(OBSERVE_ENV_VAR, "1")
        adapter = _adapter()
        payload = {
            "cmd": "aibot_event_callback",
            "body": {
                "msgid": CANARY,
                "msgtype": "event",
                "event": {"eventtype": "enter_chat"},
            },
        }
        with caplog.at_level(logging.INFO):
            await adapter._dispatch_payload(payload)
        assert caplog.text.count("event_class=enter_chat") == 1
        assert CANARY not in caplog.text


class TestFalsePositiveGuards:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "payload",
        [
            # top-level lookalike only
            {"cmd": "aibot_event_callback", "event_type": "disconnected_event"},
            # flat body-level lookalike, not the documented nested path
            {
                "cmd": "aibot_event_callback",
                "body": {"msgtype": "event", "event_type": "disconnected_event"},
            },
            # nested value but the msgtype guard fails
            {
                "cmd": "aibot_event_callback",
                "body": {
                    "msgtype": "text",
                    "event": {"eventtype": "disconnected_event"},
                },
            },
            # event present but not a mapping
            {
                "cmd": "aibot_event_callback",
                "body": {"msgtype": "event", "event": "disconnected_event"},
            },
            # generic type field must not match
            {
                "cmd": "aibot_event_callback",
                "body": {"msgtype": "event", "type": "disconnected_event"},
            },
        ],
    )
    async def test_noncanonical_shapes_classify_other(
        self, monkeypatch, caplog, payload
    ):
        monkeypatch.setenv(OBSERVE_ENV_VAR, "1")
        adapter = _adapter()
        with caplog.at_level(logging.INFO):
            await adapter._dispatch_payload(payload)
        assert "event_class=other" in caplog.text
        assert "event_class=disconnected_event" not in caplog.text


class TestOtherEvents:
    @pytest.mark.asyncio
    async def test_unknown_event_logs_other_without_values(self, monkeypatch, caplog):
        monkeypatch.setenv(OBSERVE_ENV_VAR, "1")
        adapter = _adapter()
        payload = {
            "cmd": "aibot_event_callback",
            "body": {"event_type": f"custom_{CANARY}", "detail": CANARY},
        }
        with caplog.at_level(logging.INFO):
            await adapter._dispatch_payload(payload)
        assert "event_class=other" in caplog.text
        assert "event_class=disconnected_event" not in caplog.text
        assert CANARY not in caplog.text

    @pytest.mark.asyncio
    @pytest.mark.parametrize("body", [None, "weird", 42, ["list"]])
    async def test_malformed_body_logs_fixed_label_without_crash(
        self, monkeypatch, caplog, body
    ):
        monkeypatch.setenv(OBSERVE_ENV_VAR, "1")
        adapter = _adapter()
        payload = {"cmd": "aibot_event_callback", "body": body}
        with caplog.at_level(logging.INFO):
            await adapter._dispatch_payload(payload)
        assert "event_class=other" in caplog.text

    @pytest.mark.asyncio
    async def test_secret_shaped_values_never_logged(self, monkeypatch, caplog):
        monkeypatch.setenv(OBSERVE_ENV_VAR, "1")
        adapter = _adapter()
        payload = {"cmd": "aibot_event_callback", "body": {"secret": CANARY}}
        with caplog.at_level(logging.INFO):
            await adapter._dispatch_payload(payload)
        assert "event_class=other" in caplog.text
        assert CANARY not in caplog.text


class TestNonEventFramesUnaffected:
    @pytest.mark.asyncio
    async def test_message_callback_routes_normally_with_no_event_log(
        self, monkeypatch, caplog
    ):
        monkeypatch.setenv(OBSERVE_ENV_VAR, "1")
        adapter = _adapter()
        adapter._on_message = AsyncMock()
        with caplog.at_level(logging.INFO):
            await adapter._dispatch_payload({"cmd": "aibot_msg_callback", "body": {"msgid": "m"}})
        adapter._on_message.assert_awaited_once()
        assert "event_class" not in caplog.text

    @pytest.mark.asyncio
    async def test_ping_produces_no_event_log(self, monkeypatch, caplog):
        monkeypatch.setenv(OBSERVE_ENV_VAR, "1")
        adapter = _adapter()
        with caplog.at_level(logging.INFO):
            await adapter._dispatch_payload({"cmd": "ping"})
        assert "event_class" not in caplog.text
