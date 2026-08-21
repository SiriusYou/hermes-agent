"""Tests for explicit Core outbox poll ownership and the F6.1 A2-04 fault hook.

The poll owner is selected by ``YOUPET_OUTBOX_POLL_OWNER``
(``wecom`` | ``wecom_callback`` | ``none``). Illegal values, duplicate
polling bridges, or arming the send-fault hook on a non-owner or inert
surface must fail closed. The fault hook exists so the A2-04
transient-transport-failure evidence run can inject exactly two bounded send
failures before a real recovery send through the Core delivery ledger.

Attempt logs use a safe, message-embedded contract: fixed enums, counts, and
per-process aliases only — never raw delivery/event UUIDs or provider error
text — because the production formatter persists ``%(message)s`` only.
"""

from __future__ import annotations

import asyncio
import logging
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.integrations import youpet as youpet_module
from gateway.integrations.youpet import (
    FAULT_INJECTION_ERROR_LABEL,
    MAX_ATTEMPT_TRACKED_DELIVERIES,
    YouPetBridge,
    YouPetBridgeError,
    YouPetBridgeSettings,
    apply_outbox_poll_owner,
    build_youpet_bridge_from_env,
    youpet_settings_from_env,
)
from gateway.platforms.base import SendResult


class FakeResponse:
    def __init__(self, data=None, status_code=200, text=""):
        self._data = data or {}
        self.status_code = status_code
        self.text = text

    def json(self):
        return self._data


class FakeCoreClient:
    def __init__(self, outbox_items=None):
        self.outbox_items = outbox_items or []
        self.get_calls = []
        self.post_calls = []

    async def get(self, url, **kwargs):
        self.get_calls.append({"url": url, **kwargs})
        return FakeResponse({"items": self.outbox_items})

    async def post(self, url, **kwargs):
        self.post_calls.append({"url": url, **kwargs})
        return FakeResponse({"ok": True})

    async def aclose(self):
        pass


@pytest.fixture(autouse=True)
def _clear_poll_owner_registry():
    youpet_module._ACTIVE_POLL_OWNERS.clear()
    yield
    youpet_module._ACTIVE_POLL_OWNERS.clear()


def _settings(**overrides):
    values = {
        "enabled": True,
        "core_base_url": "http://youpet-core.test",
        "service_token": "service-token",
        "outbox_poll_enabled": False,
        "outbox_limit": 10,
    }
    values.update(overrides)
    return YouPetBridgeSettings(**values)


def _escalated_item(event_id, business_event_id, attempts):
    return {
        "event_id": event_id,
        "event_type": "task.escalated",
        "attempts": attempts,
        "payload": {
            "event_id": business_event_id,
            "event_type": "task.escalated",
            "payload": {
                "task_id": "task-1",
                "alert_id": "alert-1",
                "alert_type": "missed_checkin",
                "severity": "high",
                "recipient_user_id": "user-1",
                "summary": "WECOM-LC-A204-MARKER",
            },
        },
    }


def _enable_bridge_env(monkeypatch):
    monkeypatch.setenv("YOUPET_WECOM_BRIDGE_ENABLED", "true")
    monkeypatch.setenv("YOUPET_CORE_BASE_URL", "http://youpet-core.test")
    monkeypatch.setenv("YOUPET_SERVICE_TOKEN", "service-token")


def _attempt_fields(record):
    """Parse the message-embedded k=v fields of an outbox_send_attempt line."""
    return dict(re.findall(r"(\w+)=([^\s]+)", record.getMessage()))


class AsyncMockSend:
    async def __call__(self, chat_id, content):
        return SendResult(success=True)


class TestPollOwnerResolution:
    def test_default_owner_is_wecom_callback(self, monkeypatch):
        monkeypatch.delenv("YOUPET_OUTBOX_POLL_OWNER", raising=False)
        _enable_bridge_env(monkeypatch)
        settings = youpet_settings_from_env()
        assert settings.outbox_poll_owner == "wecom_callback"

    def test_owner_accepts_wecom_and_none(self, monkeypatch):
        _enable_bridge_env(monkeypatch)
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", "wecom")
        assert youpet_settings_from_env().outbox_poll_owner == "wecom"
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", "none")
        assert youpet_settings_from_env().outbox_poll_owner == "none"

    def test_illegal_owner_fails_closed(self, monkeypatch):
        _enable_bridge_env(monkeypatch)
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", "both")
        with pytest.raises(YouPetBridgeError) as exc_info:
            youpet_settings_from_env()
        assert "both" not in str(exc_info.value)

    def test_apply_owner_disables_callback_poll_when_wecom_owns(self):
        settings = apply_outbox_poll_owner(
            _settings(outbox_poll_enabled=True, outbox_poll_owner="wecom"),
            "wecom_callback",
        )
        assert settings.outbox_poll_enabled is False

    def test_apply_owner_enables_wecom_poll_when_wecom_owns(self):
        settings = apply_outbox_poll_owner(
            _settings(outbox_poll_enabled=True, outbox_poll_owner="wecom"),
            "wecom",
        )
        assert settings.outbox_poll_enabled is True

    def test_apply_owner_none_disables_every_adapter(self):
        for adapter in ("wecom", "wecom_callback"):
            settings = apply_outbox_poll_owner(
                _settings(outbox_poll_enabled=True, outbox_poll_owner="none"),
                adapter,
            )
            assert settings.outbox_poll_enabled is False

    def test_legacy_default_keeps_callback_polling(self):
        settings = apply_outbox_poll_owner(
            _settings(outbox_poll_enabled=True, outbox_poll_owner="wecom_callback"),
            "wecom_callback",
        )
        assert settings.outbox_poll_enabled is True

    def test_callback_builder_respects_owner_env(self, monkeypatch):
        _enable_bridge_env(monkeypatch)
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", "wecom")
        send = AsyncMockSend()
        bridge = build_youpet_bridge_from_env(send)
        assert bridge is not None
        assert bridge.settings.outbox_poll_enabled is False

        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", "wecom_callback")
        bridge = build_youpet_bridge_from_env(send)
        assert bridge is not None
        assert bridge.settings.outbox_poll_enabled is True


class TestDuplicatePollOwnerGuard:
    @pytest.mark.asyncio
    async def test_second_polling_bridge_start_fails_closed(self):
        send = AsyncMockSend()
        first = YouPetBridge(
            _settings(outbox_poll_enabled=True, outbox_poll_interval_seconds=60.0),
            send,
        )
        second = YouPetBridge(
            _settings(outbox_poll_enabled=True, outbox_poll_interval_seconds=60.0),
            send,
        )
        first._client = FakeCoreClient()

        await first.start()
        try:
            with pytest.raises(YouPetBridgeError):
                await second.start()
            # Rejection happens before any allocation: no client, no task,
            # no owner claim survives the failed start.
            assert second._client is None
            assert second._poll_task is None
            assert second._poll_owner_claimed is False
            assert youpet_module._ACTIVE_POLL_OWNERS == {"wecom_callback"}
        finally:
            await first.stop()

    @pytest.mark.asyncio
    async def test_poll_task_creation_failure_rolls_back_everything(self, monkeypatch):
        send = AsyncMockSend()
        bridge = YouPetBridge(
            _settings(outbox_poll_enabled=True, outbox_poll_interval_seconds=60.0),
            send,
        )

        real_create_task = asyncio.create_task

        def failing_create_task(coro, *args, **kwargs):
            if "poll" in getattr(coro, "__qualname__", ""):
                raise RuntimeError("simulated create_task failure")
            return real_create_task(coro, *args, **kwargs)

        monkeypatch.setattr(youpet_module.asyncio, "create_task", failing_create_task)

        with pytest.raises(RuntimeError, match="simulated create_task failure"):
            await bridge.start()

        assert youpet_module._ACTIVE_POLL_OWNERS == set()
        assert bridge._poll_task is None
        assert bridge._poll_owner_claimed is False
        assert bridge._client is None

    @pytest.mark.asyncio
    async def test_stopped_owner_releases_ownership(self):
        send = AsyncMockSend()
        first = YouPetBridge(
            _settings(outbox_poll_enabled=True, outbox_poll_interval_seconds=60.0),
            send,
        )
        first._client = FakeCoreClient()
        await first.start()
        await first.stop()

        second = YouPetBridge(
            _settings(outbox_poll_enabled=True, outbox_poll_interval_seconds=60.0),
            send,
        )
        second._client = FakeCoreClient()
        await second.start()
        await second.stop()


class TestFaultInjectionEnv:
    def test_fault_hook_requires_wecom_owner(self, monkeypatch):
        _enable_bridge_env(monkeypatch)
        monkeypatch.setenv("YOUPET_WECOM_SEND_FAULT_INJECTIONS", "2")
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", "wecom_callback")
        with pytest.raises(YouPetBridgeError) as exc_info:
            youpet_settings_from_env()
        assert "2" not in str(exc_info.value)

    def test_fault_hook_parses_for_wecom_owner(self, monkeypatch):
        _enable_bridge_env(monkeypatch)
        monkeypatch.setenv("YOUPET_WECOM_SEND_FAULT_INJECTIONS", "2")
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", "wecom")
        settings = youpet_settings_from_env()
        assert settings.fault_inject_send_failures == 2

    def test_fault_hook_rejects_non_integer(self, monkeypatch):
        _enable_bridge_env(monkeypatch)
        monkeypatch.setenv("YOUPET_WECOM_SEND_FAULT_INJECTIONS", "soon")
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", "wecom")
        with pytest.raises(YouPetBridgeError) as exc_info:
            youpet_settings_from_env()
        assert "soon" not in str(exc_info.value)

    def test_fault_hook_rejects_negative(self, monkeypatch):
        _enable_bridge_env(monkeypatch)
        monkeypatch.setenv("YOUPET_WECOM_SEND_FAULT_INJECTIONS", "-1")
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", "wecom")
        with pytest.raises(YouPetBridgeError):
            youpet_settings_from_env()

    def test_fault_hook_defaults_off(self, monkeypatch):
        _enable_bridge_env(monkeypatch)
        monkeypatch.delenv("YOUPET_WECOM_SEND_FAULT_INJECTIONS", raising=False)
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", "wecom")
        assert youpet_settings_from_env().fault_inject_send_failures == 0

    def test_callback_builder_never_arms_fault_hook(self, monkeypatch):
        _enable_bridge_env(monkeypatch)
        monkeypatch.setenv("YOUPET_WECOM_SEND_FAULT_INJECTIONS", "2")
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", "wecom")
        bridge = build_youpet_bridge_from_env(AsyncMockSend())
        assert bridge is not None
        assert bridge.settings.fault_inject_send_failures == 0


class TestFaultInjectionInertArming:
    """Arming on a poller that can never run must fail closed at parse time."""

    def _parse(self, monkeypatch):
        monkeypatch.setenv("YOUPET_WECOM_SEND_FAULT_INJECTIONS", "2")
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", "wecom")
        return youpet_settings_from_env()

    def test_rejected_when_poll_master_switch_off(self, monkeypatch):
        _enable_bridge_env(monkeypatch)
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_ENABLED", "0")
        with pytest.raises(YouPetBridgeError):
            self._parse(monkeypatch)

    def test_rejected_when_bridge_disabled(self, monkeypatch):
        monkeypatch.delenv("YOUPET_WECOM_BRIDGE_ENABLED", raising=False)
        monkeypatch.setenv("YOUPET_CORE_BASE_URL", "http://youpet-core.test")
        monkeypatch.setenv("YOUPET_SERVICE_TOKEN", "service-token")
        with pytest.raises(YouPetBridgeError):
            self._parse(monkeypatch)

    def test_rejected_without_core_url(self, monkeypatch):
        monkeypatch.setenv("YOUPET_WECOM_BRIDGE_ENABLED", "true")
        monkeypatch.delenv("YOUPET_CORE_BASE_URL", raising=False)
        monkeypatch.setenv("YOUPET_SERVICE_TOKEN", "service-token")
        with pytest.raises(YouPetBridgeError):
            self._parse(monkeypatch)

    def test_rejected_without_service_token(self, monkeypatch):
        monkeypatch.setenv("YOUPET_WECOM_BRIDGE_ENABLED", "true")
        monkeypatch.setenv("YOUPET_CORE_BASE_URL", "http://youpet-core.test")
        monkeypatch.delenv("YOUPET_SERVICE_TOKEN", raising=False)
        with pytest.raises(YouPetBridgeError):
            self._parse(monkeypatch)


class TestFaultInjectionRun:
    @pytest.mark.asyncio
    async def test_armed_hook_injects_two_failures_then_recovers(self, caplog):
        send_calls = []

        async def fake_send(chat_id, content):
            send_calls.append((chat_id, content))
            return SendResult(success=True)

        bridge = YouPetBridge(
            _settings(
                fault_inject_send_failures=2,
                user_chat_map={"user-1": "chat-1"},
            ),
            fake_send,
        )
        client = FakeCoreClient()
        bridge._client = client
        delivery_id = "99999999-9999-4999-8999-999999999999"
        business_event_id = "business-escalation-a204"

        with caplog.at_level(logging.INFO, logger="gateway.integrations.youpet"):
            client.outbox_items = [_escalated_item(delivery_id, business_event_id, 0)]
            first = await bridge.poll_once()
            assert first["nacked"] == 1 and first["sent"] == 0
            assert send_calls == []
            assert client.post_calls[-1]["url"].endswith(f"/outbox/{delivery_id}/nack")
            assert (
                client.post_calls[-1]["json"]["error"] == FAULT_INJECTION_ERROR_LABEL
            )

            client.outbox_items = [_escalated_item(delivery_id, business_event_id, 1)]
            second = await bridge.poll_once()
            assert second["nacked"] == 1 and second["sent"] == 0
            assert send_calls == []

            client.outbox_items = [_escalated_item(delivery_id, business_event_id, 2)]
            third = await bridge.poll_once()
            assert third["sent"] == 1 and third["acked"] == 1
            assert len(send_calls) == 1
            chat_id, content = send_calls[0]
            assert chat_id == "chat-1"
            assert "WECOM-LC-A204-MARKER" in content
            assert client.post_calls[-1]["url"].endswith(f"/outbox/{delivery_id}/ack")

        assert business_event_id in bridge._processed_event_ids

        attempts = [
            record
            for record in caplog.records
            if "outbox_send_attempt" in record.getMessage()
        ]
        assert len(attempts) == 3
        observed = [
            (
                int(fields["core_attempts"]),
                int(fields["transport_ordinal"]),
                fields["outcome"],
            )
            for record in attempts
            for fields in [_attempt_fields(record)]
        ]
        assert observed == [
            (0, 1, "injected_failure"),
            (1, 2, "injected_failure"),
            (2, 3, "sent"),
        ]
        fields = [_attempt_fields(record) for record in attempts]
        aliases = {f["delivery_alias"] for f in fields}
        business_aliases = {f["business_alias"] for f in fields}
        assert len(aliases) == 1
        assert len(business_aliases) == 1
        for record in attempts:
            message = record.getMessage()
            assert delivery_id not in message
            assert business_event_id not in message
        assert fields[0]["error_label"] == FAULT_INJECTION_ERROR_LABEL
        assert fields[1]["error_label"] == FAULT_INJECTION_ERROR_LABEL

    @pytest.mark.asyncio
    async def test_unarmed_hook_sends_normally(self):
        send_calls = []

        async def fake_send(chat_id, content):
            send_calls.append((chat_id, content))
            return SendResult(success=True)

        bridge = YouPetBridge(
            _settings(user_chat_map={"user-1": "chat-1"}),
            fake_send,
        )
        assert bridge.settings.fault_inject_send_failures == 0
        client = FakeCoreClient(
            outbox_items=[_escalated_item("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "biz-1", 0)]
        )
        bridge._client = client

        counts = await bridge.poll_once()
        assert counts["sent"] == 1 and counts["acked"] == 1
        assert len(send_calls) == 1


class TestSendExceptionPath:
    @pytest.mark.asyncio
    async def test_send_exception_logs_one_safe_record_and_still_nacks(self, caplog):
        canary = "CANARY-SECRET-9f3k"

        async def canary_send(chat_id, content):
            raise RuntimeError(canary)

        bridge = YouPetBridge(
            _settings(user_chat_map={"user-1": "chat-1"}),
            canary_send,
        )
        delivery_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        client = FakeCoreClient(
            outbox_items=[_escalated_item(delivery_id, "biz-exc", 0)]
        )
        bridge._client = client

        with caplog.at_level(logging.INFO, logger="gateway.integrations.youpet"):
            counts = await bridge.poll_once()

        assert counts["nacked"] == 1
        attempts = [
            record
            for record in caplog.records
            if "outbox_send_attempt" in record.getMessage()
        ]
        assert len(attempts) == 1
        fields = _attempt_fields(attempts[0])
        assert fields["outcome"] == "failed"
        assert fields["error_label"] == "send_exception"
        for record in caplog.records:
            assert canary not in record.getMessage()
        nack_call = client.post_calls[-1]
        assert nack_call["url"].endswith(f"/outbox/{delivery_id}/nack")
        assert canary not in nack_call["json"]["error"]

    @pytest.mark.asyncio
    async def test_send_rejection_logs_one_safe_record_and_still_nacks(self, caplog):
        canary = "CANARY-SECRET-5h2m"

        async def canary_send(chat_id, content):
            return SendResult(success=False, error=canary)

        bridge = YouPetBridge(
            _settings(user_chat_map={"user-1": "chat-1"}),
            canary_send,
        )
        delivery_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        client = FakeCoreClient(
            outbox_items=[_escalated_item(delivery_id, "biz-reject", 0)]
        )
        bridge._client = client

        with caplog.at_level(logging.INFO, logger="gateway.integrations.youpet"):
            counts = await bridge.poll_once()

        assert counts["nacked"] == 1
        attempts = [
            record
            for record in caplog.records
            if "outbox_send_attempt" in record.getMessage()
        ]
        assert len(attempts) == 1
        fields = _attempt_fields(attempts[0])
        assert fields["outcome"] == "failed"
        assert fields["error_label"] == "send_rejected"
        for record in caplog.records:
            assert canary not in record.getMessage()
        nack_call = client.post_calls[-1]
        assert nack_call["url"].endswith(f"/outbox/{delivery_id}/nack")
        assert nack_call["json"]["error"] == "WeCom send failed: send_rejected"
        assert canary not in nack_call["json"]["error"]


class TestAttemptStateBounds:
    @pytest.mark.asyncio
    async def test_successful_ack_clears_attempt_state(self):
        bridge = YouPetBridge(
            _settings(user_chat_map={"user-1": "chat-1"}),
            AsyncMockSend(),
        )
        delivery_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        client = FakeCoreClient(
            outbox_items=[_escalated_item(delivery_id, "biz-clear", 0)]
        )
        bridge._client = client

        counts = await bridge.poll_once()

        assert counts["acked"] == 1
        assert delivery_id not in bridge._transport_ordinals
        assert delivery_id not in bridge._delivery_aliases
        # The business alias survives the outer delivery's terminal ack: it is
        # evidence of inner-event identity and only bounded by its own cap.
        assert bridge._business_aliases.get("biz-clear") is not None

    @pytest.mark.asyncio
    async def test_business_alias_stable_across_outer_deliveries(self, caplog):
        bridge = YouPetBridge(
            _settings(
                fault_inject_send_failures=1,
                user_chat_map={"user-1": "chat-1"},
            ),
            AsyncMockSend(),
        )
        client = FakeCoreClient()
        bridge._client = client
        business_event_id = "biz-shared"

        with caplog.at_level(logging.INFO, logger="gateway.integrations.youpet"):
            # First outer delivery: injected failure, then recovery + ack.
            client.outbox_items = [_escalated_item("d-1", business_event_id, 0)]
            await bridge.poll_once()
            client.outbox_items = [_escalated_item("d-1", business_event_id, 1)]
            await bridge.poll_once()
            assert "d-1" not in bridge._delivery_aliases
            first_alias = bridge._business_aliases[business_event_id]

            # Second outer delivery of the same inner event is dedup-acked
            # without a send, and must not disturb the retained alias.
            client.outbox_items = [_escalated_item("d-2", business_event_id, 0)]
            counts = await bridge.poll_once()
            assert counts["acked"] == 1 and counts["sent"] == 0
            assert bridge._business_aliases[business_event_id] == first_alias

        attempts = [
            record
            for record in caplog.records
            if "outbox_send_attempt" in record.getMessage()
        ]
        aliases = {
            _attempt_fields(record)["business_alias"] for record in attempts
        }
        assert aliases == {first_alias}

    @pytest.mark.asyncio
    async def test_attempt_state_bounded_with_fifo_eviction(self):
        total = MAX_ATTEMPT_TRACKED_DELIVERIES + 5
        bridge = YouPetBridge(
            _settings(
                # Budget covers the flood plus the survivor re-poll below, so
                # every attempt in this test stays on the injected path.
                fault_inject_send_failures=total + 1,
                user_chat_map={"user-1": "chat-1"},
            ),
            AsyncMockSend(),
        )
        items = [
            _escalated_item(f"delivery-{i:04d}", f"biz-{i:04d}", 0)
            for i in range(total)
        ]
        client = FakeCoreClient(outbox_items=items)
        bridge._client = client

        counts = await bridge.poll_once()

        assert counts["nacked"] == total
        assert len(bridge._transport_ordinals) == MAX_ATTEMPT_TRACKED_DELIVERIES
        assert len(bridge._delivery_aliases) == MAX_ATTEMPT_TRACKED_DELIVERIES
        for i in range(5):
            assert f"delivery-{i:04d}" not in bridge._transport_ordinals
        survivor = f"delivery-{total - 1:04d}"
        assert bridge._transport_ordinals[survivor] == 1

        client.outbox_items = [_escalated_item(survivor, f"biz-{total - 1:04d}", 1)]
        counts = await bridge.poll_once()
        assert counts["nacked"] == 1
        assert bridge._transport_ordinals[survivor] == 2


def _make_wecom_adapter(monkeypatch, *, owner="wecom", http_client=None):
    import gateway.platforms.wecom as wecom_module
    from gateway.config import PlatformConfig
    from gateway.platforms.wecom import WeComAdapter

    monkeypatch.setattr(wecom_module, "AIOHTTP_AVAILABLE", True)
    monkeypatch.setattr(wecom_module, "HTTPX_AVAILABLE", True)
    monkeypatch.setattr(
        wecom_module,
        "httpx",
        SimpleNamespace(AsyncClient=lambda **kwargs: http_client or AsyncMock()),
    )
    monkeypatch.setenv("YOUPET_WECOM_BRIDGE_ENABLED", "true")
    monkeypatch.setenv("YOUPET_CORE_BASE_URL", "http://youpet-core.test")
    monkeypatch.setenv("YOUPET_SERVICE_TOKEN", "service-token")
    monkeypatch.setenv("YOUPET_OUTBOX_POLL_INTERVAL_SECONDS", "60")
    if owner is None:
        monkeypatch.delenv("YOUPET_OUTBOX_POLL_OWNER", raising=False)
    else:
        monkeypatch.setenv("YOUPET_OUTBOX_POLL_OWNER", owner)

    adapter = WeComAdapter(
        PlatformConfig(enabled=True, extra={"bot_id": "bot-1", "secret": "s-1"})
    )
    adapter._open_connection = AsyncMock()
    adapter._listen_loop = AsyncMock()
    adapter._heartbeat_loop = AsyncMock()
    return adapter


class TestWeComAdapterBridgeLifecycle:

    @pytest.mark.asyncio
    async def test_connect_starts_poller_when_wecom_owns(self, monkeypatch):
        adapter = _make_wecom_adapter(monkeypatch, owner="wecom")
        bridge = adapter._youpet_bridge
        assert bridge is not None
        assert bridge.settings.outbox_poll_enabled is True
        bridge._client = FakeCoreClient()

        success = await adapter.connect()
        try:
            assert success is True
            assert bridge._poll_task is not None
            assert youpet_module._ACTIVE_POLL_OWNERS == {"wecom"}
        finally:
            await adapter.disconnect()

        assert bridge._poll_task is None
        assert youpet_module._ACTIVE_POLL_OWNERS == set()

    @pytest.mark.asyncio
    async def test_connect_rolls_back_when_bridge_start_fails(self, monkeypatch):
        adapter = _make_wecom_adapter(monkeypatch, owner="wecom")
        bridge = adapter._youpet_bridge
        assert bridge is not None
        monkeypatch.setattr(
            YouPetBridge,
            "start",
            AsyncMock(side_effect=YouPetBridgeError("simulated duplicate owner")),
        )

        success = await adapter.connect()

        assert success is False
        assert adapter.fatal_error_code == "wecom_connect_error"
        assert bridge._poll_task is None
        assert bridge._poll_owner_claimed is False
        assert youpet_module._ACTIVE_POLL_OWNERS == set()
        assert adapter._listen_task is None
        assert adapter._heartbeat_task is None
        assert adapter._http_client is None
        # Rollback fully confirmed: the original retryable behavior stands.
        assert adapter.fatal_error_retryable is True

    @pytest.mark.asyncio
    async def test_connect_without_ownership_leaves_poller_off(self, monkeypatch):
        adapter = _make_wecom_adapter(monkeypatch, owner=None)
        bridge = adapter._youpet_bridge
        assert bridge is not None
        assert bridge.settings.outbox_poll_enabled is False
        bridge._client = FakeCoreClient()

        success = await adapter.connect()
        try:
            assert success is True
            assert bridge._poll_task is None
            assert youpet_module._ACTIVE_POLL_OWNERS == set()
        finally:
            await adapter.disconnect()


class TestCoreAttemptsValidation:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_attempts",
        ["0\nFORGED_FIELD=CANARY", "2", -1, True, None],
        ids=["newline-string", "plain-string", "negative", "bool", "missing"],
    )
    async def test_invalid_attempts_fail_closed_before_send(self, caplog, bad_attempts):
        send_calls = []

        async def fake_send(chat_id, content):
            send_calls.append((chat_id, content))
            return SendResult(success=True)

        bridge = YouPetBridge(
            _settings(user_chat_map={"user-1": "chat-1"}),
            fake_send,
        )
        item = _escalated_item("ffffffff-ffff-4fff-8fff-ffffffffffff", "biz-bad", 0)
        if bad_attempts is None:
            del item["attempts"]
        else:
            item["attempts"] = bad_attempts
        client = FakeCoreClient(outbox_items=[item])
        bridge._client = client

        with caplog.at_level(logging.INFO, logger="gateway.integrations.youpet"):
            counts = await bridge.poll_once()

        assert counts["nacked"] == 1 and counts["sent"] == 0
        assert send_calls == []
        assert not [
            record
            for record in caplog.records
            if "outbox_send_attempt" in record.getMessage()
        ]
        nack_call = client.post_calls[-1]
        assert nack_call["json"]["error"] == (
            "Core outbox item carried an invalid attempts field"
        )
        for record in caplog.records:
            assert "FORGED_FIELD" not in record.getMessage()


def _make_callback_adapter(monkeypatch, tmp_path):
    from gateway.config import PlatformConfig
    from gateway.platforms.wecom_callback import WecomCallbackAdapter

    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    monkeypatch.setenv("YOUPET_WECOM_BRIDGE_ENABLED", "true")
    monkeypatch.setenv("YOUPET_CORE_BASE_URL", "http://youpet-core.test")
    monkeypatch.setenv("YOUPET_SERVICE_TOKEN", "service-token")
    monkeypatch.delenv("YOUPET_OUTBOX_POLL_OWNER", raising=False)
    return WecomCallbackAdapter(
        PlatformConfig(
            enabled=True,
            extra={
                "mode": "callback",
                "host": "127.0.0.1",
                "port": 0,
                "apps": [
                    {
                        "name": "test-app",
                        "corp_id": "ww1234567890",
                        "corp_secret": "test-secret",
                        "agent_id": "1000002",
                        "token": "test-callback-token",
                        "encoding_aes_key": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
                    }
                ],
            },
        )
    )


class TestWecomCallbackBridgeFailurePath:
    @pytest.mark.asyncio
    async def test_connect_failure_stops_bridge_and_poll_task(
        self, monkeypatch, tmp_path,
    ):
        adapter = _make_callback_adapter(monkeypatch, tmp_path)
        bridge = adapter._youpet_bridge
        assert bridge is not None
        assert bridge.settings.outbox_poll_enabled is True
        monkeypatch.setattr(
            YouPetBridge,
            "start",
            AsyncMock(side_effect=YouPetBridgeError("simulated start failure")),
        )

        success = await adapter.connect()

        assert success is False
        assert bridge._poll_task is None
        assert bridge._poll_owner_claimed is False
        assert bridge._client is None
        assert youpet_module._ACTIVE_POLL_OWNERS == set()
        assert adapter._poll_task is None
        assert adapter._http_client is None
        assert adapter._runner is None
        # Clean rollback preserves the pre-existing transient-failure shape:
        # no fatal state is recorded.
        assert adapter.has_fatal_error is False


class TestAttemptLogPersistsToDisk:
    async def _capture_logs(self, tmp_path, items, *, armed=0):
        """Drive one poll through the real production logging setup."""
        import hermes_logging

        root = logging.getLogger()
        before_handlers = list(root.handlers)
        log_dir = hermes_logging.setup_logging(
            hermes_home=tmp_path,
            log_level="INFO",
            mode="gateway",
            force=True,
        )
        try:
            bridge = YouPetBridge(
                _settings(
                    fault_inject_send_failures=armed,
                    user_chat_map={"user-1": "chat-1"},
                ),
                AsyncMockSend(),
            )
            client = FakeCoreClient(outbox_items=items)
            bridge._client = client

            counts = await bridge.poll_once()

            for handler in logging.getLogger().handlers:
                handler.flush()
            gateway_log = (log_dir / "gateway.log").read_text()
            agent_log = (log_dir / "agent.log").read_text()
            return counts, gateway_log, agent_log
        finally:
            for handler in list(root.handlers):
                if handler not in before_handlers:
                    handler.close()
                    root.removeHandler(handler)
            hermes_logging._logging_initialized = False

    @pytest.mark.asyncio
    async def test_attempt_line_written_through_production_formatter(self, tmp_path):
        delivery_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        business_event_id = "biz-on-disk"
        counts, gateway_log, agent_log = await self._capture_logs(
            tmp_path,
            [_escalated_item(delivery_id, business_event_id, 0)],
            armed=1,
        )

        assert counts["nacked"] == 1
        assert "outbox_send_attempt" in gateway_log
        line = next(
            line for line in gateway_log.splitlines() if "outbox_send_attempt" in line
        )
        for field in (
            "delivery_alias=",
            "business_alias=",
            "event_type=task.escalated",
            "core_attempts=0",
            "transport_ordinal=1",
            "outcome=injected_failure",
            f"error_label={FAULT_INJECTION_ERROR_LABEL}",
        ):
            assert field in line
        assert delivery_id not in gateway_log
        assert business_event_id not in gateway_log
        assert delivery_id not in agent_log

    @pytest.mark.asyncio
    async def test_invalid_attempts_cannot_forge_log_lines(self, tmp_path):
        item = _escalated_item("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "biz-forge", 0)
        item["attempts"] = "0\nFORGED_FIELD=CANARY"

        counts, gateway_log, agent_log = await self._capture_logs(tmp_path, [item])

        assert counts["nacked"] == 1
        assert "outbox_send_attempt" not in gateway_log
        assert "FORGED_FIELD" not in gateway_log
        assert "FORGED_FIELD" not in agent_log
        assert "invalid attempts field" in agent_log


class _ObservedHttpClient:
    def __init__(self, *, fail_close=False):
        self.closed = False
        self._fail_close = fail_close

    async def aclose(self):
        if self._fail_close:
            raise RuntimeError("http-close-fail")
        self.closed = True


class TestWeComAdapterRollbackStages:
    def _adapter_with_fake_ws(self, monkeypatch, http_client=None):
        adapter = _make_wecom_adapter(
            monkeypatch, owner="wecom", http_client=http_client,
        )
        fake_ws = SimpleNamespace(closed=False, close=AsyncMock())

        async def open_ok():
            adapter._ws = fake_ws

        adapter._open_connection = AsyncMock(side_effect=open_ok)
        return adapter, fake_ws

    @pytest.mark.asyncio
    async def test_bridge_stop_failure_does_not_skip_later_stages(
        self, monkeypatch, caplog,
    ):
        http_client = _ObservedHttpClient()
        adapter, fake_ws = self._adapter_with_fake_ws(monkeypatch, http_client)
        monkeypatch.setattr(
            YouPetBridge,
            "start",
            AsyncMock(side_effect=YouPetBridgeError("start-fail")),
        )
        monkeypatch.setattr(
            YouPetBridge,
            "stop",
            AsyncMock(side_effect=RuntimeError("cleanup-fail")),
        )

        with caplog.at_level(logging.WARNING):
            success = await adapter.connect()

        assert success is False
        # Later stages still ran despite the bridge-stop failure.
        assert adapter._listen_task is None
        assert adapter._heartbeat_task is None
        fake_ws.close.assert_awaited_once()
        assert adapter._ws is None
        assert http_client.closed is True
        assert adapter._http_client is None
        assert youpet_module._ACTIVE_POLL_OWNERS == set()
        # Original startup failure preserved; unconfirmed stage reported.
        assert "start-fail" in (adapter.fatal_error_message or "")
        assert "rollback unconfirmed: youpet_bridge" in (
            adapter.fatal_error_message or ""
        )
        # Unconfirmed rollback is a state-machine input: no auto-reconnect.
        assert adapter.fatal_error_retryable is False
        # Cleanup failure payload never logged — fixed stage label only.
        assert "cleanup-fail" not in caplog.text

    @pytest.mark.asyncio
    async def test_http_close_failure_reported_and_ws_still_cleaned(
        self, monkeypatch, caplog,
    ):
        http_client = _ObservedHttpClient(fail_close=True)
        adapter, fake_ws = self._adapter_with_fake_ws(monkeypatch, http_client)
        monkeypatch.setattr(
            YouPetBridge,
            "start",
            AsyncMock(side_effect=YouPetBridgeError("start-fail")),
        )

        with caplog.at_level(logging.WARNING):
            success = await adapter.connect()

        assert success is False
        fake_ws.close.assert_awaited_once()
        assert adapter._ws is None
        # Reference cleared even though the close itself failed.
        assert adapter._http_client is None
        assert "http_client" in (adapter.fatal_error_message or "")
        assert "http-close-fail" not in caplog.text
        assert adapter._youpet_bridge._poll_owner_claimed is False
        assert adapter.fatal_error_retryable is False

    @pytest.mark.asyncio
    async def test_listener_task_failure_reported(self, monkeypatch, caplog):
        http_client = _ObservedHttpClient()
        adapter, fake_ws = self._adapter_with_fake_ws(monkeypatch, http_client)
        adapter._listen_loop = AsyncMock(side_effect=RuntimeError("listen-crash"))

        async def failing_start(_bridge_self):
            # Yield once so the listen task actually runs and crashes before
            # the startup failure lands; otherwise the stage just cancels a
            # pending task and there is nothing to report.
            await asyncio.sleep(0)
            raise YouPetBridgeError("start-fail")

        monkeypatch.setattr(YouPetBridge, "start", failing_start)

        with caplog.at_level(logging.WARNING):
            success = await adapter.connect()

        assert success is False
        assert "listener" in (adapter.fatal_error_message or "")
        assert adapter.fatal_error_retryable is False
        assert adapter._heartbeat_task is None
        fake_ws.close.assert_awaited_once()
        assert http_client.closed is True
        assert "listen-crash" not in caplog.text

    @pytest.mark.asyncio
    async def test_ws_close_failure_does_not_skip_session_close(
        self, monkeypatch, caplog,
    ):
        http_client = _ObservedHttpClient()
        adapter = _make_wecom_adapter(
            monkeypatch, owner="wecom", http_client=http_client,
        )
        fake_ws = SimpleNamespace(
            closed=False,
            close=AsyncMock(side_effect=RuntimeError("ws-close-fail")),
        )
        fake_session = SimpleNamespace(closed=False, close=AsyncMock())

        async def open_ok():
            adapter._ws = fake_ws
            adapter._session = fake_session

        adapter._open_connection = AsyncMock(side_effect=open_ok)
        monkeypatch.setattr(
            YouPetBridge,
            "start",
            AsyncMock(side_effect=YouPetBridgeError("start-fail")),
        )

        with caplog.at_level(logging.WARNING):
            success = await adapter.connect()

        assert success is False
        # The session close runs even though the websocket close failed, and
        # both references are detached regardless.
        fake_ws.close.assert_awaited_once()
        fake_session.close.assert_awaited_once()
        assert adapter._ws is None
        assert adapter._session is None
        # Inner per-resource label plus outer stage label, both fixed.
        assert "ws_close" in caplog.text
        assert "rollback unconfirmed: websocket" in (
            adapter.fatal_error_message or ""
        )
        assert adapter.fatal_error_retryable is False
        assert "ws-close-fail" not in caplog.text


class TestWecomCallbackRollbackStages:
    @pytest.mark.asyncio
    async def test_bridge_stop_failure_still_cleans_poll_runner_http(
        self, monkeypatch, tmp_path, caplog,
    ):
        adapter = _make_callback_adapter(monkeypatch, tmp_path)
        monkeypatch.setattr(
            YouPetBridge,
            "start",
            AsyncMock(side_effect=YouPetBridgeError("start-fail")),
        )
        monkeypatch.setattr(
            YouPetBridge,
            "stop",
            AsyncMock(side_effect=RuntimeError("cleanup-fail")),
        )

        with caplog.at_level(logging.WARNING):
            success = await adapter.connect()

        assert success is False
        assert adapter._poll_task is None
        assert adapter._runner is None
        assert adapter._site is None
        assert adapter._http_client is None
        assert youpet_module._ACTIVE_POLL_OWNERS == set()
        assert "unconfirmed=youpet_bridge" in caplog.text
        assert "cleanup-fail" not in caplog.text
        # Unconfirmed rollback is recorded as a non-retryable fatal state.
        assert adapter.has_fatal_error is True
        assert adapter.fatal_error_code == "wecom_callback_rollback_incomplete"
        assert adapter.fatal_error_retryable is False

    @pytest.mark.asyncio
    async def test_runner_cleanup_failure_reported_and_http_still_closed(
        self, monkeypatch, tmp_path, caplog,
    ):
        import gateway.platforms.wecom_callback as callback_module

        adapter = _make_callback_adapter(monkeypatch, tmp_path)
        monkeypatch.setattr(
            YouPetBridge,
            "start",
            AsyncMock(side_effect=YouPetBridgeError("start-fail")),
        )
        monkeypatch.setattr(
            callback_module.web.AppRunner,
            "cleanup",
            AsyncMock(side_effect=RuntimeError("runner-fail")),
        )

        with caplog.at_level(logging.WARNING):
            success = await adapter.connect()

        assert success is False
        # Reference cleared even though the cleanup itself failed.
        assert adapter._runner is None
        assert adapter._http_client is None
        assert "unconfirmed=runner" in caplog.text
        assert "runner-fail" not in caplog.text
        assert adapter.has_fatal_error is True
        assert adapter.fatal_error_code == "wecom_callback_rollback_incomplete"
        assert adapter.fatal_error_retryable is False


class TestCleanupContractCallers:
    """_cleanup_ws() returns labels; every caller must consume them."""

    @pytest.mark.asyncio
    async def test_open_connection_aborts_before_new_session(
        self, monkeypatch, caplog,
    ):
        import gateway.platforms.wecom as wecom_module
        from gateway.platforms.wecom import (
            WeComAdapter,
            WeComCleanupIncompleteError,
        )

        adapter = _make_wecom_adapter(monkeypatch, owner="wecom")
        adapter._open_connection = WeComAdapter._open_connection.__get__(adapter)
        fake_ws = SimpleNamespace(
            closed=False,
            close=AsyncMock(side_effect=RuntimeError("ws-close-fail")),
        )
        fake_session = SimpleNamespace(closed=False, close=AsyncMock())
        adapter._ws = fake_ws
        adapter._session = fake_session
        session_ctor = MagicMock()
        monkeypatch.setattr(wecom_module.aiohttp, "ClientSession", session_ctor)

        with caplog.at_level(logging.WARNING):
            with pytest.raises(WeComCleanupIncompleteError):
                await adapter._open_connection()

        # Session still closed, but no replacement connection was opened.
        fake_ws.close.assert_awaited_once()
        fake_session.close.assert_awaited_once()
        session_ctor.assert_not_called()
        assert adapter._ws is None
        assert adapter._session is None
        assert "ws-close-fail" not in caplog.text

    @pytest.mark.asyncio
    async def test_connect_non_retryable_when_preconnect_cleanup_fails(
        self, monkeypatch,
    ):
        from gateway.platforms.wecom import WeComAdapter

        adapter = _make_wecom_adapter(monkeypatch, owner="wecom")
        adapter._open_connection = WeComAdapter._open_connection.__get__(adapter)
        adapter._ws = SimpleNamespace(
            closed=False,
            close=AsyncMock(side_effect=RuntimeError("ws-close-fail")),
        )
        adapter._session = SimpleNamespace(closed=False, close=AsyncMock())

        success = await adapter.connect()

        assert success is False
        assert adapter._listen_task is None
        assert adapter._heartbeat_task is None
        assert "rollback unconfirmed: ws_close" in (
            adapter.fatal_error_message or ""
        )
        assert adapter.fatal_error_retryable is False
        assert youpet_module._ACTIVE_POLL_OWNERS == set()

    @pytest.mark.asyncio
    async def test_disconnect_reports_failure_and_continues_cleanup(
        self, monkeypatch, caplog,
    ):
        from gateway.platforms.wecom import WeComCleanupIncompleteError

        adapter = _make_wecom_adapter(monkeypatch, owner="wecom")
        adapter._ws = SimpleNamespace(
            closed=False,
            close=AsyncMock(side_effect=RuntimeError("ws-close-fail")),
        )
        adapter._session = SimpleNamespace(closed=False, close=AsyncMock())
        http_client = _ObservedHttpClient()
        adapter._http_client = http_client
        bridge = adapter._youpet_bridge
        bridge._client = FakeCoreClient()

        with caplog.at_level(logging.INFO):
            with pytest.raises(WeComCleanupIncompleteError):
                await adapter.disconnect()

        # Remaining cleanup still ran after the WS close failure.
        assert http_client.closed is True
        assert adapter._http_client is None
        assert bridge._client is None
        # No successful-disconnect record; fixed labels only.
        assert "Disconnected" not in caplog.text
        assert "unconfirmed=ws_close" in caplog.text
        assert "ws-close-fail" not in caplog.text

    @pytest.mark.asyncio
    async def test_disconnect_success_still_logs_disconnected(
        self, monkeypatch, caplog,
    ):
        adapter = _make_wecom_adapter(monkeypatch, owner="wecom")
        adapter._youpet_bridge._client = FakeCoreClient()

        with caplog.at_level(logging.INFO):
            await adapter.disconnect()

        assert "Disconnected" in caplog.text


class TestListenLoopCleanupGate:
    @pytest.mark.asyncio
    async def test_cleanup_incomplete_is_terminal_not_reconnected(
        self, monkeypatch, caplog,
    ):
        import gateway.platforms.wecom as wecom_module
        from gateway.platforms.wecom import (
            WeComAdapter,
            WeComCleanupIncompleteError,
        )

        adapter = _make_wecom_adapter(monkeypatch, owner="wecom")
        adapter._running = True
        monkeypatch.setattr(wecom_module, "RECONNECT_BACKOFF", [0])

        open_calls = []

        async def open_outcomes():
            open_calls.append(1)
            if len(open_calls) == 1:
                raise WeComCleanupIncompleteError(["ws_close"])
            # Sentinel for a regressed (non-terminal) gate: a second open
            # "succeeds", then the next read exits the loop deterministically
            # so the assertion below fails instead of hanging forever.
            adapter._read_events = AsyncMock(side_effect=asyncio.CancelledError())

        adapter._open_connection = open_outcomes
        adapter._read_events = AsyncMock(side_effect=RuntimeError("read-fail"))
        # The factory stubs the loop for connect()-level tests; rebind the
        # real one here.
        adapter._listen_loop = WeComAdapter._listen_loop.__get__(adapter)

        handler_calls = []

        async def gateway_style_handler(adpt):
            handler_calls.append(adpt)
            # The real gateway handler calls disconnect(); doing the same
            # here proves the listen task neither self-awaits nor
            # self-cancels when it triggers the fatal notification.
            await adpt.disconnect()

        adapter.set_fatal_error_handler(gateway_style_handler)

        with caplog.at_level(logging.INFO):
            listen_task = asyncio.create_task(adapter._listen_loop())
            adapter._listen_task = listen_task
            # Bounded wait: a regression must fail, never hang for CI.
            await asyncio.wait_for(listen_task, timeout=10)
            # Let the detached notification task run.
            for _ in range(5):
                await asyncio.sleep(0)

        # The cleanup-incomplete rejection is terminal: no second open, no
        # reconnect, non-retryable fatal, exactly one handler notification.
        assert len(open_calls) == 1
        assert "Reconnected" not in caplog.text
        assert adapter.fatal_error_code == "wecom_cleanup_incomplete"
        assert adapter.fatal_error_retryable is False
        assert len(handler_calls) == 1
        # The notify task was registry-owned and discarded after completion.
        assert adapter._background_tasks == set()
