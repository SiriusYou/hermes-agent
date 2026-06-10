"""Tests for the optional YouPet Core bridge."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from gateway.config import Platform
from gateway.integrations.youpet import YouPetBridge, YouPetBridgeSettings
from gateway.platforms.base import MessageEvent, MessageType, SendResult
from gateway.session import SessionSource


class FakeResponse:
    def __init__(self, data=None, status_code=200, text=""):
        self._data = data or {}
        self.status_code = status_code
        self.text = text

    def json(self):
        return self._data


class FakeCoreClient:
    def __init__(self, outbox_items=None, inbound_response=None):
        self.outbox_items = outbox_items or []
        self.inbound_response = inbound_response or {}
        self.get_calls = []
        self.post_calls = []
        self.closed = False

    async def get(self, url, **kwargs):
        self.get_calls.append({"url": url, **kwargs})
        return FakeResponse({"items": self.outbox_items})

    async def post(self, url, **kwargs):
        self.post_calls.append({"url": url, **kwargs})
        if url.endswith("/wecom/inbound"):
            return FakeResponse(self.inbound_response)
        return FakeResponse({"ok": True})

    async def aclose(self):
        self.closed = True


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


def _event():
    source = SessionSource(
        platform=Platform.WECOM_CALLBACK,
        chat_id="ww1234567890:zhangsan",
        chat_type="dm",
        user_id="zhangsan",
        user_name="zhangsan",
    )
    return MessageEvent(
        text="completed",
        message_type=MessageType.TEXT,
        source=source,
        message_id="msg-001",
        timestamp=datetime(2026, 6, 2, 12, 0, tzinfo=UTC),
    )


def _outbox_item(event_id, event_type, payload):
    aggregate_type, aggregate_id = _aggregate_for_outbox_item(event_type, payload)
    return {
        "event_id": event_id,
        "consumer": "hermes",
        "state": "pending",
        "attempts": 0,
        "next_attempt_at": "2026-06-01T00:00:00Z",
        "last_attempt_at": None,
        "delivered_at": None,
        "dead_lettered_at": None,
        "last_error": None,
        "event_type": event_type,
        "aggregate_type": aggregate_type,
        "aggregate_id": aggregate_id,
        "correlation_id": "corr-1",
        "payload": {
            "aggregate": {
                "id": aggregate_id,
                "type": aggregate_type,
            },
            "correlation_id": "corr-1",
            "event_id": f"payload-{event_id}",
            "event_type": event_type,
            "event_version": 1,
            "idempotency_key": f"idem-{event_type}",
            "occurred_at": "2026-06-01T00:00:00Z",
            "payload": payload,
            "producer": "youpet-core",
        },
        "created_at": "2026-06-01T00:00:00Z",
    }


def _aggregate_for_outbox_item(event_type, payload):
    if event_type.startswith("health_plan."):
        return "health_plan", payload.get("plan_id", "plan-1")
    if event_type.startswith("task."):
        return "task_instance", payload.get("task_id", "task-1")
    if event_type.startswith("alert."):
        return "alert", payload.get("alert_id", payload.get("related_id", "alert-1"))
    return "task_instance", payload.get("task_id", "task-1")


def _counts(**overrides):
    counts = {
        "pulled": 0,
        "processed": 0,
        "sent": 0,
        "acked": 0,
        "nacked": 0,
        "skipped": 0,
    }
    counts.update(overrides)
    return counts


@pytest.mark.asyncio
async def test_wecom_event_posts_core_inbound_and_learns_chat_mapping():
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    client = FakeCoreClient(
        inbound_response={
            "matched_user_id": "user-123",
            "matched_task_id": "task-123",
            "action": "checkin_recorded",
        },
    )
    bridge = YouPetBridge(_settings(), fake_send)
    bridge._client = client

    skip_agent = await bridge.handle_wecom_event(
        _event(),
        {"corp_id": "ww1234567890"},
    )

    assert skip_agent is True
    assert sent == []
    assert bridge._runtime_user_chat_map["user-123"] == "ww1234567890:zhangsan"
    call = client.post_calls[0]
    assert call["url"] == "http://youpet-core.test/api/v1/wecom/inbound"
    assert call["headers"]["Authorization"] == "Bearer service-token"
    assert call["headers"]["X-Actor-Id"] == "hermes-wecom-bridge"
    assert call["headers"]["Idempotency-Key"] == "wecom:ww1234567890:msg-001"
    assert call["json"] == {
        "corp_id": "ww1234567890",
        "source": "hermes_wecom",
        "conversation_type": "dm",
        "wecom_user_id": "zhangsan",
        "wecom_group_id": None,
        "message_id": "msg-001",
        "message_type": "text",
        "text": "completed",
        "media": [],
        "received_at": "2026-06-02T12:00:00Z",
    }


@pytest.mark.asyncio
async def test_poll_once_sends_reminder_and_acks():
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    event_id = "11111111-1111-4111-8111-111111111111"
    client = FakeCoreClient(
        outbox_items=[
            _outbox_item(
                event_id,
                "task.reminder_due",
                {
                    "task_id": "task-1",
                    "recipient_user_id": "user-123",
                    "message_context": {
                        "pet_name": "Mochi",
                        "plan_title": "30 day deworming follow-up",
                    },
                },
            ),
        ],
    )
    bridge = YouPetBridge(
        _settings(user_chat_map={"user-123": "ww1234567890:zhangsan"}),
        fake_send,
    )
    bridge._client = client

    counts = await bridge.poll_once()

    assert counts == _counts(pulled=1, processed=1, sent=1, acked=1)
    assert sent == [
        (
            "ww1234567890:zhangsan",
            "[YouPet] Reminder for Mochi: 30 day deworming follow-up. Reply when completed.",
        ),
    ]
    assert client.post_calls[-1]["url"].endswith(f"/internal/events/outbox/{event_id}/ack")
    assert client.post_calls[-1]["params"] == {"consumer": "hermes"}


@pytest.mark.asyncio
async def test_poll_once_sends_task_escalated_once_and_acks_alert_created_noop(caplog):
    caplog.set_level("INFO")
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    task_escalated_event_id = "55555555-5555-4555-8555-555555555555"
    alert_created_event_id = "66666666-6666-4666-8666-666666666666"
    client = FakeCoreClient(
        outbox_items=[
            _outbox_item(
                task_escalated_event_id,
                "task.escalated",
                {
                    "task_id": "task-5",
                    "alert_id": "alert-5",
                    "alert_type": "missed_checkin",
                    "severity": "high",
                    "recipient_user_id": "user-123",
                    "summary": "Needs follow-up",
                },
            ),
            _outbox_item(
                alert_created_event_id,
                "alert.created",
                {
                    "alert_id": "alert-5",
                    "alert_type": "missed_checkin",
                    "severity": "high",
                    "related_type": "task_instance",
                    "related_id": "task-5",
                    "assigned_to": None,
                    "summary": "Needs follow-up",
                },
            ),
        ],
    )
    bridge = YouPetBridge(
        _settings(
            default_chat_id="ww1234567890:default",
            user_chat_map={"user-123": "ww1234567890:zhangsan"},
        ),
        fake_send,
    )
    bridge._client = client

    counts = await bridge.poll_once()

    assert counts == _counts(pulled=2, processed=2, sent=1, acked=2)
    assert sent == [("ww1234567890:zhangsan", "[YouPet Alert] high: Needs follow-up")]
    assert "Acknowledging alert.created without WeCom send" in caplog.text
    ack_urls = [
        call["url"]
        for call in client.post_calls
        if call["url"].endswith("/ack")
    ]
    assert any(
        url.endswith(f"/internal/events/outbox/{task_escalated_event_id}/ack")
        for url in ack_urls
    )
    assert any(
        url.endswith(f"/internal/events/outbox/{alert_created_event_id}/ack")
        for url in ack_urls
    )
    assert not any(call["url"].endswith("/nack") for call in client.post_calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"alert_id": "alert-6", "severity": "high", "summary": "Missing recipient"},
        {
            "alert_id": "alert-6",
            "severity": "high",
            "recipient_user_id": "missing-user",
            "summary": "Unmapped recipient",
        },
    ],
)
async def test_poll_once_nacks_unroutable_task_escalated_without_default_fallback(payload):
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    event_id = "77777777-7777-4777-8777-777777777777"
    client = FakeCoreClient(
        outbox_items=[
            _outbox_item(
                event_id,
                "task.escalated",
                payload,
            ),
        ],
    )
    bridge = YouPetBridge(
        _settings(default_chat_id="ww1234567890:default"),
        fake_send,
    )
    bridge._client = client

    counts = await bridge.poll_once()

    assert counts == _counts(pulled=1, processed=1, nacked=1)
    assert sent == []
    assert client.post_calls[-1]["url"].endswith(f"/internal/events/outbox/{event_id}/nack")
    assert client.post_calls[-1]["json"]["error"] == (
        "No WeCom chat_id for YouPet outbox recipient"
    )


@pytest.mark.asyncio
async def test_poll_once_skips_empty_event_id_before_dispatch_even_on_repoll(caplog):
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    client = FakeCoreClient(
        outbox_items=[
            _outbox_item(
                "",
                "task.reminder_due",
                {
                    "task_id": "task-empty",
                    "recipient_user_id": "user-123",
                    "message_context": {"pet_name": "Mochi", "plan_title": "care task"},
                },
            ),
            _outbox_item(
                "   ",
                "task.reminder_due",
                {
                    "task_id": "task-whitespace",
                    "recipient_user_id": "user-123",
                    "message_context": {"pet_name": "Mochi", "plan_title": "care task"},
                },
            ),
            None,
        ],
    )
    bridge = YouPetBridge(
        _settings(user_chat_map={"user-123": "ww1234567890:zhangsan"}),
        fake_send,
    )
    bridge._client = client

    first_counts = await bridge.poll_once()
    second_counts = await bridge.poll_once()

    assert first_counts == _counts(pulled=3, processed=3, skipped=3)
    assert second_counts == _counts(pulled=3, processed=3, skipped=3)
    assert sent == []
    assert client.post_calls == []
    assert caplog.text.count("Skipping outbox item with missing event_id") == 6


@pytest.mark.asyncio
async def test_poll_once_observably_acks_unknown_event_type(caplog):
    caplog.set_level("INFO")
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    event_id = "88888888-8888-4888-8888-888888888888"
    client = FakeCoreClient(
        outbox_items=[
            _outbox_item(
                event_id,
                "future.event_type",
                {"task_id": "task-future"},
            ),
        ],
    )
    bridge = YouPetBridge(_settings(), fake_send)
    bridge._client = client

    counts = await bridge.poll_once()

    assert counts == _counts(pulled=1, processed=1, acked=1)
    assert sent == []
    assert client.post_calls[-1]["url"].endswith(f"/internal/events/outbox/{event_id}/ack")
    assert "Acknowledging unhandled outbox event type: future.event_type" in caplog.text


@pytest.mark.asyncio
async def test_poll_once_nacks_malformed_known_event(caplog):
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    event_id = "99999999-9999-4999-8999-999999999999"
    item = _outbox_item(event_id, "task.reminder_due", {"task_id": "task-malformed"})
    item["payload"]["payload"] = None
    client = FakeCoreClient(outbox_items=[item])
    bridge = YouPetBridge(
        _settings(user_chat_map={"user-123": "ww1234567890:zhangsan"}),
        fake_send,
    )
    bridge._client = client

    counts = await bridge.poll_once()

    assert counts == _counts(pulled=1, processed=1, nacked=1)
    assert sent == []
    assert client.post_calls[-1]["url"].endswith(f"/internal/events/outbox/{event_id}/nack")
    assert client.post_calls[-1]["json"]["error"] == "Malformed YouPet task.reminder_due payload"
    assert "Malformed YouPet task.reminder_due payload" in caplog.text


@pytest.mark.asyncio
async def test_poll_once_dedupes_processed_event_id():
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    event_id = "44444444-4444-4444-8444-444444444444"
    item = _outbox_item(
        event_id,
        "task.reminder_due",
        {
            "task_id": "task-4",
            "recipient_user_id": "user-123",
            "message_context": {"pet_name": "Mochi", "plan_title": "care task"},
        },
    )
    client = FakeCoreClient(outbox_items=[item])
    bridge = YouPetBridge(
        _settings(user_chat_map={"user-123": "ww1234567890:zhangsan"}),
        fake_send,
    )
    bridge._client = client

    await bridge.poll_once()
    await bridge.poll_once()

    assert len(sent) == 1
    ack_calls = [
        call for call in client.post_calls
        if call["url"].endswith(f"/internal/events/outbox/{event_id}/ack")
    ]
    assert len(ack_calls) == 2


@pytest.mark.asyncio
async def test_poll_once_nacks_unroutable_reminder():
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    event_id = "22222222-2222-4222-8222-222222222222"
    client = FakeCoreClient(
        outbox_items=[
            _outbox_item(
                event_id,
                "task.reminder_due",
                {"task_id": "task-2", "recipient_user_id": "missing-user"},
            ),
        ],
    )
    bridge = YouPetBridge(_settings(), fake_send)
    bridge._client = client

    counts = await bridge.poll_once()

    assert counts == _counts(pulled=1, processed=1, nacked=1)
    assert sent == []
    assert client.post_calls[-1]["url"].endswith(f"/internal/events/outbox/{event_id}/nack")
    assert client.post_calls[-1]["json"]["error"] == "No WeCom chat_id for YouPet outbox recipient"


@pytest.mark.asyncio
async def test_poll_once_acks_health_plan_without_send():
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    event_id = "33333333-3333-4333-8333-333333333333"
    client = FakeCoreClient(
        outbox_items=[
            _outbox_item(
                event_id,
                "health_plan.activated",
                {"plan_id": "plan-1", "owner_user_id": "user-123"},
            ),
        ],
    )
    bridge = YouPetBridge(_settings(), fake_send)
    bridge._client = client

    counts = await bridge.poll_once()

    assert counts == _counts(pulled=1, processed=1, acked=1)
    assert sent == []
    assert client.post_calls[-1]["url"].endswith(f"/internal/events/outbox/{event_id}/ack")
