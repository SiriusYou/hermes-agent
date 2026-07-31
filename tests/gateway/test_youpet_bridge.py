"""Tests for the optional YouPet Core bridge."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from gateway.config import Platform
from gateway.integrations.youpet import (
    MAX_PROCESSED_EVENT_IDS,
    YouPetBridge,
    YouPetBridgeSettings,
    is_wecom_pre_core_authorized,
)
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


def _wecom_event(platform: Platform, *, user_id: str = "zhangsan", chat_id: str = "chat-1"):
    source = SessionSource(
        platform=platform,
        chat_id=chat_id,
        chat_type="group" if chat_id.startswith("group") else "dm",
        user_id=user_id,
        user_name=user_id,
    )
    return MessageEvent(
        text="completed",
        message_type=MessageType.TEXT,
        source=source,
        message_id="msg-auth",
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


@pytest.mark.parametrize(
    ("platform", "env_name"),
    [
        (Platform.WECOM_CALLBACK, "WECOM_CALLBACK_ALLOWED_USERS"),
        (Platform.WECOM, "WECOM_ALLOWED_USERS"),
        (Platform.WECOM, "GATEWAY_ALLOWED_USERS"),
    ],
)
def test_pre_core_authorization_accepts_env_allowlists(monkeypatch, platform, env_name):
    monkeypatch.setenv(env_name, "zhangsan")

    assert is_wecom_pre_core_authorized(_wecom_event(platform)) is True


@pytest.mark.parametrize(
    ("platform", "env_name"),
    [
        (Platform.WECOM_CALLBACK, "WECOM_CALLBACK_ALLOW_ALL_USERS"),
        (Platform.WECOM, "WECOM_ALLOW_ALL_USERS"),
        (Platform.WECOM, "GATEWAY_ALLOW_ALL_USERS"),
    ],
)
def test_pre_core_authorization_accepts_allow_all_flags(monkeypatch, platform, env_name):
    monkeypatch.setenv(env_name, "true")

    assert is_wecom_pre_core_authorized(_wecom_event(platform)) is True


def test_pre_core_authorization_denies_without_matching_allowlist(monkeypatch):
    monkeypatch.setenv("WECOM_ALLOWED_USERS", "other-user")

    assert is_wecom_pre_core_authorized(_wecom_event(Platform.WECOM)) is False


@pytest.mark.parametrize("env_name", ["WECOM_ALLOWED_USERS", "GATEWAY_ALLOWED_USERS"])
def test_pre_core_authorization_does_not_match_chat_id_as_user(monkeypatch, env_name):
    monkeypatch.setenv(env_name, "group-1")

    event = _wecom_event(Platform.WECOM, user_id="user-2", chat_id="group-1")

    assert is_wecom_pre_core_authorized(event) is False


def test_pre_core_authorization_rejects_group_prefixed_user_allowlist(monkeypatch):
    monkeypatch.setenv("WECOM_ALLOWED_USERS", "group:zhangsan")

    assert is_wecom_pre_core_authorized(_wecom_event(Platform.WECOM)) is False


@pytest.mark.asyncio
async def test_wecom_event_posts_core_inbound_and_learns_chat_mapping(monkeypatch):
    monkeypatch.setenv("WECOM_CALLBACK_ALLOW_ALL_USERS", "1")
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
async def test_wecom_event_denied_before_core_write_without_allowlist(monkeypatch):
    monkeypatch.delenv("WECOM_CALLBACK_ALLOW_ALL_USERS", raising=False)
    monkeypatch.delenv("GATEWAY_ALLOW_ALL_USERS", raising=False)
    client = FakeCoreClient()
    bridge = YouPetBridge(_settings(), AsyncMock())
    bridge._client = client

    skip_agent = await bridge.handle_wecom_event(_event(), {"corp_id": "ww1234567890"})

    assert skip_agent is True
    assert client.post_calls == []


@pytest.mark.asyncio
async def test_wecom_group_image_event_posts_metadata_only(monkeypatch):
    monkeypatch.setenv("WECOM_ALLOW_ALL_USERS", "1")
    source = SessionSource(
        platform=Platform.WECOM,
        chat_id="group-1",
        chat_type="group",
        user_id="zhangsan",
        user_name="zhangsan",
    )
    event = MessageEvent(
        text="",
        message_type=MessageType.PHOTO,
        source=source,
        raw_message={
            "body": {
                "msgid": "group-msg-1",
                "chatid": "group-1",
                "chattype": "group",
                "from": {"userid": "zhangsan"},
                "msgtype": "image",
                "image": {
                    "media_id": "img-media-1",
                    "filename": "checkin.jpg",
                    "size": "12345",
                    "url": "https://wecom.example/media",
                },
            }
        },
        message_id="group-msg-1",
        timestamp=datetime(2026, 6, 2, 12, 1, tzinfo=UTC),
    )
    client = FakeCoreClient()
    bridge = YouPetBridge(_settings(corp_id="ww-group"), AsyncMock())
    bridge._client = client

    skip_agent = await bridge.handle_wecom_event(event, {})

    assert skip_agent is True
    call = client.post_calls[0]
    assert call["json"] == {
        "corp_id": "ww-group",
        "source": "hermes_wecom",
        "conversation_type": "group",
        "wecom_user_id": "zhangsan",
        "wecom_group_id": "group-1",
        "message_id": "group-msg-1",
        "message_type": "image",
        "text": None,
        "media": [
            {
                "media_type": "image",
                "wecom_media_id": "img-media-1",
                "filename": "checkin.jpg",
                "size_bytes": 12345,
            }
        ],
        "received_at": "2026-06-02T12:01:00Z",
    }


@pytest.mark.asyncio
async def test_wecom_callback_image_event_posts_metadata_only(monkeypatch):
    monkeypatch.setenv("WECOM_CALLBACK_ALLOWED_USERS", "zhangsan")
    source = SessionSource(
        platform=Platform.WECOM_CALLBACK,
        chat_id="ww1234567890:zhangsan",
        chat_type="dm",
        user_id="zhangsan",
        user_name="zhangsan",
    )
    event = MessageEvent(
        text="",
        message_type=MessageType.PHOTO,
        source=source,
        raw_message="""
        <xml>
          <ToUserName>ww1234567890</ToUserName>
          <FromUserName>zhangsan</FromUserName>
          <CreateTime>1710000000</CreateTime>
          <MsgType>image</MsgType>
          <MediaId>callback-image-1</MediaId>
          <PicUrl>https://wecom.example/callback-image</PicUrl>
          <MsgId>m-callback-image</MsgId>
        </xml>
        """,
        message_id="m-callback-image",
        timestamp=datetime(2026, 6, 2, 12, 2, tzinfo=UTC),
    )
    client = FakeCoreClient()
    bridge = YouPetBridge(_settings(), AsyncMock())
    bridge._client = client

    skip_agent = await bridge.handle_wecom_event(event, {"corp_id": "ww1234567890"})

    assert skip_agent is True
    assert client.post_calls[0]["json"]["media"] == [
        {
            "media_type": "image",
            "wecom_media_id": "callback-image-1",
        }
    ]
    assert client.post_calls[0]["json"]["message_type"] == "image"


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
async def test_poll_once_dedupes_by_business_payload_event_id_when_row_ids_change():
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    event_type = "task.reminder_due"
    payload = {
        "task_id": "task-5",
        "recipient_user_id": "user-123",
        "message_context": {"pet_name": "Mochi", "plan_title": "care task"},
    }
    first_item = _outbox_item(
        "11111111-1111-1111-8111-111111111111",
        event_type,
        payload,
    )
    first_item["payload"]["event_id"] = "business-task-5"

    second_item = _outbox_item(
        "22222222-2222-2222-8222-222222222222",
        event_type,
        payload,
    )
    second_item["payload"]["event_id"] = "business-task-5"

    client = FakeCoreClient(outbox_items=[first_item])
    bridge = YouPetBridge(
        _settings(user_chat_map={"user-123": "ww1234567890:zhangsan"}),
        fake_send,
    )
    bridge._client = client

    await bridge.poll_once()

    client.outbox_items = [second_item]
    await bridge.poll_once()

    assert len(sent) == 1
    ack_calls = [
        call
        for call in client.post_calls
        if call["url"].endswith("/ack")
    ]
    assert len(ack_calls) == 2
    assert client.post_calls[0]["url"].endswith(
        "/internal/events/outbox/11111111-1111-1111-8111-111111111111/ack"
    )
    assert client.post_calls[1]["url"].endswith(
        "/internal/events/outbox/22222222-2222-2222-8222-222222222222/ack"
    )
    assert "business-task-5" in bridge._processed_event_ids
    assert "11111111-1111-1111-8111-111111111111" not in bridge._processed_event_ids
    assert "22222222-2222-2222-8222-222222222222" not in bridge._processed_event_ids


@pytest.mark.asyncio
async def test_poll_once_recovers_after_transient_send_failure_without_duplicate_replay():
    send_attempts = []
    successful_sends = []
    send_results = [
        SendResult(success=False, error="transient send failure"),
        SendResult(success=True),
    ]

    async def fake_send(chat_id, content):
        send_attempts.append((chat_id, content))
        result = send_results.pop(0)
        if result.success:
            successful_sends.append((chat_id, content))
        return result

    event_type = "task.reminder_due"
    business_event_id = "business-task-recovery"
    payload = {
        "task_id": "task-recovery",
        "recipient_user_id": "user-123",
        "message_context": {"pet_name": "Mochi", "plan_title": "care task"},
    }
    first_item = _outbox_item(
        "66666666-6666-4666-8666-666666666666",
        event_type,
        payload,
    )
    first_item["payload"]["event_id"] = business_event_id

    second_item = _outbox_item(
        "77777777-7777-4777-8777-777777777777",
        event_type,
        payload,
    )
    second_item["payload"]["event_id"] = business_event_id

    replay_item = _outbox_item(
        "88888888-8888-4888-8888-888888888888",
        event_type,
        payload,
    )
    replay_item["payload"]["event_id"] = business_event_id

    client = FakeCoreClient(outbox_items=[first_item])
    bridge = YouPetBridge(
        _settings(user_chat_map={"user-123": "ww1234567890:zhangsan"}),
        fake_send,
    )
    bridge._client = client

    first_counts = await bridge.poll_once()

    assert first_counts == _counts(pulled=1, processed=1, nacked=1)
    assert client.post_calls[-1]["url"].endswith(
        "/internal/events/outbox/66666666-6666-4666-8666-666666666666/nack"
    )
    assert business_event_id not in bridge._processed_event_ids
    assert bridge._processed_event_id_order == []

    client.outbox_items = [second_item]
    second_counts = await bridge.poll_once()

    assert second_counts == _counts(pulled=1, processed=1, sent=1, acked=1)
    assert client.post_calls[-1]["url"].endswith(
        "/internal/events/outbox/77777777-7777-4777-8777-777777777777/ack"
    )
    assert bridge._processed_event_id_order == [business_event_id]
    assert business_event_id in bridge._processed_event_ids
    assert "77777777-7777-4777-8777-777777777777" not in bridge._processed_event_ids

    client.outbox_items = [replay_item]
    replay_counts = await bridge.poll_once()

    assert replay_counts == _counts(pulled=1, processed=1, acked=1)
    assert client.post_calls[-1]["url"].endswith(
        "/internal/events/outbox/88888888-8888-4888-8888-888888888888/ack"
    )
    assert len(send_attempts) == 2
    assert len(successful_sends) == 1
    assert bridge._processed_event_id_order == [business_event_id]
    assert set(bridge._processed_event_ids) == {business_event_id}


@pytest.mark.asyncio
async def test_poll_once_dedupes_legacy_delivery_id_and_backfills_business_event_id():
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    delivery_id = "12121212-1212-4212-8212-121212121212"
    business_event_id = "business-task-legacy"
    state_path = YouPetBridge._processed_event_state_path()
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps({"event_ids": [delivery_id]}, indent=2) + "\n",
        encoding="utf-8",
    )

    item = _outbox_item(
        delivery_id,
        "task.reminder_due",
        {
            "task_id": "task-legacy",
            "recipient_user_id": "user-123",
            "message_context": {"pet_name": "Mochi", "plan_title": "care task"},
        },
    )
    item["payload"]["event_id"] = business_event_id

    client = FakeCoreClient(outbox_items=[item])
    bridge = YouPetBridge(
        _settings(user_chat_map={"user-123": "ww1234567890:zhangsan"}),
        fake_send,
    )
    bridge._client = client

    counts = await bridge.poll_once()

    assert counts == _counts(pulled=1, processed=1, acked=1)
    assert sent == []
    assert client.post_calls == [
        {
            "url": "http://youpet-core.test/internal/events/outbox/12121212-1212-4212-8212-121212121212/ack",
            "params": {"consumer": "hermes"},
            "headers": {
                "Authorization": "Bearer service-token",
                "X-Actor-Id": "hermes-wecom-bridge",
            },
        }
    ]
    assert bridge._processed_event_id_order == [business_event_id]
    assert business_event_id in bridge._processed_event_ids
    assert delivery_id not in bridge._processed_event_ids
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["event_ids"] == bridge._processed_event_id_order


@pytest.mark.asyncio
async def test_poll_once_removes_redundant_legacy_key_when_canonical_key_already_exists():
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    leading_event_id = "business-leading"
    delivery_id = "13131313-1313-4131-8131-131313131313"
    business_event_id = "business-task-mixed"
    trailing_event_id = "business-trailing"
    expected_event_ids = [
        leading_event_id,
        business_event_id,
        trailing_event_id,
    ]
    state_path = YouPetBridge._processed_event_state_path()
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "event_ids": [
                    leading_event_id,
                    delivery_id,
                    business_event_id,
                    trailing_event_id,
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    item = _outbox_item(
        delivery_id,
        "task.reminder_due",
        {
            "task_id": "task-mixed",
            "recipient_user_id": "user-123",
            "message_context": {"pet_name": "Mochi", "plan_title": "care task"},
        },
    )
    item["payload"]["event_id"] = business_event_id

    client = FakeCoreClient(outbox_items=[item])
    bridge = YouPetBridge(
        _settings(user_chat_map={"user-123": "ww1234567890:zhangsan"}),
        fake_send,
    )
    bridge._client = client

    counts = await bridge.poll_once()

    assert counts == _counts(pulled=1, processed=1, acked=1)
    assert sent == []
    assert client.post_calls == [
        {
            "url": "http://youpet-core.test/internal/events/outbox/13131313-1313-4131-8131-131313131313/ack",
            "params": {"consumer": "hermes"},
            "headers": {
                "Authorization": "Bearer service-token",
                "X-Actor-Id": "hermes-wecom-bridge",
            },
        }
    ]
    assert bridge._processed_event_id_order == expected_event_ids
    assert bridge._processed_event_id_order.count(business_event_id) == 1
    assert delivery_id not in bridge._processed_event_ids
    assert business_event_id in bridge._processed_event_ids
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["event_ids"] == bridge._processed_event_id_order


@pytest.mark.asyncio
async def test_poll_once_backfills_full_legacy_ledger_without_eviction_or_duplicate_send():
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    oldest_delivery_id = "01010101-0101-4101-8101-010101010101"
    oldest_business_event_id = "business-task-oldest"
    current_delivery_id = "02020202-0202-4202-8202-020202020202"
    current_business_event_id = "business-task-current"
    filler_event_ids = [
        f"business-filler-{index:04d}"
        for index in range(MAX_PROCESSED_EVENT_IDS - 2)
    ]
    state_path = YouPetBridge._processed_event_state_path()
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "event_ids": [
                    oldest_delivery_id,
                    current_delivery_id,
                    *filler_event_ids,
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    oldest_item = _outbox_item(
        oldest_delivery_id,
        "task.reminder_due",
        {
            "task_id": "task-oldest",
            "recipient_user_id": "user-123",
            "message_context": {"pet_name": "Mochi", "plan_title": "care task"},
        },
    )
    oldest_item["payload"]["event_id"] = oldest_business_event_id

    current_item = _outbox_item(
        current_delivery_id,
        "task.reminder_due",
        {
            "task_id": "task-current",
            "recipient_user_id": "user-123",
            "message_context": {"pet_name": "Mochi", "plan_title": "care task"},
        },
    )
    current_item["payload"]["event_id"] = current_business_event_id

    client = FakeCoreClient(outbox_items=[current_item])
    bridge = YouPetBridge(
        _settings(user_chat_map={"user-123": "ww1234567890:zhangsan"}),
        fake_send,
    )
    bridge._client = client

    first_counts = await bridge.poll_once()

    assert first_counts == _counts(pulled=1, processed=1, acked=1)
    assert sent == []
    assert len(bridge._processed_event_id_order) == MAX_PROCESSED_EVENT_IDS
    assert bridge._processed_event_id_order == [
        oldest_delivery_id,
        current_business_event_id,
        *filler_event_ids,
    ]
    assert oldest_delivery_id in bridge._processed_event_ids
    assert current_delivery_id not in bridge._processed_event_ids
    assert current_business_event_id in bridge._processed_event_ids
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["event_ids"] == bridge._processed_event_id_order

    client.outbox_items = [oldest_item]
    second_counts = await bridge.poll_once()

    assert second_counts == _counts(pulled=1, processed=1, acked=1)
    assert sent == []
    ack_calls = [
        call["url"]
        for call in client.post_calls
        if call["url"].endswith("/ack")
    ]
    assert ack_calls == [
        "http://youpet-core.test/internal/events/outbox/02020202-0202-4202-8202-020202020202/ack",
        "http://youpet-core.test/internal/events/outbox/01010101-0101-4101-8101-010101010101/ack",
    ]
    assert len(bridge._processed_event_id_order) == MAX_PROCESSED_EVENT_IDS
    assert bridge._processed_event_id_order == [
        oldest_business_event_id,
        current_business_event_id,
        *filler_event_ids,
    ]
    assert oldest_delivery_id not in bridge._processed_event_ids
    assert current_delivery_id not in bridge._processed_event_ids
    assert oldest_business_event_id in bridge._processed_event_ids
    assert current_business_event_id in bridge._processed_event_ids
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["event_ids"] == bridge._processed_event_id_order


def test_remember_processed_event_id_evicts_oldest_and_persists_bound():
    bridge = YouPetBridge(_settings(), AsyncMock())

    expected = [
        f"event-{index:04d}"
        for index in range(1, MAX_PROCESSED_EVENT_IDS + 1)
    ]
    for index in range(MAX_PROCESSED_EVENT_IDS + 1):
        bridge._remember_processed_event_id(f"event-{index:04d}")

    assert len(bridge._processed_event_id_order) == MAX_PROCESSED_EVENT_IDS
    assert len(bridge._processed_event_ids) == MAX_PROCESSED_EVENT_IDS
    assert bridge._processed_event_id_order == expected
    assert "event-0000" not in bridge._processed_event_ids
    assert expected[-1] in bridge._processed_event_ids
    persisted = json.loads(
        YouPetBridge._processed_event_state_path().read_text(encoding="utf-8")
    )
    assert persisted["event_ids"] == expected


@pytest.mark.asyncio
async def test_poll_once_replays_distinct_business_event_ids_when_row_shape_matches():
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    payload = {
        "task_id": "task-6",
        "recipient_user_id": "user-123",
        "message_context": {"pet_name": "Mochi", "plan_title": "care task"},
    }
    first_item = _outbox_item(
        "33333333-3333-4333-8333-333333333333",
        "task.reminder_due",
        payload,
    )
    first_item["payload"]["event_id"] = "business-task-6-a"
    second_item = _outbox_item(
        "44444444-4444-4444-8444-444444444444",
        "task.reminder_due",
        payload,
    )
    second_item["payload"]["event_id"] = "business-task-6-b"

    client = FakeCoreClient(outbox_items=[first_item])
    bridge = YouPetBridge(
        _settings(user_chat_map={"user-123": "ww1234567890:zhangsan"}),
        fake_send,
    )
    bridge._client = client

    await bridge.poll_once()

    client.outbox_items = [second_item]
    await bridge.poll_once()

    assert len(sent) == 2
    ack_calls = [
        call["url"]
        for call in client.post_calls
        if call["url"].endswith("/ack")
    ]
    assert ack_calls == [
        "http://youpet-core.test/internal/events/outbox/33333333-3333-4333-8333-333333333333/ack",
        "http://youpet-core.test/internal/events/outbox/44444444-4444-4444-8444-444444444444/ack",
    ]


@pytest.mark.asyncio
async def test_poll_once_nacks_supported_event_with_missing_business_event_id():
    sent = []

    async def fake_send(chat_id, content):
        sent.append((chat_id, content))
        return SendResult(success=True)

    delivery_id = "55555555-5555-4555-8555-555555555555"
    item = _outbox_item(
        delivery_id,
        "task.reminder_due",
        {
            "task_id": "task-7",
            "recipient_user_id": "user-123",
            "message_context": {"pet_name": "Mochi", "plan_title": "care task"},
        },
    )
    item["payload"]["event_id"] = "   "

    client = FakeCoreClient(outbox_items=[item])
    bridge = YouPetBridge(
        _settings(user_chat_map={"user-123": "ww1234567890:zhangsan"}),
        fake_send,
    )
    bridge._client = client

    counts = await bridge.poll_once()

    assert counts == _counts(pulled=1, processed=1, nacked=1)
    assert sent == []
    assert client.post_calls[-1]["url"].endswith(f"/internal/events/outbox/{delivery_id}/nack")
    assert client.post_calls[-1]["json"]["error"] == (
        "Malformed YouPet task.reminder_due payload: missing event_id"
    )


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
