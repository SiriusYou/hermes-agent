"""Tests for the WeCom callback-mode adapter."""

import asyncio
import hmac
import json
import logging
import time
from xml.etree import ElementTree as ET

import pytest

from gateway.config import PlatformConfig
from gateway.integrations.youpet import YouPetBridgeError
from gateway.platforms.base import MessageType
from gateway.platforms.wecom_callback import (
    MAX_PERSISTED_DEDUP_ENTRIES,
    MESSAGE_DEDUP_TTL_SECONDS,
    WecomCallbackAdapter,
)
from gateway.platforms.wecom_crypto import WXBizMsgCrypt, WeComCryptoError


def _app(name="test-app", corp_id="ww1234567890", agent_id="1000002"):
    return {
        "name": name,
        "corp_id": corp_id,
        "corp_secret": "test-secret",
        "agent_id": agent_id,
        "token": "test-callback-token",
        "encoding_aes_key": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
    }


def _config(apps=None):
    return PlatformConfig(
        enabled=True,
        extra={"mode": "callback", "host": "127.0.0.1", "port": 0, "apps": apps or [_app()]},
    )


@pytest.fixture(autouse=True)
def _isolated_hermes_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))


def _fresh_query(timestamp=None):
    timestamp = int(time.time()) if timestamp is None else timestamp
    return {"timestamp": str(timestamp)}


class _CallbackRequest:
    def __init__(self, timestamp=None, query=None, body="<encrypted/>"):
        self.query = _fresh_query(timestamp) if query is None else query
        self._body = body
        self.text_called = False

    async def text(self):
        self.text_called = True
        return self._body


class TestWecomCrypto:
    def test_roundtrip_encrypt_decrypt(self):
        app = _app()
        crypt = WXBizMsgCrypt(app["token"], app["encoding_aes_key"], app["corp_id"])
        encrypted_xml = crypt.encrypt(
            "<xml><Content>hello</Content></xml>", nonce="nonce123", timestamp="123456",
        )
        root = ET.fromstring(encrypted_xml)
        decrypted = crypt.decrypt(
            root.findtext("MsgSignature", default=""),
            root.findtext("TimeStamp", default=""),
            root.findtext("Nonce", default=""),
            root.findtext("Encrypt", default=""),
        )
        assert b"<Content>hello</Content>" in decrypted

    def test_signature_mismatch_raises(self):
        app = _app()
        crypt = WXBizMsgCrypt(app["token"], app["encoding_aes_key"], app["corp_id"])
        encrypted_xml = crypt.encrypt("<xml/>", nonce="n", timestamp="1")
        root = ET.fromstring(encrypted_xml)
        from gateway.platforms.wecom_crypto import SignatureError
        with pytest.raises(SignatureError):
            crypt.decrypt("bad-sig", "1", "n", root.findtext("Encrypt", default=""))

    def test_non_ascii_signature_mismatch_raises_signature_error(self):
        app = _app()
        crypt = WXBizMsgCrypt(app["token"], app["encoding_aes_key"], app["corp_id"])
        encrypted_xml = crypt.encrypt("<xml/>", nonce="n", timestamp="1")
        root = ET.fromstring(encrypted_xml)
        from gateway.platforms.wecom_crypto import SignatureError

        with pytest.raises(SignatureError):
            crypt.decrypt("sécret", "1", "n", root.findtext("Encrypt", default=""))

    def test_signature_compare_is_timing_safe(self, monkeypatch):
        """Ensure hmac.compare_digest is used for WeCom signature comparison."""
        calls: list[tuple[bytes, bytes]] = []
        real_compare = hmac.compare_digest

        def _spy(a, b):
            calls.append((a, b))
            return real_compare(a, b)

        monkeypatch.setattr("gateway.platforms.wecom_crypto.hmac.compare_digest", _spy)

        app = _app()
        crypt = WXBizMsgCrypt(app["token"], app["encoding_aes_key"], app["corp_id"])
        encrypted_xml = crypt.encrypt(
            "<xml><Content>hello</Content></xml>",
            nonce="n",
            timestamp="1",
        )
        root = ET.fromstring(encrypted_xml)
        signature = root.findtext("MsgSignature", default="")
        decrypted = crypt.decrypt(
            signature,
            "1",
            "n",
            root.findtext("Encrypt", default=""),
        )

        assert b"<Content>hello</Content>" in decrypted
        assert calls, (
            "hmac.compare_digest was never called; WeCom signature check is not timing-safe"
        )
        provided, expected = calls[0]
        assert provided == signature.encode("utf-8")
        assert expected == signature.encode("utf-8")


class TestWecomCallbackEventConstruction:
    def test_build_event_extracts_text_message(self):
        adapter = WecomCallbackAdapter(_config())
        xml_text = """
        <xml>
          <ToUserName>ww1234567890</ToUserName>
          <FromUserName>zhangsan</FromUserName>
          <CreateTime>1710000000</CreateTime>
          <MsgType>text</MsgType>
          <Content>\u4f60\u597d</Content>
          <MsgId>123456789</MsgId>
        </xml>
        """
        event = adapter._build_event(_app(), xml_text)
        assert event is not None
        assert event.source is not None
        assert event.source.user_id == "zhangsan"
        assert event.source.chat_id == "ww1234567890:zhangsan"
        assert event.message_id == "123456789"
        assert event.text == "\u4f60\u597d"

    def test_build_event_extracts_image_message_for_metadata_bridge(self):
        adapter = WecomCallbackAdapter(_config())
        xml_text = """
        <xml>
          <ToUserName>ww1234567890</ToUserName>
          <FromUserName>zhangsan</FromUserName>
          <CreateTime>1710000000</CreateTime>
          <MsgType>image</MsgType>
          <MediaId>media-callback-1</MediaId>
          <PicUrl>https://wecom.example/image</PicUrl>
          <MsgId>img-123</MsgId>
        </xml>
        """
        event = adapter._build_event(_app(), xml_text)
        assert event is not None
        assert event.source is not None
        assert event.source.user_id == "zhangsan"
        assert event.source.chat_id == "ww1234567890:zhangsan"
        assert event.message_id == "img-123"
        assert event.text == ""
        assert event.message_type == MessageType.PHOTO

    def test_build_event_returns_none_for_subscribe(self):
        adapter = WecomCallbackAdapter(_config())
        xml_text = """
        <xml>
          <ToUserName>ww1234567890</ToUserName>
          <FromUserName>zhangsan</FromUserName>
          <CreateTime>1710000000</CreateTime>
          <MsgType>event</MsgType>
          <Event>subscribe</Event>
        </xml>
        """
        event = adapter._build_event(_app(), xml_text)
        assert event is None


class TestWecomCallbackRouting:
    def test_user_app_key_scopes_across_corps(self):
        adapter = WecomCallbackAdapter(_config())
        assert adapter._user_app_key("corpA", "alice") == "corpA:alice"
        assert adapter._user_app_key("corpB", "alice") == "corpB:alice"
        assert adapter._user_app_key("corpA", "alice") != adapter._user_app_key("corpB", "alice")

    @pytest.mark.asyncio
    async def test_send_selects_correct_app_for_scoped_chat_id(self):
        apps = [
            _app(name="corp-a", corp_id="corpA", agent_id="1001"),
            _app(name="corp-b", corp_id="corpB", agent_id="2002"),
        ]
        adapter = WecomCallbackAdapter(_config(apps=apps))
        adapter._user_app_map["corpB:alice"] = "corp-b"
        adapter._access_tokens["corp-b"] = {"token": "tok-b", "expires_at": 9999999999}

        calls = {}

        class FakeResponse:
            def json(self):
                return {"errcode": 0, "msgid": "ok1"}

        class FakeClient:
            async def post(self, url, json):
                calls["url"] = url
                calls["json"] = json
                return FakeResponse()

        adapter._http_client = FakeClient()
        result = await adapter.send("corpB:alice", "hello")

        assert result.success is True
        assert calls["json"]["touser"] == "alice"
        assert calls["json"]["agentid"] == 2002
        assert "tok-b" in calls["url"]

    @pytest.mark.asyncio
    async def test_send_falls_back_from_bare_user_id_when_unique(self):
        apps = [_app(name="corp-a", corp_id="corpA", agent_id="1001")]
        adapter = WecomCallbackAdapter(_config(apps=apps))
        adapter._user_app_map["corpA:alice"] = "corp-a"
        adapter._access_tokens["corp-a"] = {"token": "tok-a", "expires_at": 9999999999}

        calls = {}

        class FakeResponse:
            def json(self):
                return {"errcode": 0, "msgid": "ok2"}

        class FakeClient:
            async def post(self, url, json):
                calls["url"] = url
                calls["json"] = json
                return FakeResponse()

        adapter._http_client = FakeClient()
        result = await adapter.send("alice", "hello")

        assert result.success is True
        assert calls["json"]["agentid"] == 1001


class TestWecomCallbackSendTokenRefresh:
    @pytest.mark.asyncio
    async def test_send_retries_with_fresh_token_on_errcode_40001(self):
        """errcode=40001 must evict the cached token, refresh, and retry once."""
        adapter = WecomCallbackAdapter(_config())
        adapter._access_tokens["test-app"] = {"token": "stale", "expires_at": 9999999999}
        adapter._user_app_map["ww1234567890:alice"] = "test-app"

        responses = [
            {"errcode": 40001, "errmsg": "invalid credential"},
            {"errcode": 0, "msgid": "msg-ok"},
        ]
        post_calls = []

        class FakeClient:
            async def post(self, url, json=None, **kw):
                post_calls.append(url)

                class R:
                    def json(inner):
                        return responses[len(post_calls) - 1]
                return R()

            async def get(self, url, params=None, **kw):
                class R:
                    def json(inner):
                        return {"errcode": 0, "access_token": "fresh", "expires_in": 7200}
                return R()

        adapter._http_client = FakeClient()
        result = await adapter.send("ww1234567890:alice", "hello")

        assert result.success is True
        assert result.message_id == "msg-ok"
        assert len(post_calls) == 2
        assert "fresh" in post_calls[1]
        assert adapter._access_tokens["test-app"]["token"] == "fresh"

    @pytest.mark.asyncio
    async def test_send_retries_with_fresh_token_on_errcode_42001(self):
        """errcode=42001 (token expired) must also trigger the refresh-retry path."""
        adapter = WecomCallbackAdapter(_config())
        adapter._access_tokens["test-app"] = {"token": "expired", "expires_at": 9999999999}

        responses = [
            {"errcode": 42001, "errmsg": "access_token expired"},
            {"errcode": 0, "msgid": "msg-42"},
        ]
        post_calls = []

        class FakeClient:
            async def post(self, url, json=None, **kw):
                post_calls.append(url)

                class R:
                    def json(inner):
                        return responses[len(post_calls) - 1]
                return R()

            async def get(self, url, params=None, **kw):
                class R:
                    def json(inner):
                        return {"errcode": 0, "access_token": "renewed", "expires_in": 7200}
                return R()

        adapter._http_client = FakeClient()
        result = await adapter.send("alice", "hello")

        assert result.success is True
        assert len(post_calls) == 2

    @pytest.mark.asyncio
    async def test_send_does_not_retry_on_non_token_errcode(self):
        """Errors unrelated to token validity must fail immediately without retrying."""
        adapter = WecomCallbackAdapter(_config())
        adapter._access_tokens["test-app"] = {"token": "good", "expires_at": 9999999999}

        post_calls = []

        class FakeClient:
            async def post(self, url, json=None, **kw):
                post_calls.append(url)

                class R:
                    def json(inner):
                        return {"errcode": 60020, "errmsg": "not allow to access"}
                return R()

        adapter._http_client = FakeClient()
        result = await adapter.send("alice", "hello")

        assert result.success is False
        assert len(post_calls) == 1

    @pytest.mark.asyncio
    async def test_send_fails_cleanly_when_retry_also_fails(self):
        """If the refreshed token is also rejected, return failure without looping further."""
        adapter = WecomCallbackAdapter(_config())
        adapter._access_tokens["test-app"] = {"token": "bad1", "expires_at": 9999999999}

        post_calls = []

        class FakeClient:
            async def post(self, url, json=None, **kw):
                post_calls.append(url)

                class R:
                    def json(inner):
                        return {"errcode": 42001, "errmsg": "access_token expired"}
                return R()

            async def get(self, url, params=None, **kw):
                class R:
                    def json(inner):
                        return {"errcode": 0, "access_token": "bad2", "expires_in": 7200}
                return R()

        adapter._http_client = FakeClient()
        result = await adapter.send("alice", "hello")

        assert result.success is False
        assert len(post_calls) == 2


class TestWecomCallbackPollLoop:
    @pytest.mark.asyncio
    async def test_poll_loop_dispatches_handle_message(self, monkeypatch):
        adapter = WecomCallbackAdapter(_config())
        calls = []

        async def fake_handle_message(event):
            calls.append(event.text)

        monkeypatch.setattr(adapter, "handle_message", fake_handle_message)
        event = adapter._build_event(
            _app(),
            """
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>lisi</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>test</Content>
              <MsgId>m2</MsgId>
            </xml>
            """,
        )
        task = asyncio.create_task(adapter._poll_loop())
        await adapter._message_queue.put(event)
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert calls == ["test"]


class TestWecomCallbackYouPetBridge:
    @pytest.mark.asyncio
    async def test_concurrent_redelivery_waits_for_inflight_dispatch_without_double_send(self):
        adapter = WecomCallbackAdapter(_config())
        event = adapter._build_event(
            _app(),
            """
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>done</Content>
              <MsgId>m-concurrent</MsgId>
            </xml>
            """,
        )
        dispatch_started = asyncio.Event()
        allow_dispatch = asyncio.Event()
        calls = []

        async def fake_dispatch(inbound_event, app):
            calls.append((inbound_event.message_id, app["name"]))
            dispatch_started.set()
            await allow_dispatch.wait()
            return True

        adapter._decrypt_request = lambda *args: "<xml/>"
        adapter._build_event = lambda *args: event
        adapter._dispatch_youpet_bridge = fake_dispatch

        first = asyncio.create_task(adapter._handle_callback(_CallbackRequest()))
        await dispatch_started.wait()
        second = asyncio.create_task(adapter._handle_callback(_CallbackRequest()))
        await asyncio.sleep(0)

        assert calls == [("m-concurrent", "test-app")]

        allow_dispatch.set()
        first_response, second_response = await asyncio.gather(first, second)

        assert first_response.status == 200
        assert second_response.status == 200
        dedup_key = adapter._message_dedup_key(_app(), "m-concurrent")
        assert adapter._seen_messages[dedup_key] > 0
        assert dedup_key not in adapter._inflight_messages
        assert calls == [("m-concurrent", "test-app")]

    @pytest.mark.asyncio
    async def test_cancelled_inflight_dispatch_releases_reservation_for_retry(self):
        adapter = WecomCallbackAdapter(_config())
        event = adapter._build_event(
            _app(),
            """
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>done</Content>
              <MsgId>m-cancelled</MsgId>
            </xml>
            """,
        )
        dispatch_started = asyncio.Event()
        never_finish_first_dispatch = asyncio.Event()
        calls = []

        async def fake_dispatch(inbound_event, app):
            calls.append((inbound_event.message_id, app["name"]))
            if len(calls) == 1:
                dispatch_started.set()
                await never_finish_first_dispatch.wait()
            return True

        adapter._decrypt_request = lambda *args: "<xml/>"
        adapter._build_event = lambda *args: event
        adapter._dispatch_youpet_bridge = fake_dispatch

        first = asyncio.create_task(adapter._handle_callback(_CallbackRequest()))
        await dispatch_started.wait()
        dedup_key = adapter._message_dedup_key(_app(), "m-cancelled")
        assert dedup_key in adapter._inflight_messages

        waiting_duplicate = asyncio.create_task(adapter._handle_callback(_CallbackRequest()))
        await asyncio.sleep(0)
        assert calls == [("m-cancelled", "test-app")]

        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        duplicate_response = await waiting_duplicate

        assert duplicate_response.status == 502
        assert dedup_key not in adapter._inflight_messages
        assert dedup_key not in adapter._seen_messages

        retry_response = await adapter._handle_callback(_CallbackRequest())

        assert retry_response.status == 200
        assert adapter._seen_messages[dedup_key] > 0
        assert dedup_key not in adapter._inflight_messages
        assert calls == [
            ("m-cancelled", "test-app"),
            ("m-cancelled", "test-app"),
        ]

    @pytest.mark.asyncio
    async def test_core_failure_does_not_retain_dedup_record_before_retry(self):
        adapter = WecomCallbackAdapter(_config())
        event = adapter._build_event(
            _app(),
            """
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>done</Content>
              <MsgId>m-retry</MsgId>
            </xml>
            """,
        )
        calls = []

        async def fake_dispatch(inbound_event, app):
            calls.append((inbound_event.message_id, app["name"]))
            if len(calls) == 1:
                raise YouPetBridgeError("temporary core failure")
            return True

        adapter._decrypt_request = lambda *args: "<xml/>"
        adapter._build_event = lambda *args: event
        adapter._dispatch_youpet_bridge = fake_dispatch

        first = await adapter._handle_callback(_CallbackRequest())
        assert first.status == 502
        dedup_key = adapter._message_dedup_key(_app(), "m-retry")
        assert dedup_key not in adapter._seen_messages

        second = await adapter._handle_callback(_CallbackRequest())
        assert second.status == 200
        assert adapter._seen_messages[dedup_key] > 0
        assert calls == [("m-retry", "test-app"), ("m-retry", "test-app")]
        assert adapter._message_queue.empty()

        duplicate = await adapter._handle_callback(_CallbackRequest())
        assert duplicate.status == 200
        assert calls == [("m-retry", "test-app"), ("m-retry", "test-app")]

    @pytest.mark.asyncio
    async def test_stale_or_invalid_timestamp_rejected_before_decrypt(self, monkeypatch):
        adapter = WecomCallbackAdapter(_config())
        now = 1_700_000_000
        monkeypatch.setattr("gateway.platforms.wecom_callback.time.time", lambda: now)
        decrypt_calls = []

        def fail_if_called(*args):
            decrypt_calls.append(args)
            return "<xml/>"

        adapter._decrypt_request = fail_if_called

        for timestamp in (now - 301, now + 301, "", "not-a-timestamp"):
            request = _CallbackRequest(query={"timestamp": str(timestamp)})
            response = await adapter._handle_callback(request)

            assert response.status == 403
            assert request.text_called is False

        assert decrypt_calls == []

        for timestamp in (now - 300, now + 300):
            request = _CallbackRequest(query={"timestamp": str(timestamp)})
            response = await adapter._handle_callback(request)

            assert response.status == 200
            assert request.text_called is True

        assert len(decrypt_calls) == 2

    @pytest.mark.asyncio
    async def test_successful_message_replay_is_persisted_across_restart(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        now = 1_700_000_000
        monkeypatch.setattr("gateway.platforms.wecom_callback.time.time", lambda: now)
        event = WecomCallbackAdapter(_config())._build_event(
            _app(),
            """
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>done</Content>
              <MsgId>m-persisted</MsgId>
            </xml>
            """,
        )
        calls = []

        async def dispatch_once(inbound_event, app):
            calls.append((inbound_event.message_id, app["name"]))
            return True

        adapter_a = WecomCallbackAdapter(_config())
        adapter_a._decrypt_request = lambda *args: "<xml/>"
        adapter_a._build_event = lambda *args: event
        adapter_a._dispatch_youpet_bridge = dispatch_once

        first = await adapter_a._handle_callback(_CallbackRequest(timestamp=now))

        assert first.status == 200
        assert calls == [("m-persisted", "test-app")]
        dedup_key = adapter_a._message_dedup_key(_app(), "m-persisted")
        persisted = json.loads((tmp_path / "wecom_callback" / "replay_dedup.json").read_text())
        assert persisted["seen_messages"][dedup_key] == now

        replay_calls = []

        async def dispatch_replay(inbound_event, app):
            replay_calls.append((inbound_event.message_id, app["name"]))
            return True

        adapter_b = WecomCallbackAdapter(_config())
        adapter_b._decrypt_request = lambda *args: "<xml/>"
        adapter_b._build_event = lambda *args: event
        adapter_b._dispatch_youpet_bridge = dispatch_replay

        replay = await adapter_b._handle_callback(_CallbackRequest(timestamp=now))

        assert replay.status == 200
        assert replay_calls == []
        assert adapter_b._message_queue.empty()

    @pytest.mark.asyncio
    async def test_future_dated_callback_cannot_replay_after_one_window(self, monkeypatch):
        now = 1_700_000_000
        signed_timestamp = now + 299
        current_time = {"value": now}
        monkeypatch.setattr(
            "gateway.platforms.wecom_callback.time.time",
            lambda: current_time["value"],
        )
        adapter = WecomCallbackAdapter(_config())
        event = adapter._build_event(
            _app(),
            """
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>done</Content>
              <MsgId>m-future-window</MsgId>
            </xml>
            """,
        )
        calls = []

        async def dispatch(inbound_event, app):
            calls.append((inbound_event.message_id, app["name"]))
            return True

        adapter._decrypt_request = lambda *args: "<xml/>"
        adapter._build_event = lambda *args: event
        adapter._dispatch_youpet_bridge = dispatch

        first = await adapter._handle_callback(_CallbackRequest(timestamp=signed_timestamp))
        current_time["value"] = now + 301
        replay = await adapter._handle_callback(_CallbackRequest(timestamp=signed_timestamp))

        assert first.status == 200
        assert replay.status == 200
        assert calls == [("m-future-window", "test-app")]

    @pytest.mark.asyncio
    async def test_future_dated_callback_cannot_replay_at_inclusive_boundary(self, monkeypatch):
        now = 1_700_000_000
        signed_timestamp = now + 300
        current_time = {"value": now}
        monkeypatch.setattr(
            "gateway.platforms.wecom_callback.time.time",
            lambda: current_time["value"],
        )
        adapter = WecomCallbackAdapter(_config())
        event = adapter._build_event(
            _app(),
            """
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>done</Content>
              <MsgId>m-future-boundary</MsgId>
            </xml>
            """,
        )
        calls = []

        async def dispatch(inbound_event, app):
            calls.append((inbound_event.message_id, app["name"]))
            return True

        adapter._decrypt_request = lambda *args: "<xml/>"
        adapter._build_event = lambda *args: event
        adapter._dispatch_youpet_bridge = dispatch

        first = await adapter._handle_callback(_CallbackRequest(timestamp=signed_timestamp))
        current_time["value"] = now + 600
        replay = await adapter._handle_callback(_CallbackRequest(timestamp=signed_timestamp))

        assert first.status == 200
        assert replay.status == 200
        assert calls == [("m-future-boundary", "test-app")]

    @pytest.mark.asyncio
    async def test_over_cap_in_retention_entries_are_not_evicted(
        self, caplog, monkeypatch,
    ):
        now = 1_700_000_000
        monkeypatch.setattr("gateway.platforms.wecom_callback.time.time", lambda: now)
        adapter = WecomCallbackAdapter(_config())
        entry_count = MAX_PERSISTED_DEDUP_ENTRIES + 1
        oldest_msg_id = "m-over-cap-0"
        for index in range(entry_count):
            msg_id = f"m-over-cap-{index}"
            dedup_key = adapter._message_dedup_key(_app(), msg_id)
            adapter._seen_messages[dedup_key] = now - 599 + (index / 10_000)

        with caplog.at_level(logging.WARNING):
            adapter._persist_seen_messages()

        assert len(adapter._seen_messages) == entry_count
        persisted = json.loads(adapter._dedup_state_path.read_text(encoding="utf-8"))
        assert len(persisted["seen_messages"]) == entry_count
        assert "exceeding cap" in caplog.text
        assert str(adapter._dedup_state_path) in caplog.text

        event = adapter._build_event(
            _app(),
            f"""
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>done</Content>
              <MsgId>{oldest_msg_id}</MsgId>
            </xml>
            """,
        )
        calls = []

        async def dispatch(inbound_event, app):
            calls.append((inbound_event.message_id, app["name"]))
            return True

        adapter._decrypt_request = lambda *args: "<xml/>"
        adapter._build_event = lambda *args: event
        adapter._dispatch_youpet_bridge = dispatch

        replay = await adapter._handle_callback(_CallbackRequest(timestamp=now))

        assert replay.status == 200
        assert calls == []
        oldest_key = adapter._message_dedup_key(_app(), oldest_msg_id)
        assert oldest_key in adapter._seen_messages

    def test_over_cap_trim_still_prunes_expired_entries(self, monkeypatch):
        now = 1_700_000_000
        monkeypatch.setattr("gateway.platforms.wecom_callback.time.time", lambda: now)
        adapter = WecomCallbackAdapter(_config())
        valid = {
            adapter._message_dedup_key(_app(), f"m-valid-{index}"): now - index
            for index in range(3)
        }
        expired = {
            adapter._message_dedup_key(
                _app(), f"m-expired-{index}",
            ): now - adapter._dedup_retention_seconds - 1 - index
            for index in range(MAX_PERSISTED_DEDUP_ENTRIES + 5)
        }
        adapter._seen_messages = {**expired, **valid}

        adapter._persist_seen_messages()

        assert adapter._seen_messages == valid
        persisted = json.loads(adapter._dedup_state_path.read_text(encoding="utf-8"))
        assert persisted["seen_messages"] == valid

    @pytest.mark.asyncio
    async def test_expired_seen_record_is_deleted_and_reprocessed(self, monkeypatch):
        now = 1_700_000_000
        current_time = {"value": now}
        monkeypatch.setattr(
            "gateway.platforms.wecom_callback.time.time",
            lambda: current_time["value"],
        )
        adapter = WecomCallbackAdapter(_config())
        event = adapter._build_event(
            _app(),
            """
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>done</Content>
              <MsgId>m-expired-seen</MsgId>
            </xml>
            """,
        )
        dedup_key = adapter._message_dedup_key(_app(), "m-expired-seen")
        adapter._seen_messages[dedup_key] = now
        adapter._persist_seen_messages()
        current_time["value"] = now + adapter._dedup_retention_seconds + 1
        calls = []

        async def dispatch(inbound_event, app):
            calls.append((inbound_event.message_id, app["name"]))
            return True

        adapter._decrypt_request = lambda *args: "<xml/>"
        adapter._build_event = lambda *args: event
        adapter._dispatch_youpet_bridge = dispatch

        response = await adapter._handle_callback(
            _CallbackRequest(timestamp=current_time["value"]),
        )

        assert response.status == 200
        assert calls == [("m-expired-seen", "test-app")]
        assert adapter._seen_messages[dedup_key] == current_time["value"]
        persisted = json.loads(adapter._dedup_state_path.read_text(encoding="utf-8"))
        assert persisted["seen_messages"][dedup_key] == current_time["value"]

    @pytest.mark.asyncio
    async def test_persist_failure_logs_warning_but_keeps_in_memory_dedup(
        self, caplog, monkeypatch,
    ):
        now = 1_700_000_000
        monkeypatch.setattr("gateway.platforms.wecom_callback.time.time", lambda: now)

        def fail_atomic_write(*args, **kwargs):
            raise OSError("permission denied")

        monkeypatch.setattr(
            "gateway.platforms.wecom_callback.atomic_json_write",
            fail_atomic_write,
        )
        adapter = WecomCallbackAdapter(_config())
        event = adapter._build_event(
            _app(),
            """
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>done</Content>
              <MsgId>m-persist-oserror</MsgId>
            </xml>
            """,
        )
        calls = []

        async def dispatch(inbound_event, app):
            calls.append((inbound_event.message_id, app["name"]))
            return True

        adapter._decrypt_request = lambda *args: "<xml/>"
        adapter._build_event = lambda *args: event
        adapter._dispatch_youpet_bridge = dispatch

        with caplog.at_level(logging.WARNING):
            first = await adapter._handle_callback(_CallbackRequest(timestamp=now))
            replay = await adapter._handle_callback(_CallbackRequest(timestamp=now))

        assert first.status == 200
        assert replay.status == 200
        assert calls == [("m-persist-oserror", "test-app")]
        assert "Failed to persist replay dedup state" in caplog.text
        dedup_key = adapter._message_dedup_key(_app(), "m-persist-oserror")
        assert dedup_key in adapter._seen_messages

    def test_replay_window_config_falls_back_and_valid_override_is_honored(
        self, monkeypatch,
    ):
        now = 1_700_000_000
        monkeypatch.setattr("gateway.platforms.wecom_callback.time.time", lambda: now)

        for raw_value in ("abc", -1, 0):
            adapter = WecomCallbackAdapter(
                PlatformConfig(
                    enabled=True,
                    extra={
                        "mode": "callback",
                        "host": "127.0.0.1",
                        "port": 0,
                        "apps": [_app()],
                        "replay_window_seconds": raw_value,
                    },
                ),
            )
            assert adapter._replay_window_seconds == MESSAGE_DEDUP_TTL_SECONDS

        adapter = WecomCallbackAdapter(
            PlatformConfig(
                enabled=True,
                extra={
                    "mode": "callback",
                    "host": "127.0.0.1",
                    "port": 0,
                    "apps": [_app()],
                    "replay_window_seconds": 600,
                },
            ),
        )

        assert adapter._timestamp_is_fresh(str(now - 600)) is True
        assert adapter._timestamp_is_fresh(str(now + 600)) is True
        assert adapter._timestamp_is_fresh(str(now - 601)) is False

    @pytest.mark.asyncio
    async def test_failed_dispatch_does_not_persist_replay_record_across_restart(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        now = 1_700_000_000
        monkeypatch.setattr("gateway.platforms.wecom_callback.time.time", lambda: now)
        event = WecomCallbackAdapter(_config())._build_event(
            _app(),
            """
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>done</Content>
              <MsgId>m-failed-then-retry</MsgId>
            </xml>
            """,
        )

        async def fail_dispatch(inbound_event, app):
            raise YouPetBridgeError("temporary core failure")

        adapter_a = WecomCallbackAdapter(_config())
        adapter_a._decrypt_request = lambda *args: "<xml/>"
        adapter_a._build_event = lambda *args: event
        adapter_a._dispatch_youpet_bridge = fail_dispatch

        first = await adapter_a._handle_callback(_CallbackRequest(timestamp=now))

        assert first.status == 502
        state_path = tmp_path / "wecom_callback" / "replay_dedup.json"
        assert not state_path.exists()

        calls = []

        async def dispatch_retry(inbound_event, app):
            calls.append((inbound_event.message_id, app["name"]))
            return True

        adapter_b = WecomCallbackAdapter(_config())
        adapter_b._decrypt_request = lambda *args: "<xml/>"
        adapter_b._build_event = lambda *args: event
        adapter_b._dispatch_youpet_bridge = dispatch_retry

        retry = await adapter_b._handle_callback(_CallbackRequest(timestamp=now))

        assert retry.status == 200
        assert calls == [("m-failed-then-retry", "test-app")]

    def test_corrupt_persisted_dedup_state_is_ignored(self, caplog, monkeypatch, tmp_path):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        state_path = tmp_path / "wecom_callback" / "replay_dedup.json"
        state_path.parent.mkdir(parents=True)
        state_path.write_text("{not-json", encoding="utf-8")

        with caplog.at_level(logging.WARNING):
            adapter = WecomCallbackAdapter(_config())

        assert adapter._seen_messages == {}
        assert "Failed to load replay dedup state" in caplog.text

    def test_persisted_dedup_state_prunes_bad_expired_and_future_entries(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        now = 1_700_000_000
        monkeypatch.setattr("gateway.platforms.wecom_callback.time.time", lambda: now)
        state_path = tmp_path / "wecom_callback" / "replay_dedup.json"
        state_path.parent.mkdir(parents=True)
        state_path.write_text(
            json.dumps(
                {
                    "seen_messages": {
                        "valid": now - 10,
                        "retained_for_future_skew": now - 301,
                        "retained_at_boundary": now - 600,
                        "expired": now - 601,
                        "future": now + 10,
                        "bad": "not-a-timestamp",
                    }
                }
            ),
            encoding="utf-8",
        )

        adapter = WecomCallbackAdapter(_config())

        assert adapter._seen_messages == {
            "valid": now - 10,
            "retained_for_future_skew": now - 301,
            "retained_at_boundary": now - 600,
        }

    def test_dedup_key_is_scoped_by_callback_app(self):
        app_a = _app(name="app-a", corp_id="corp-a", agent_id="100")
        app_b = _app(name="app-b", corp_id="corp-b", agent_id="100")

        assert (
            WecomCallbackAdapter._message_dedup_key(app_a, "same-msg-id")
            != WecomCallbackAdapter._message_dedup_key(app_b, "same-msg-id")
        )

    @pytest.mark.asyncio
    async def test_same_msg_id_from_different_apps_does_not_cross_dedup(self, monkeypatch):
        now = 1_700_000_000
        monkeypatch.setattr("gateway.platforms.wecom_callback.time.time", lambda: now)
        app_a = _app(name="app-a", corp_id="same-corp", agent_id="100")
        app_b = _app(name="app-b", corp_id="same-corp", agent_id="200")
        adapter = WecomCallbackAdapter(_config(apps=[app_a, app_b]))
        event_a = adapter._build_event(
            app_a,
            """
            <xml>
              <ToUserName>same-corp</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>first</Content>
              <MsgId>m-shared</MsgId>
            </xml>
            """,
        )
        event_b = adapter._build_event(
            app_b,
            """
            <xml>
              <ToUserName>same-corp</ToUserName>
              <FromUserName>lisi</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>second</Content>
              <MsgId>m-shared</MsgId>
            </xml>
            """,
        )
        target_app = {"name": "app-a"}
        calls = []

        def decrypt_for_target(app, *args):
            if app["name"] != target_app["name"]:
                raise WeComCryptoError("wrong app")
            return "<xml/>"

        def build_event_for_target(app, *args):
            return event_a if app["name"] == "app-a" else event_b

        async def dispatch(inbound_event, app):
            calls.append((inbound_event.text, inbound_event.message_id, app["name"]))
            return True

        adapter._decrypt_request = decrypt_for_target
        adapter._build_event = build_event_for_target
        adapter._dispatch_youpet_bridge = dispatch

        first = await adapter._handle_callback(_CallbackRequest(timestamp=now))
        target_app["name"] = "app-b"
        second = await adapter._handle_callback(_CallbackRequest(timestamp=now))

        assert first.status == 200
        assert second.status == 200
        assert calls == [
            ("first", "m-shared", "app-a"),
            ("second", "m-shared", "app-b"),
        ]

    @pytest.mark.asyncio
    async def test_youpet_bridge_can_skip_agent_dispatch(self):
        adapter = WecomCallbackAdapter(_config())
        event = adapter._build_event(
            _app(),
            """
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>done</Content>
              <MsgId>m3</MsgId>
            </xml>
            """,
        )

        class FakeBridge:
            def __init__(self):
                self.calls = []

            async def handle_wecom_event(self, inbound_event, app):
                self.calls.append((inbound_event.message_id, app["name"]))
                return True

        bridge = FakeBridge()
        adapter._youpet_bridge = bridge

        skip_agent_dispatch = await adapter._dispatch_youpet_bridge(event, _app())

        assert skip_agent_dispatch is True
        assert bridge.calls == [("m3", "test-app")]

    @pytest.mark.asyncio
    async def test_youpet_bridge_can_allow_agent_dispatch(self):
        adapter = WecomCallbackAdapter(_config())
        event = adapter._build_event(
            _app(),
            """
            <xml>
              <ToUserName>ww1234567890</ToUserName>
              <FromUserName>zhangsan</FromUserName>
              <CreateTime>1710000000</CreateTime>
              <MsgType>text</MsgType>
              <Content>done</Content>
              <MsgId>m4</MsgId>
            </xml>
            """,
        )

        class FakeBridge:
            async def handle_wecom_event(self, inbound_event, app):
                return False

        adapter._youpet_bridge = FakeBridge()

        skip_agent_dispatch = await adapter._dispatch_youpet_bridge(event, _app())

        assert skip_agent_dispatch is False
