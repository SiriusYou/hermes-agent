"""Optional YouPet Core bridge for the WeCom callback adapter."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional, TypedDict

import httpx
try:
    import defusedxml.ElementTree as ET
except ImportError:  # pragma: no cover - callback adapter already requires defusedxml
    ET = None  # type: ignore[assignment]

from hermes_constants import get_hermes_home
from gateway.config import Platform
from gateway.platforms.base import MessageEvent, SendResult
from utils import atomic_replace

logger = logging.getLogger(__name__)

HERMES_CONSUMER = "hermes"
YOUPET_SOURCE = "hermes_wecom"
MAX_PROCESSED_EVENT_IDS = 1000
SUPPORTED_OUTBOX_EVENTS = {
    "health_plan.activated",
    "task.created",
    "task.reminder_due",
    "task.escalated",
    "alert.created",
}


class YouPetBridgeError(RuntimeError):
    """Raised when the YouPet bridge cannot complete a required side effect."""


SendCallable = Callable[[str, str], Awaitable[SendResult]]


class YouPetPollCounts(TypedDict):
    pulled: int
    processed: int
    sent: int
    acked: int
    nacked: int
    skipped: int


@dataclass
class YouPetBridgeSettings:
    enabled: bool = False
    core_base_url: str = ""
    service_token: str = ""
    actor_id: str = "hermes-wecom-bridge"
    source: str = YOUPET_SOURCE
    outbox_consumer: str = HERMES_CONSUMER
    outbox_poll_enabled: bool = True
    outbox_poll_interval_seconds: float = 5.0
    outbox_limit: int = 20
    skip_agent_dispatch: bool = True
    ack_unhandled_events: bool = True
    corp_id: Optional[str] = None
    default_chat_id: Optional[str] = None
    user_chat_map: dict[str, str] = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.enabled and self.core_base_url and self.service_token)


def build_youpet_bridge_from_env(send: SendCallable) -> Optional["YouPetBridge"]:
    settings = youpet_settings_from_env()
    if not settings.enabled:
        return None
    return YouPetBridge(settings, send)


def _poll_counts() -> YouPetPollCounts:
    return {
        "pulled": 0,
        "processed": 0,
        "sent": 0,
        "acked": 0,
        "nacked": 0,
        "skipped": 0,
    }


def youpet_settings_from_env() -> YouPetBridgeSettings:
    user_chat_map: dict[str, str] = {}
    raw_map = os.getenv("YOUPET_WECOM_USER_CHAT_MAP_JSON", "").strip()
    if raw_map:
        try:
            decoded = json.loads(raw_map)
            if isinstance(decoded, dict):
                user_chat_map = {
                    str(key): str(value)
                    for key, value in decoded.items()
                    if key and value
                }
        except json.JSONDecodeError:
            logger.warning("[YouPetBridge] Invalid YOUPET_WECOM_USER_CHAT_MAP_JSON")

    return YouPetBridgeSettings(
        enabled=_env_bool("YOUPET_WECOM_BRIDGE_ENABLED", default=False),
        core_base_url=os.getenv("YOUPET_CORE_BASE_URL", "").rstrip("/"),
        service_token=os.getenv("YOUPET_SERVICE_TOKEN", ""),
        actor_id=os.getenv("YOUPET_ACTOR_ID", "hermes-wecom-bridge"),
        source=os.getenv("YOUPET_WECOM_SOURCE", YOUPET_SOURCE),
        outbox_consumer=os.getenv("YOUPET_OUTBOX_CONSUMER", HERMES_CONSUMER),
        outbox_poll_enabled=_env_bool("YOUPET_OUTBOX_POLL_ENABLED", default=True),
        outbox_poll_interval_seconds=_env_float(
            "YOUPET_OUTBOX_POLL_INTERVAL_SECONDS", default=5.0,
        ),
        outbox_limit=_env_int("YOUPET_OUTBOX_LIMIT", default=20),
        skip_agent_dispatch=_env_bool("YOUPET_WECOM_SKIP_AGENT_DISPATCH", default=True),
        ack_unhandled_events=_env_bool("YOUPET_OUTBOX_ACK_UNHANDLED_EVENTS", default=True),
        corp_id=(
            os.getenv("YOUPET_WECOM_CORP_ID")
            or os.getenv("WECOM_CALLBACK_CORP_ID")
            or None
        ),
        default_chat_id=os.getenv("YOUPET_WECOM_DEFAULT_CHAT_ID") or None,
        user_chat_map=user_chat_map,
    )


class YouPetBridge:
    """Bridge WeCom callback events and YouPet Core outbox events."""

    def __init__(self, settings: YouPetBridgeSettings, send: SendCallable):
        self.settings = settings
        self._send = send
        self._client: Optional[httpx.AsyncClient] = None
        self._poll_task: Optional[asyncio.Task] = None
        self._runtime_user_chat_map: dict[str, str] = {}
        self._processed_event_id_order = self._load_processed_event_ids()
        self._processed_event_ids = set(self._processed_event_id_order)

    async def start(self) -> None:
        if not self.settings.configured:
            logger.warning(
                "[YouPetBridge] Enabled but not configured; set "
                "YOUPET_CORE_BASE_URL and YOUPET_SERVICE_TOKEN",
            )
            return
        self._ensure_client()
        if self.settings.outbox_poll_enabled and self._poll_task is None:
            self._poll_task = asyncio.create_task(self._poll_loop())
            logger.info("[YouPetBridge] Started Core outbox poller")

    async def stop(self) -> None:
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            self._poll_task = None
        if self._client:
            await self._client.aclose()
            self._client = None

    async def handle_wecom_event(self, event: MessageEvent, app: dict[str, Any]) -> bool:
        if not self.settings.configured:
            return False
        if not is_wecom_pre_core_authorized(event):
            source = event.source
            logger.info(
                "[YouPetBridge] Ignoring unauthorized WeCom inbound user=%s chat=%s platform=%s",
                getattr(source, "user_id", None),
                getattr(source, "chat_id", None),
                getattr(getattr(source, "platform", None), "value", getattr(source, "platform", None)),
            )
            return True
        payload = self._build_inbound_payload(event, app)
        response = await self._post(
            "/api/v1/wecom/inbound",
            json=payload,
            headers=self._headers(
                correlation_id=f"corr_wecom_{payload['corp_id']}_{payload['message_id']}",
                idempotency_key=f"wecom:{payload['corp_id']}:{payload['message_id']}",
            ),
        )
        data = _response_json(response)
        matched_user_id = data.get("matched_user_id")
        if matched_user_id and event.source and event.source.chat_id:
            self._runtime_user_chat_map[str(matched_user_id)] = str(event.source.chat_id)
        return self.settings.skip_agent_dispatch

    async def poll_once(self) -> YouPetPollCounts:
        counts = _poll_counts()
        if not self.settings.configured:
            return counts
        response = await self._get(
            "/internal/events/outbox",
            params={
                "consumer": self.settings.outbox_consumer,
                "limit": self.settings.outbox_limit,
            },
            headers=self._headers(),
        )
        items = _response_json(response).get("items", [])
        if not isinstance(items, list):
            raise YouPetBridgeError("Core outbox response did not contain items")

        counts["pulled"] = len(items)
        for item in items:
            counts["processed"] += 1
            if not isinstance(item, dict):
                counts["skipped"] += 1
                logger.error(
                    "[YouPetBridge] Skipping outbox item with missing event_id",
                )
                continue
            event_id = str(item.get("event_id") or "").strip()
            if not event_id:
                counts["skipped"] += 1
                logger.error(
                    "[YouPetBridge] Skipping outbox item with missing event_id",
                )
                continue
            try:
                if event_id in self._processed_event_ids:
                    await self._ack(event_id)
                    counts["acked"] += 1
                    continue
                sent = await self._process_outbox_item(item)
                if sent:
                    counts["sent"] += 1
                self._remember_processed_event_id(event_id)
                await self._ack(event_id)
                counts["acked"] += 1
            except Exception as exc:
                logger.warning(
                    "[YouPetBridge] Failed to process outbox event %s: %s",
                    event_id,
                    exc,
                )
                await self._nack(event_id, str(exc))
                counts["nacked"] += 1
        return counts

    async def _poll_loop(self) -> None:
        while True:
            try:
                await self.poll_once()
            except Exception:
                logger.exception("[YouPetBridge] Outbox poll failed")
            await asyncio.sleep(self.settings.outbox_poll_interval_seconds)

    def _build_inbound_payload(self, event: MessageEvent, app: dict[str, Any]) -> dict[str, Any]:
        source = event.source
        corp_id = str(app.get("corp_id") or self.settings.corp_id or "")
        if not corp_id and source and source.chat_id and ":" in source.chat_id:
            corp_id = source.chat_id.split(":", 1)[0]
        user_id = str(getattr(source, "user_id", "") or "")
        chat_type = str(getattr(source, "chat_type", "") or "").lower()
        chat_id = str(getattr(source, "chat_id", "") or "")
        media = _wecom_media_metadata(event)
        message_type = _core_message_type(event, media)
        return {
            "corp_id": corp_id,
            "source": self.settings.source,
            "conversation_type": "group" if chat_type == "group" else "dm",
            "wecom_user_id": user_id or None,
            "wecom_group_id": chat_id if chat_type == "group" else None,
            "message_id": str(event.message_id or ""),
            "message_type": message_type,
            "text": event.text or None,
            "media": media,
            "received_at": _iso_utc(event.timestamp),
        }

    async def _process_outbox_item(self, item: dict[str, Any]) -> bool:
        event_type = str(item.get("event_type") or "")
        envelope = item.get("payload") if isinstance(item.get("payload"), dict) else {}
        if not event_type:
            event_type = str(envelope.get("event_type") or "")

        if event_type not in SUPPORTED_OUTBOX_EVENTS:
            logger.info("[YouPetBridge] Acknowledging unhandled outbox event type: %s", event_type)
            return False

        if event_type == "health_plan.activated":
            return False

        payload = self._business_payload(envelope, event_type)

        if event_type in {"task.created", "task.reminder_due"}:
            chat_id = self._resolve_chat_id(payload, ("recipient_user_id", "owner_user_id"))
            await self._send_required(chat_id, self._render_task_message(event_type, payload))
            return True

        if event_type == "task.escalated":
            chat_id = self._resolve_chat_id(
                payload,
                ("recipient_user_id",),
                allow_default=False,
            )
            await self._send_required(chat_id, self._render_alert_message(event_type, payload))
            return True

        if event_type == "alert.created":
            logger.info("[YouPetBridge] Acknowledging alert.created without WeCom send")
            return False

        chat_id = self._resolve_chat_id(
            payload,
            ("recipient_user_id", "owner_user_id", "assigned_to"),
        )
        await self._send_required(chat_id, self._render_alert_message(event_type, payload))
        return True

    @staticmethod
    def _business_payload(envelope: dict[str, Any], event_type: str) -> dict[str, Any]:
        payload = envelope.get("payload")
        if isinstance(payload, dict):
            return payload
        raise YouPetBridgeError(f"Malformed YouPet {event_type} payload")

    def _load_processed_event_ids(self) -> list[str]:
        path = self._processed_event_state_path()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        raw_ids = data.get("event_ids") if isinstance(data, dict) else None
        if not isinstance(raw_ids, list):
            return []
        return [str(item) for item in raw_ids[-MAX_PROCESSED_EVENT_IDS:] if item]

    def _remember_processed_event_id(self, event_id: str) -> None:
        if not event_id or event_id in self._processed_event_ids:
            return
        self._processed_event_ids.add(event_id)
        self._processed_event_id_order.append(event_id)
        if len(self._processed_event_id_order) > MAX_PROCESSED_EVENT_IDS:
            evicted = self._processed_event_id_order.pop(0)
            self._processed_event_ids.discard(evicted)

        path = self._processed_event_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(".tmp")
        tmp_path.write_text(
            json.dumps({"event_ids": self._processed_event_id_order}, indent=2) + "\n",
            encoding="utf-8",
        )
        atomic_replace(tmp_path, path)

    @staticmethod
    def _processed_event_state_path() -> Path:
        return get_hermes_home() / "integrations" / "youpet_processed_outbox_events.json"

    def _resolve_chat_id(
        self,
        payload: dict[str, Any],
        user_keys: tuple[str, ...],
        *,
        allow_default: bool = True,
    ) -> str:
        for key in user_keys:
            user_id = payload.get(key)
            if not user_id:
                continue
            chat_id = (
                self._runtime_user_chat_map.get(str(user_id))
                or self.settings.user_chat_map.get(str(user_id))
            )
            if chat_id:
                return chat_id
        if allow_default and self.settings.default_chat_id:
            return self.settings.default_chat_id
        raise YouPetBridgeError("No WeCom chat_id for YouPet outbox recipient")

    async def _send_required(self, chat_id: str, content: str) -> None:
        result = await self._send(chat_id, content)
        if isinstance(result, SendResult) and not result.success:
            raise YouPetBridgeError(result.error or "WeCom send failed")

    async def _ack(self, event_id: str) -> None:
        if not event_id:
            raise YouPetBridgeError("Missing outbox event_id")
        await self._post(
            f"/internal/events/outbox/{event_id}/ack",
            params={"consumer": self.settings.outbox_consumer},
            headers=self._headers(),
        )

    async def _nack(self, event_id: str, error: str) -> None:
        if not event_id:
            logger.warning("[YouPetBridge] Cannot nack outbox event without event_id")
            return
        await self._post(
            f"/internal/events/outbox/{event_id}/nack",
            params={"consumer": self.settings.outbox_consumer},
            json={"error": error[:1000]},
            headers=self._headers(),
        )

    async def _get(self, path: str, **kwargs: Any) -> httpx.Response:
        response = await self._ensure_client().get(self._url(path), **kwargs)
        _raise_for_status(response, path)
        return response

    async def _post(self, path: str, **kwargs: Any) -> httpx.Response:
        response = await self._ensure_client().post(self._url(path), **kwargs)
        _raise_for_status(response, path)
        return response

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=20.0)
        return self._client

    def _url(self, path: str) -> str:
        return f"{self.settings.core_base_url}{path}"

    def _headers(
        self,
        *,
        correlation_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.settings.service_token}",
            "X-Actor-Id": self.settings.actor_id,
        }
        if correlation_id:
            headers["X-Correlation-Id"] = correlation_id
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    @staticmethod
    def _render_task_message(event_type: str, payload: dict[str, Any]) -> str:
        context = payload.get("message_context") if isinstance(payload.get("message_context"), dict) else {}
        pet_name = context.get("pet_name") or payload.get("pet_id") or "your pet"
        plan_title = context.get("plan_title") or payload.get("task_type") or "care task"
        due_at = payload.get("due_at")
        if event_type == "task.created":
            suffix = f" Due at {due_at}." if due_at else ""
            return f"[YouPet] New care task for {pet_name}: {plan_title}.{suffix}"
        return f"[YouPet] Reminder for {pet_name}: {plan_title}. Reply when completed."

    @staticmethod
    def _render_alert_message(event_type: str, payload: dict[str, Any]) -> str:
        severity = payload.get("severity") or "alert"
        summary = payload.get("summary") or payload.get("alert_type") or event_type
        return f"[YouPet Alert] {severity}: {summary}"


def _env_bool(name: str, *, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, *, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, *, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def is_wecom_pre_core_authorized(event: MessageEvent) -> bool:
    """Return True when a WeCom inbound message may be written to Core.

    The normal gateway allowlist check runs after adapter dispatch. The YouPet
    bridge writes to Core before that boundary, so it needs the same env
    allowlist/allow-all contract at the bridge edge.
    """
    source = event.source
    if not source:
        return False
    platform = getattr(source, "platform", None)
    if platform == Platform.WECOM_CALLBACK:
        env_prefix = "WECOM_CALLBACK"
    elif platform == Platform.WECOM:
        env_prefix = "WECOM"
    else:
        return False

    if _env_bool(f"{env_prefix}_ALLOW_ALL_USERS", default=False):
        return True
    if _env_bool("GATEWAY_ALLOW_ALL_USERS", default=False):
        return True

    user_id = str(getattr(source, "user_id", "") or "").strip()
    allowed = _env_entries(f"{env_prefix}_ALLOWED_USERS") + _env_entries("GATEWAY_ALLOWED_USERS")
    if not allowed:
        return False
    return _entry_matches_any(allowed, [user_id])


def _env_entries(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


def _normalize_allow_entry(value: str) -> str:
    normalized = str(value or "").strip()
    normalized = re.sub(r"^wecom(_callback)?:", "", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"^user:", "", normalized, flags=re.IGNORECASE)
    return normalized.strip().lower()


def _entry_matches_any(entries: list[str], targets: list[str]) -> bool:
    normalized_targets = {_normalize_allow_entry(target) for target in targets if str(target or "").strip()}
    for entry in entries:
        normalized = _normalize_allow_entry(entry)
        if normalized == "*" or normalized in normalized_targets:
            return True
    return False


def _core_message_type(event: MessageEvent, media: list[dict[str, Any]]) -> str:
    raw = getattr(event.message_type, "value", str(event.message_type))
    if raw == "photo" and any(item.get("media_type") == "image" for item in media):
        return "image"
    return raw


def _wecom_media_metadata(event: MessageEvent) -> list[dict[str, Any]]:
    raw = event.raw_message
    if isinstance(raw, dict):
        body = raw.get("body") if isinstance(raw.get("body"), dict) else raw
        return _media_metadata_from_wecom_body(body)
    if isinstance(raw, str):
        return _media_metadata_from_callback_xml(raw)
    return []


def _media_metadata_from_callback_xml(xml_text: str) -> list[dict[str, Any]]:
    if ET is None:
        return []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return []
    msg_type = (root.findtext("MsgType") or "").lower()
    if msg_type != "image":
        return []
    media_id = root.findtext("MediaId") or root.findtext("PicUrl") or ""
    item = _media_metadata_item(
        "image",
        {
            "media_id": media_id,
            "filename": root.findtext("FileName"),
            "size": root.findtext("FileSize") or root.findtext("Size"),
        },
    )
    return [item] if item else []


def _media_metadata_from_wecom_body(body: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[tuple[str, dict[str, Any]]] = []
    msg_type = str(body.get("msgtype") or "").lower()
    if msg_type == "mixed":
        mixed = body.get("mixed") if isinstance(body.get("mixed"), dict) else {}
        items = mixed.get("msg_item") if isinstance(mixed.get("msg_item"), list) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            if str(item.get("msgtype") or "").lower() == "image" and isinstance(item.get("image"), dict):
                refs.append(("image", item["image"]))
    else:
        if isinstance(body.get("image"), dict):
            refs.append(("image", body["image"]))
        appmsg = body.get("appmsg") if isinstance(body.get("appmsg"), dict) else {}
        if isinstance(appmsg.get("image"), dict):
            refs.append(("image", appmsg["image"]))

    quote = body.get("quote") if isinstance(body.get("quote"), dict) else {}
    if str(quote.get("msgtype") or "").lower() == "image" and isinstance(quote.get("image"), dict):
        refs.append(("image", quote["image"]))

    metadata: list[dict[str, Any]] = []
    for kind, ref in refs:
        item = _media_metadata_item(kind, ref)
        if item:
            metadata.append(item)
    return metadata


def _media_metadata_item(kind: str, ref: dict[str, Any]) -> Optional[dict[str, Any]]:
    if kind != "image":
        return None
    media_id = _first_str(ref, ("media_id", "mediaid", "id", "file_id", "url"))
    if not media_id:
        return None
    item: dict[str, Any] = {
        "media_type": "image",
        "wecom_media_id": media_id,
    }
    filename = _first_str(ref, ("filename", "name", "title"))
    if filename:
        item["filename"] = filename
    size = _first_int(ref, ("size_bytes", "size", "filesize", "file_size"))
    if size is not None:
        item["size_bytes"] = size
    return item


def _first_str(payload: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = payload.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _first_int(payload: dict[str, Any], keys: tuple[str, ...]) -> Optional[int]:
    for key in keys:
        value = payload.get(key)
        if value is None or value == "":
            continue
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            continue
        if parsed >= 0:
            return parsed
    return None


def _iso_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _response_json(response: Any) -> dict[str, Any]:
    try:
        data = response.json()
    except Exception as exc:
        raise YouPetBridgeError("Core response was not JSON") from exc
    if not isinstance(data, dict):
        raise YouPetBridgeError("Core response JSON was not an object")
    return data


def _raise_for_status(response: Any, path: str) -> None:
    status_code = int(getattr(response, "status_code", 200) or 200)
    if status_code < 400:
        return
    body = getattr(response, "text", "")
    raise YouPetBridgeError(f"Core request failed {status_code} {path}: {body}")
