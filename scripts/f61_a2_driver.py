"""F6.1 A2 outbound evidence driver (WeCom AI Bot long connection).

Reviewed, committed test tooling — run ONLY from a hermes-agent checkout
whose tracked worktree exactly matches HEAD (startup enforces this). One
transport attempt per invocation: the driver never generates delivery IDs
(a correlation alias may be supplied), never decides retries, never
reconnects mid-run, and never degrades or falls back on its own.

Inbound safety: every mode installs a drop-only inbound guard before
connecting; the group-reply mode swaps in a restricted observer that applies
the configured group/sender policy and binds only on full-text equality with
the approved ``<mention-prefix> <marker>`` (first match wins). No mode
dispatches, bridges Core, or replies on its own. Retained external fields
are mapped to closed enums.

Outcome contract (three states):
  accepted_by_platform — explicit integer errcode == 0 on a response
                         correlated to the request req_id
  rejected_by_platform — explicit integer errcode != 0, correlated
  unknown              — timeout, disconnect, emission failure,
                         missing/malformed fields, or an uncorrelated
                         response

Every record carries exclusive_window_valid (no invalidating event classes
observed — the documented benign enter_chat does not invalidate),
observation_complete, case_criterion_met, and requires_rerun.

Credentials come from the launching shell (set -a; source ~/.hermes/.env).
Output is one JSON record with fixed classifications, latencies, lengths,
and equality relations only — never real IDs, req_ids, raw frames, or raw
errmsg text.

Subcommands:
  connect-check        connect, hold briefly, report takeover events
  send-dm              one aibot_send_msg to $F61_A2_DM_TARGET (A2-01 DM leg)
  send-group-reply     aibot_respond_msg once, bound to an inbound req_id
                       captured on THIS connection by full-text equality
                       with the approved '<mention-prefix> <marker>'
                       (A2-01 group leg)
  send-invalid         one aibot_send_msg to a deliberately invalid synthetic
                       target; never retried (A2-02)
  send-disconnect      emit aibot_send_msg, then close the socket with the
                       response future unresolved; outcome "unknown" unless a
                       trusted response demonstrably arrived first (A2-03)
  recall-capability    OFFLINE: pinned adapter command inventory vs the
                       documented command set; never connects (A2-05)
"""

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

INVALID_TARGET = "f61-invalid-target-0000"  # deliberately non-routable (A2-02)
MAX_CONTENT = 4000
REQUEST_TIMEOUT_SECONDS = 15.0
HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[1]
DRIVER_REL = "scripts/f61_a2_driver.py"
OFFICIAL_DOC_URL = "https://developer.work.weixin.qq.com/document/path/101463"
OFFICIAL_DOC_CHECKED_AT = "2026-08-15"

_CHATTYPE_LABELS = {"single", "group"}
_MSGTYPE_LABELS = {"text", "image", "file", "mixed", "voice", "event", "markdown", "appmsg"}


def _enum_label(value, allowed) -> str:
    """Map a provider-controlled value to a closed label set."""
    label = str(value or "").strip().lower()
    return label if label in allowed else "other"


# Error-code MEANINGS come from the official global errcode appendix
# (https://developer.work.weixin.qq.com/document/path/90313, checked
# 2026-08-15): 60011 no privilege for the specified member/dept/tag; 60111
# UserID does not exist; 81013 all of UserID/dept/tag illegal or
# unauthorized; 42001/42007 token expired; 45009 frequency limited.
# The permanent/transient split is PROJECT RETRY POLICY — "permanent" means
# "must not auto-retry the same request and configuration" — not a
# vendor-stated retry attribute. Only codes verified in the cited appendix
# appear here (45047 was removed 2026-08-15: absent from the appendix).
PERMANENT_TARGET_ERRCODES = {60011, 60111, 81013}
TRANSIENT_ERRCODES = {42001, 42007, 45009}


def retryability_class(errcode) -> str:
    """permanent | transient | unknown — from documented errcode sets only."""
    if isinstance(errcode, bool) or not isinstance(errcode, int):
        return "unknown"
    if errcode in PERMANENT_TARGET_ERRCODES:
        return "permanent"
    if errcode in TRANSIENT_ERRCODES:
        return "transient"
    return "unknown"


def classify_result(errcode, errmsg) -> str:
    """Map a platform result to a fixed error class. Never returns raw text.

    Only an explicit integer 0 is success; a missing/erroneous errcode is
    never success.
    """
    if isinstance(errcode, bool):
        return "other"
    if isinstance(errcode, int):
        if errcode == 0:
            return "success"
        if errcode in {40013, 40014, 42001, 42007}:
            return "auth"
        if errcode in PERMANENT_TARGET_ERRCODES:
            return "target"
        if errcode in {45009}:
            return "rate-limit"
    text = str(errmsg or "").lower()
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if any(k in text for k in ("connect", "socket", "closed", "transport")):
        return "transport"
    if any(k in text for k in ("auth", "secret", "token")):
        return "auth"
    if any(k in text for k in ("invalid", "not found", "target", "chatid", "userid")):
        return "target"
    return "other"


def verify_committed_self(root: Path = REPO_ROOT) -> str:
    """Require the driver committed and the tracked worktree byte-exact to HEAD.

    Porcelain alone is not an exact-byte gate: skip-worktree/assume-unchanged
    index flags hide modified files from it. So: reject any index flags,
    require empty porcelain, and blob-compare the load-bearing modules
    (driver, adapter, config/policy loader) against frozen HEAD blobs.
    Returns "" or an error string.
    """
    try:
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(root), "rev-parse", f"{head}:{DRIVER_REL}"],
            capture_output=True, text=True, check=True,
        )
        ls_v = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-v"],
            capture_output=True, text=True, check=True,
        ).stdout
        for line in ls_v.splitlines():
            if line and not line.startswith("H "):
                return f"index flag hides working-tree state: {line.split(None, 1)[-1] if len(line) > 2 else line}"
        dirty = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        if dirty:
            return f"tracked worktree differs from HEAD {head[:12]}"
        for rel in (DRIVER_REL, "gateway/platforms/wecom.py", "gateway/config.py"):
            expected = subprocess.run(
                ["git", "-C", str(root), "rev-parse", f"{head}:{rel}"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            actual = subprocess.run(
                ["git", "-C", str(root), "hash-object", "--path", rel, str(root / rel)],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            if expected != actual:
                return f"{rel} differs from committed HEAD {head[:12]}"
    except (subprocess.CalledProcessError, OSError) as exc:
        return f"committed-self-check failed: {type(exc).__name__}"
    return ""


def build_adapter():
    """Adapter from the real gateway config (policies included), never bridging."""
    from gateway.config import Platform, load_gateway_config
    from gateway.platforms.wecom import WeComAdapter

    config = load_gateway_config().platforms[Platform.WECOM]
    adapter = WeComAdapter(config)
    adapter._youpet_bridge = None  # the driver never bridges Core
    return adapter


def _inbox_entry(payload):
    body = payload.get("body") if isinstance(payload.get("body"), dict) else {}
    return {
        "chattype": _enum_label(body.get("chattype"), _CHATTYPE_LABELS),
        "msgtype": _enum_label(body.get("msgtype"), _MSGTYPE_LABELS),
        "msgid_len": len(str(body.get("msgid") or "")),
    }


def install_inbound_guard(adapter, inbox):
    """Default inbound behavior for every mode: record structure, drop.

    Nothing reaches handle_message / sessions / agent dispatch from any
    driver mode, and provider-controlled strings are enum-mapped.
    """

    async def drop(payload):
        inbox.append(_inbox_entry(payload))

    adapter._on_message = drop


def install_event_spy(adapter, events):
    """Record event-callback classes (fixed labels) to detect takeovers."""
    from gateway.platforms.wecom import WeComAdapter

    original = adapter._dispatch_payload

    async def spy(payload):
        if str(payload.get("cmd") or "") == "aibot_event_callback":
            events.append(WeComAdapter._classify_event_callback(payload))
        await original(payload)

    adapter._dispatch_payload = spy


async def _no_reconnect(*_args, **_kwargs):
    raise RuntimeError("driver reconnect suppressed by design (A2)")


def _unknown(reason_class, req_id=None):
    return {
        "transport_outcome": "unknown",
        "reason_class": reason_class,
        "correlated": False,
        "errcode": None,
        "errmsg_class": "other",
        "retryability_class": "unknown",
        "request_req_id_len": len(str(req_id or "")),
        "response_req_id_len": 0,
    }


def _outcome_from_response(response, req_id):
    """Three-state outcome with request/response correlation.

    ``response`` and its ``headers`` are untrusted protocol values; anything
    malformed classifies as unknown, never raises.
    """
    if not isinstance(response, dict):
        return _unknown("malformed-response", req_id)
    headers = response.get("headers")
    headers = headers if isinstance(headers, dict) else {}
    resp_req = headers.get("req_id")
    correlated = isinstance(resp_req, str) and resp_req == req_id
    errcode = response.get("errcode")
    valid_int = isinstance(errcode, int) and not isinstance(errcode, bool)
    if valid_int and errcode == 0 and correlated:
        outcome = "accepted_by_platform"
    elif valid_int and errcode != 0 and correlated:
        outcome = "rejected_by_platform"
    else:
        outcome = "unknown"
    return {
        "transport_outcome": outcome,
        "correlated": correlated,
        "errcode": errcode if valid_int else None,
        "errmsg_class": classify_result(errcode if valid_int else None,
                                        response.get("errmsg")),
        "retryability_class": retryability_class(errcode if valid_int else None),
        "request_req_id_len": len(str(req_id or "")),
        "response_req_id_len": len(str(resp_req or "")),
    }


async def _emit_and_wait(adapter, cmd, body, req_id, timeout=REQUEST_TIMEOUT_SECONDS):
    """Register the correlation future ourselves so request/response
    correlation is provable, emit once, and await the response."""
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    adapter._pending_responses[req_id] = future
    try:
        await adapter._send_json({"cmd": cmd, "headers": {"req_id": req_id}, "body": body})
        return await asyncio.wait_for(future, timeout=timeout)
    finally:
        if not future.done():
            future.cancel()
        adapter._pending_responses.pop(req_id, None)


async def attempt_send(adapter, *, chat_id=None, reply_req_id=None, content):
    """Exactly one transport attempt with a three-state outcome."""
    body = {"msgtype": "markdown", "markdown": {"content": content[:MAX_CONTENT]}}
    if reply_req_id:
        req_id = reply_req_id
        cmd = "aibot_respond_msg"
    else:
        req_id = adapter._new_req_id("a2")
        cmd = "aibot_send_msg"
        body["chatid"] = chat_id
    t0 = time.monotonic()
    try:
        response = await _emit_and_wait(adapter, cmd, body, req_id)
    except asyncio.TimeoutError:
        result = _unknown("timeout", req_id)
        result["errmsg_class"] = "timeout"
        result["latency_ms"] = int((time.monotonic() - t0) * 1000)
        return result
    except Exception as exc:
        result = _unknown("transport", req_id)
        result["errmsg_class"] = classify_result(None, type(exc).__name__)
        result["latency_ms"] = int((time.monotonic() - t0) * 1000)
        return result
    result = _outcome_from_response(response, req_id)
    result["latency_ms"] = int((time.monotonic() - t0) * 1000)
    return result


async def attempt_send_disconnect(adapter, *, chat_id, content):
    """A2-03: emit one send, then close the socket with the response future
    unresolved. A response that demonstrably completed successfully BEFORE
    the disconnect is reported as such; anything else is "unknown". Emission
    and close failures are contained and still yield a fixed record."""
    req_id = adapter._new_req_id("a2-03")
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    adapter._pending_responses[req_id] = future
    t0 = time.monotonic()
    try:
        await adapter._send_json(
            {
                "cmd": "aibot_send_msg",
                "headers": {"req_id": req_id},
                "body": {
                    "chatid": chat_id,
                    "msgtype": "markdown",
                    "markdown": {"content": content[:MAX_CONTENT]},
                },
            }
        )
    except Exception as exc:
        if not future.done():
            future.cancel()
        adapter._pending_responses.pop(req_id, None)
        result = _unknown("emission-failed", req_id)
        result["errmsg_class"] = classify_result(None, type(exc).__name__)
        result["emitted"] = False
        return result
    emitted_ms = int((time.monotonic() - t0) * 1000)
    # A trustworthy response must have completed successfully BEFORE we close.
    if future.done() and not future.cancelled() and future.exception() is None:
        adapter._pending_responses.pop(req_id, None)
        result = _outcome_from_response(future.result(), req_id)
        result["emitted"] = True
        result["emitted_ms"] = emitted_ms
        result["note"] = "response-completed-before-disconnect"
        return result
    # Unresolved: remove from the pending map FIRST so the close cannot
    # complete it exceptionally, then disconnect and record unknown.
    if not future.done():
        future.cancel()
    adapter._pending_responses.pop(req_id, None)
    try:
        await adapter._cleanup_ws()
    except Exception:
        pass  # close failure is contained; the outcome is already unknown
    result = _unknown("disconnected-before-response", req_id)
    result["emitted"] = True
    result["emitted_ms"] = emitted_ms
    return result


async def attempt_group_reply(adapter, *, marker, reply, mention_prefix, inbox, timeout_s=120):
    """Reply once via aibot_respond_msg, bound to an inbound req_id captured
    on THIS connection by full-text equality with the operator-approved
    ``<mention_prefix> <marker>`` string (after policy checks). First match
    wins; malformed frames are ignored. No send otherwise — no proactive
    group send."""
    expected_text = f"{mention_prefix.strip()} {marker}"
    got = {}
    done = asyncio.Event()

    async def observer(payload):
        inbox.append(_inbox_entry(payload))
        if done.is_set():
            return  # first match is frozen; duplicates never overwrite
        body = payload.get("body") if isinstance(payload.get("body"), dict) else {}
        if str(body.get("chattype") or "").lower() != "group":
            return
        if not isinstance(body.get("from"), dict) or not isinstance(body.get("text"), dict):
            return
        headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
        chat_id = str(body.get("chatid") or "").strip()
        sender_id = str(body["from"].get("userid") or "").strip()
        if not adapter._is_group_allowed(chat_id, sender_id):
            return
        text = str(body["text"].get("content") or "").rstrip()
        if text == expected_text:
            got["req_id"] = headers.get("req_id")
            got["msgid_len"] = len(str(body.get("msgid") or ""))
            done.set()

    adapter._on_message = observer  # restricted; still never dispatches
    try:
        await asyncio.wait_for(done.wait(), timeout=timeout_s)
    except asyncio.TimeoutError:
        return {
            "transport_outcome": "aborted",
            "reason_class": "no-in-connection-reply-context",
            "sent": False,
        }
    req_id = str(got.get("req_id") or "")
    if not req_id:
        return {
            "transport_outcome": "aborted",
            "reason_class": "empty-req-id",
            "sent": False,
        }
    result = await attempt_send(adapter, reply_req_id=req_id, content=reply)
    result["sent"] = True
    result["inbound_msgid_len"] = got["msgid_len"]
    result["reply_bound_to_inbound_req"] = True
    return result


def capability_report():
    """A2-05: OFFLINE report; never constructs an adapter or connects."""
    from gateway.platforms import wecom as wecom_module

    inventory = sorted(
        value
        for name, value in vars(wecom_module).items()
        if name.startswith("APP_CMD_") and isinstance(value, str)
    )
    has_recall = any(
        "recall" in command.lower() or "revoke" in command.lower()
        for command in inventory
    )
    try:
        head = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        head = "unknown"
    return {
        "transport_outcome": "capability-report",
        "adapter_command_inventory": inventory,
        "recall_command_present": has_recall,
        "adapter_capability": "supported" if has_recall else "unsupported",
        "official_doc_capability": "undocumented",
        "conclusion": (
            "supported_by_selected_adapter"
            if has_recall
            else "unsupported_by_selected_adapter_and_undocumented_in_official_protocol"
        ),
        "document_url": OFFICIAL_DOC_URL,
        "document_checked_at": OFFICIAL_DOC_CHECKED_AT,
        "adapter_commit": head,
        "basis": (
            "pinned adapter source inventory plus the official long-connection"
            " document (no recall/revoke command listed as of the checked"
            " date). Adapter absence bounds the selected adapter/protocol; it"
            " is not proof the platform can never recall."
        ),
    }


def evaluate_case(case, result):
    """Split run validity: (observation_complete, case_criterion_met, requires_rerun).

    Criteria are per case and direction-aware: a contradictory outcome can
    complete the observation but never passes the criterion.
    """
    outcome = result.get("transport_outcome")
    definitive = outcome in {"accepted_by_platform", "rejected_by_platform"}
    if case == "connect-check":
        criterion = outcome == "connected"
        return True, criterion, not criterion
    if case == "send-disconnect":
        if outcome == "unknown" and result.get("reason_class") == "disconnected-before-response":
            return True, True, False  # the target state was demonstrated
        if result.get("note") == "response-completed-before-disconnect":
            return True, False, True  # window missed; rerun required
        return False, False, True     # emission failed etc.
    if case == "send-group-reply":
        if outcome == "aborted":
            return False, False, True
        return definitive, outcome == "accepted_by_platform", not definitive
    if case == "send-invalid":
        # A2-02 criterion: a correlated rejection that is BOTH target-class
        # AND documented-permanent. Text-derived target classes and unknown
        # errcodes never qualify.
        criterion = (
            outcome == "rejected_by_platform"
            and result.get("errmsg_class") == "target"
            and result.get("retryability_class") == "permanent"
        )
        return definitive, criterion, not definitive
    # send-dm: only platform acceptance satisfies A2-01.
    return definitive, outcome == "accepted_by_platform", not definitive


def offline_preflight(args) -> int:
    """All checks that must pass BEFORE any connection is opened."""
    send_cases = {"send-dm", "send-group-reply", "send-invalid", "send-disconnect"}
    if args.case in send_cases:
        if not args.marker.strip():
            print("--marker must be a non-empty approved synthetic marker", file=sys.stderr)
            return 2
        if len(args.marker) > MAX_CONTENT:
            print("--marker exceeds the transport limit; refusing to truncate", file=sys.stderr)
            return 2
        if args.delivery_alias.strip() in {"", "absent"}:
            print("--delivery-alias must be a real correlation alias, not the placeholder",
                  file=sys.stderr)
            return 2
        if args.attempt < 1:
            print("--attempt must be a positive integer", file=sys.stderr)
            return 2
    if args.case in {"send-dm", "send-disconnect"}:
        if not os.getenv("F61_A2_DM_TARGET", "").strip():
            print("F61_A2_DM_TARGET is required (operator env)", file=sys.stderr)
            return 2
    if args.case == "send-group-reply":
        if not args.reply.strip():
            print("--reply must be a non-empty approved synthetic marker", file=sys.stderr)
            return 2
        if len(args.reply) > MAX_CONTENT:
            print("--reply exceeds the transport limit; refusing to truncate", file=sys.stderr)
            return 2
        if not args.mention_prefix.strip().startswith("@"):
            print("--mention-prefix must be the operator-approved mention (e.g. '@Agent Core Bot')",
                  file=sys.stderr)
            return 2
    return 0


async def run(args) -> int:
    adapter = build_adapter()
    inbox = []
    install_inbound_guard(adapter, inbox)
    takeover_events = []
    install_event_spy(adapter, takeover_events)
    if not await adapter.connect():
        print(json.dumps({"case": args.case, "transport_outcome": "connect_failed",
                          "case_criterion_met": False, "requires_rerun": True}))
        return 1
    adapter._open_connection = _no_reconnect  # never reconnect mid-run
    try:
        if args.case == "connect-check":
            await asyncio.sleep(3)
            result = {"transport_outcome": "connected"}
        elif args.case == "send-dm":
            result = await attempt_send(
                adapter,
                chat_id=os.getenv("F61_A2_DM_TARGET", "").strip(),
                content=args.marker,
            )
        elif args.case == "send-group-reply":
            result = await attempt_group_reply(
                adapter, marker=args.marker.strip(), reply=args.reply.strip(),
                mention_prefix=args.mention_prefix, inbox=inbox,
            )
        elif args.case == "send-invalid":
            result = await attempt_send(
                adapter, chat_id=INVALID_TARGET, content=args.marker
            )
        elif args.case == "send-disconnect":
            result = await attempt_send_disconnect(
                adapter,
                chat_id=os.getenv("F61_A2_DM_TARGET", "").strip(),
                content=args.marker,
            )
        else:
            print(f"unknown case {args.case}", file=sys.stderr)
            return 2
        result["case"] = args.case
        result["delivery_id_alias"] = args.delivery_alias
        result["attempt"] = args.attempt
        result["observed_event_classes"] = takeover_events
        result["inbound_seen"] = inbox
        # Only the documented benign event (enter_chat) keeps the window
        # valid; disconnected_event and any unclassified "other" fail closed.
        window_invalid = any(e != "enter_chat" for e in takeover_events)
        complete, criterion, rerun = evaluate_case(args.case, result)
        result["exclusive_window_valid"] = not window_invalid
        result["observation_complete"] = complete
        result["case_criterion_met"] = criterion
        result["requires_rerun"] = rerun or window_invalid
        print(json.dumps(result, sort_keys=True))
        return 0 if (criterion and not window_invalid) else 1
    finally:
        await adapter.disconnect()


def main_for(argv) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=[
        "connect-check", "send-dm", "send-group-reply",
        "send-invalid", "send-disconnect", "recall-capability",
    ])
    parser.add_argument("--marker", default="", help="exact approved synthetic marker")
    parser.add_argument("--reply", default="", help="approved reply marker (group leg)")
    parser.add_argument("--mention-prefix", default="",
                        help="operator-approved mention prefix for the group leg, e.g. '@Agent Core Bot'")
    parser.add_argument("--delivery-alias", default="absent",
                        help="correlation alias only; the real delivery_id stays in Core")
    parser.add_argument("--attempt", type=int, default=1)
    args = parser.parse_args(argv)

    mismatch = verify_committed_self()
    if mismatch:
        print(f"refusing to run: {mismatch}", file=sys.stderr)
        return 2
    if args.case == "recall-capability":
        print(json.dumps(capability_report(), sort_keys=True))
        return 0
    preflight = offline_preflight(args)
    if preflight:
        return preflight
    return asyncio.run(run(args))


def main() -> int:
    return main_for(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
