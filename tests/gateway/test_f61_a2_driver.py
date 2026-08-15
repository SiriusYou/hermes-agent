"""Unit tests for the F6.1 A2 outbound evidence driver (scripts/f61_a2_driver.py).

Pins: three-state outcome contract with req_id correlation, closed-enum
mapping of provider-controlled fields, inbound-inert guard wiring, exact
first-match-frozen group binding with policy enforcement, offline preflights
that never connect, full-worktree committed self-check, and the A2-03
unknown-outcome state machine under emission/close fault injection.
"""

import asyncio
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

CANARY = "CANARY-SECRET-MARKER-4e91"
MARKER = "WECOM-LC-20260815-01-A201-GROUP-PROBE"
REPLY = "WECOM-LC-20260815-01-A201-GROUP-REPLY ack"

DRIVER_PATH = Path(__file__).resolve().parents[2] / "scripts" / "f61_a2_driver.py"
_spec = importlib.util.spec_from_file_location("f61_a2_driver", DRIVER_PATH)
driver = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(driver)


class FakeAdapter:
    """Minimal adapter double; canned responses resolve via _send_json."""

    def __init__(self, response=None, group_allowed=True, resolve_with_marker="marker"):
        self.response = response
        self.group_allowed = group_allowed
        self.sent = []
        self.closed = False
        self.cleanup_fails = False
        self._pending_responses = {}
        self._on_message = None
        self._youpet_bridge = None

    def _is_group_allowed(self, chat_id, sender_id):
        return self.group_allowed

    @staticmethod
    def _new_req_id(prefix):
        return f"{prefix}-fixedreqid0123456789"

    async def connect(self):
        return True

    async def disconnect(self):
        return None

    async def _dispatch_payload(self, payload):
        return None

    async def _send_json(self, payload):
        self.sent.append(payload)
        if self.response is None:
            return  # platform stays silent
        req_id = payload["headers"]["req_id"]
        future = self._pending_responses.get(req_id)
        if future is not None and not future.done():
            future.set_result(self.response)

    async def _cleanup_ws(self):
        if self.cleanup_fails:
            raise OSError("close failed")
        self.closed = True
        # Simulate the listen loop's exceptional completion sweep.
        for future in self._pending_responses.values():
            if not future.done():
                future.set_exception(RuntimeError("WeCom connection interrupted"))


def good_response(req_id="a2-fixedreqid0123456789", errcode=0, errmsg="ok"):
    return {"errcode": errcode, "errmsg": errmsg, "headers": {"req_id": req_id}}


class TestClassifyResult:
    @pytest.mark.parametrize(
        "errcode,errmsg,expected",
        [
            (0, "ok", "success"),
            (40013, "invalid credential", "auth"),
            (60011, "no privilege", "target"),
            (45009, "freq limited", "rate-limit"),
            (-1, "request timed out", "timeout"),
            (-1, "connection closed", "transport"),
            (99999, "mystery", "other"),
            (None, None, "other"),
            (True, "ok", "other"),
        ],
    )
    def test_fixed_classes(self, errcode, errmsg, expected):
        assert driver.classify_result(errcode, errmsg) == expected


class TestThreeStateOutcome:
    @pytest.mark.asyncio
    async def test_accepted_requires_zero_and_correlation(self):
        adapter = FakeAdapter(response=good_response())
        result = await driver.attempt_send(adapter, chat_id="t", content="hi")
        assert result["transport_outcome"] == "accepted_by_platform"
        assert result["correlated"] is True
        assert len(adapter.sent) == 1

    @pytest.mark.asyncio
    async def test_platform_error_is_rejected(self):
        adapter = FakeAdapter(
            response=good_response(errcode=60011, errmsg=f"chat {CANARY} invalid")
        )
        result = await driver.attempt_send(adapter, chat_id="t", content="hi")
        assert result["transport_outcome"] == "rejected_by_platform"
        assert result["errcode"] == 60011
        assert result["errmsg_class"] == "target"
        assert CANARY not in json.dumps(result)

    @pytest.mark.asyncio
    async def test_missing_errcode_is_unknown(self):
        adapter = FakeAdapter(response={"headers": {"req_id": "a2-fixedreqid0123456789"}})
        result = await driver.attempt_send(adapter, chat_id="t", content="hi")
        assert result["transport_outcome"] == "unknown"

    @pytest.mark.asyncio
    async def test_uncorrelated_response_is_unknown(self):
        adapter = FakeAdapter(response=good_response(req_id="someone-elses-req-id"))
        result = await driver.attempt_send(adapter, chat_id="t", content="hi")
        assert result["transport_outcome"] == "unknown"
        assert result["correlated"] is False

    @pytest.mark.asyncio
    async def test_non_dict_response_is_unknown_not_crash(self):
        adapter = FakeAdapter(response=CANARY)  # malformed: not a dict
        result = await driver.attempt_send(adapter, chat_id="t", content="hi")
        assert result["transport_outcome"] == "unknown"
        assert result["reason_class"] == "malformed-response"
        assert CANARY not in json.dumps(result)

    @pytest.mark.asyncio
    async def test_non_dict_headers_is_unknown_not_crash(self):
        adapter = FakeAdapter(response={"errcode": 0, "headers": CANARY})
        result = await driver.attempt_send(adapter, chat_id="t", content="hi")
        assert result["transport_outcome"] == "unknown"
        assert CANARY not in json.dumps(result)

    @pytest.mark.asyncio
    async def test_silent_platform_is_unknown_timeout(self):
        adapter = FakeAdapter(response=None)
        result = await driver.attempt_send(adapter, chat_id="t", content="hi")
        assert result["transport_outcome"] == "unknown"
        assert result["reason_class"] == "timeout"
        assert adapter._pending_responses == {}


class TestInboundGuard:
    @pytest.mark.asyncio
    async def test_guard_drops_and_enum_maps_provider_values(self):
        adapter = FakeAdapter()
        inbox = []
        driver.install_inbound_guard(adapter, inbox)
        await adapter._on_message(
            {"cmd": "aibot_msg_callback",
             "body": {"chattype": CANARY, "msgtype": CANARY, "msgid": CANARY,
                      "text": {"content": CANARY}}}
        )
        assert inbox == [{"chattype": "other", "msgtype": "other",
                          "msgid_len": len(CANARY)}]
        assert CANARY not in json.dumps(inbox)

    @pytest.mark.asyncio
    async def test_guard_maps_known_values(self):
        adapter = FakeAdapter()
        inbox = []
        driver.install_inbound_guard(adapter, inbox)
        await adapter._on_message(
            {"body": {"chattype": "group", "msgtype": "image", "msgid": "m"}}
        )
        assert inbox == [{"chattype": "group", "msgtype": "image", "msgid_len": 1}]


class TestGroupReply:
    @pytest.mark.asyncio
    async def test_aborts_without_marker_and_never_falls_back(self):
        adapter = FakeAdapter()
        result = await driver.attempt_group_reply(
            adapter, marker=MARKER, reply=REPLY, inbox=[], timeout_s=0.2
        )
        assert result["transport_outcome"] == "aborted"
        assert result["sent"] is False
        assert adapter.sent == []

    @pytest.mark.asyncio
    async def test_substring_is_not_enough_exact_match_required(self):
        adapter = FakeAdapter()

        async def feed_superstring():
            await asyncio.sleep(0.05)
            await adapter._on_message(
                {"cmd": "aibot_msg_callback",
                 "body": {"chattype": "group", "msgid": "m" * 32,
                          "from": {"userid": "u"}, "text": {"content": f"{MARKER} EXTRA"}},
                 "headers": {"req_id": "q" * 24}}
            )

        feeder = asyncio.create_task(feed_superstring())
        result = await driver.attempt_group_reply(
            adapter, marker=MARKER, reply=REPLY, inbox=[], timeout_s=0.3
        )
        await feeder
        assert result["transport_outcome"] == "aborted"
        assert adapter.sent == []

    @pytest.mark.asyncio
    async def test_policy_denied_group_never_binds(self):
        adapter = FakeAdapter(group_allowed=False)

        async def feed_marker():
            await asyncio.sleep(0.05)
            await adapter._on_message(
                {"cmd": "aibot_msg_callback",
                 "body": {"chattype": "group", "msgid": "m" * 32, "chatid": "g",
                          "from": {"userid": "u"}, "text": {"content": MARKER}},
                 "headers": {"req_id": "q" * 24}}
            )

        feeder = asyncio.create_task(feed_marker())
        result = await driver.attempt_group_reply(
            adapter, marker=MARKER, reply=REPLY, inbox=[], timeout_s=0.3
        )
        await feeder
        assert result["transport_outcome"] == "aborted"
        assert adapter.sent == []

    @pytest.mark.asyncio
    async def test_malformed_frame_does_not_crash_or_bind(self):
        adapter = FakeAdapter()

        async def feed_malformed():
            await asyncio.sleep(0.05)
            await adapter._on_message(
                {"cmd": "aibot_msg_callback",
                 "body": {"chattype": "group", "from": CANARY, "text": CANARY},
                 "headers": CANARY}
            )

        feeder = asyncio.create_task(feed_malformed())
        result = await driver.attempt_group_reply(
            adapter, marker=MARKER, reply=REPLY, inbox=[], timeout_s=0.3
        )
        await feeder
        assert result["transport_outcome"] == "aborted"
        assert adapter.sent == []

    @pytest.mark.asyncio
    async def test_first_match_is_frozen(self):
        adapter = FakeAdapter(response=good_response(req_id="first-req-0000000000000000"))
        order = []

        async def feed_two():
            await asyncio.sleep(0.05)
            for req in ("first-req-0000000000000000", "secnd-req-0000000000000000"):
                await adapter._on_message(
                    {"cmd": "aibot_msg_callback",
                     "body": {"chattype": "group", "msgid": "m" * 32, "chatid": "g",
                              "from": {"userid": "u"}, "text": {"content": MARKER}},
                     "headers": {"req_id": req}}
                )
                order.append(req)

        feeder = asyncio.create_task(feed_two())
        result = await driver.attempt_group_reply(
            adapter, marker=MARKER, reply=REPLY, inbox=[], timeout_s=2
        )
        await feeder
        assert result["sent"] is True
        assert adapter.sent[0]["headers"]["req_id"] == "first-req-0000000000000000"


class TestSendDisconnect:
    @pytest.mark.asyncio
    async def test_unresolved_future_records_unknown_under_close_failure(self):
        adapter = FakeAdapter(response=None)
        result = await driver.attempt_send_disconnect(adapter, chat_id="t", content="hi")
        assert result["emitted"] is True
        assert result["transport_outcome"] == "unknown"
        assert result["reason_class"] == "disconnected-before-response"
        assert adapter.closed is True
        assert adapter._pending_responses == {}

    @pytest.mark.asyncio
    async def test_emission_failure_is_contained_and_cleans_up(self):
        adapter = FakeAdapter()

        async def broken_send(payload):
            raise RuntimeError(f"ws write failed near {CANARY}")

        adapter._send_json = broken_send
        result = await driver.attempt_send_disconnect(adapter, chat_id="t", content="hi")
        assert result["emitted"] is False
        assert result["transport_outcome"] == "unknown"
        assert result["reason_class"] == "emission-failed"
        assert adapter._pending_responses == {}  # no leaked pending entry
        assert CANARY not in json.dumps(result)

    @pytest.mark.asyncio
    async def test_cleanup_failure_is_contained(self):
        adapter = FakeAdapter(response=None)
        adapter.cleanup_fails = True
        result = await driver.attempt_send_disconnect(adapter, chat_id="t", content="hi")
        assert result["transport_outcome"] == "unknown"

    @pytest.mark.asyncio
    async def test_exceptional_completion_is_not_mistaken_for_response(self):
        adapter = FakeAdapter(response=None)
        original_send = adapter._send_json

        async def failing_send(payload):
            await original_send(payload)
            req_id = payload["headers"]["req_id"]
            adapter._pending_responses[req_id].set_exception(RuntimeError("boom"))

        adapter._send_json = failing_send
        result = await driver.attempt_send_disconnect(adapter, chat_id="t", content="hi")
        assert result["transport_outcome"] == "unknown"

    @pytest.mark.asyncio
    async def test_successful_response_before_close_is_reported(self):
        adapter = FakeAdapter(response=good_response(req_id="a2-03-fixedreqid0123456789"))
        result = await driver.attempt_send_disconnect(adapter, chat_id="t", content="hi")
        assert result["transport_outcome"] == "accepted_by_platform"
        assert result["note"] == "response-completed-before-disconnect"
        assert result["request_req_id_len"] == len("a2-03-fixedreqid0123456789")
        assert result["response_req_id_len"] == len("a2-03-fixedreqid0123456789")


class TestOfflinePreflight:
    def test_recall_capability_never_constructs_adapter(self, monkeypatch, capsys):
        monkeypatch.setattr(driver, "verify_committed_self", lambda *a, **k: "")
        monkeypatch.setattr(
            driver, "build_adapter",
            lambda: (_ for _ in ()).throw(AssertionError("must not connect")),
        )
        rc = driver.main_for(["recall-capability"])
        out = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert out["recall_command_present"] is False
        assert out["document_url"].startswith("https://developer.work.weixin.qq.com/")
        assert out["document_checked_at"]
        assert out["adapter_commit"]

    def test_empty_marker_rejected_before_connect(self, monkeypatch):
        monkeypatch.setattr(driver, "verify_committed_self", lambda *a, **k: "")
        monkeypatch.setattr(
            driver, "build_adapter",
            lambda: (_ for _ in ()).throw(AssertionError("must not connect")),
        )
        assert driver.main_for(["send-group-reply", "--marker", "", "--reply", REPLY]) == 2

    def test_missing_dm_target_rejected_before_connect(self, monkeypatch):
        monkeypatch.setattr(driver, "verify_committed_self", lambda *a, **k: "")
        monkeypatch.setattr(
            driver, "build_adapter",
            lambda: (_ for _ in ()).throw(AssertionError("must not connect")),
        )
        monkeypatch.delenv("F61_A2_DM_TARGET", raising=False)
        assert driver.main_for(["send-dm", "--marker", MARKER]) == 2


class TestCommittedSelfCheck:
    @staticmethod
    def _git(root, *args):
        subprocess.run(["git", "-C", str(root)] + list(args),
                       capture_output=True, check=True)

    def _make_repo(self, tmp_path, with_driver=True):
        self._git(tmp_path, "init", "-q")
        self._git(tmp_path, "config", "user.email", "t@example.invalid")
        self._git(tmp_path, "config", "user.name", "test")
        if with_driver:
            (tmp_path / "scripts").mkdir()
            (tmp_path / "scripts" / "f61_a2_driver.py").write_text("# driver\n")
        (tmp_path / "gateway" / "platforms").mkdir(parents=True)
        (tmp_path / "gateway" / "platforms" / "wecom.py").write_text("# adapter\n")
        (tmp_path / "gateway" / "config.py").write_text("# policy loader stand-in\n")
        self._git(tmp_path, "add", ".")
        self._git(tmp_path, "commit", "-qm", "init")
        return tmp_path

    def test_clean_repo_with_committed_driver_passes(self, tmp_path):
        self._make_repo(tmp_path)
        assert driver.verify_committed_self(tmp_path) == ""

    def test_driver_mismatch_fails(self, tmp_path):
        self._make_repo(tmp_path)
        (tmp_path / "scripts" / "f61_a2_driver.py").write_text("# tampered\n")
        assert driver.verify_committed_self(tmp_path) != ""

    def test_policy_module_mismatch_fails(self, tmp_path):
        self._make_repo(tmp_path)
        (tmp_path / "gateway" / "config.py").write_text("# tampered allowlist\n")
        assert driver.verify_committed_self(tmp_path) != ""

    def test_driver_not_committed_fails(self, tmp_path):
        self._make_repo(tmp_path, with_driver=False)
        assert driver.verify_committed_self(tmp_path) != ""

    def test_bogus_root_reports_error(self, tmp_path):
        assert driver.verify_committed_self(tmp_path / "nope") != ""

    def test_skip_worktree_flag_fails_even_with_clean_porcelain(self, tmp_path):
        self._make_repo(tmp_path)
        target = tmp_path / "gateway" / "config.py"
        self._git(tmp_path, "update-index", "--skip-worktree", "gateway/config.py")
        target.write_text("# tampered allowlist under skip-worktree\n")
        # porcelain is now empty for this file, but the flag itself must fail
        assert driver.verify_committed_self(tmp_path) != ""

    def test_assume_unchanged_flag_fails(self, tmp_path):
        self._make_repo(tmp_path)
        self._git(tmp_path, "update-index", "--assume-unchanged", "gateway/config.py")
        (tmp_path / "gateway" / "config.py").write_text("# tampered under assume-unchanged\n")
        assert driver.verify_committed_self(tmp_path) != ""


class TestCaseCriteriaMatrix:
    """Direction-aware per-case criteria: contradictory outcomes may complete
    an observation but never pass the criterion."""

    @pytest.mark.parametrize(
        "case,result,expected",
        [
            ("send-dm", {"transport_outcome": "accepted_by_platform"}, (True, True, False)),
            ("send-dm", {"transport_outcome": "rejected_by_platform"}, (True, False, False)),
            ("send-dm", {"transport_outcome": "unknown"}, (False, False, True)),
            ("send-group-reply", {"transport_outcome": "accepted_by_platform"}, (True, True, False)),
            ("send-group-reply", {"transport_outcome": "rejected_by_platform"}, (True, False, False)),
            ("send-group-reply", {"transport_outcome": "unknown"}, (False, False, True)),
            ("send-group-reply", {"transport_outcome": "aborted"}, (False, False, True)),
            ("send-invalid", {"transport_outcome": "rejected_by_platform", "errmsg_class": "target", "retryability_class": "permanent"}, (True, True, False)),
            ("send-invalid", {"transport_outcome": "rejected_by_platform", "errmsg_class": "target", "retryability_class": "transient"}, (True, False, False)),
            ("send-invalid", {"transport_outcome": "rejected_by_platform", "errmsg_class": "target"}, (True, False, False)),
            ("send-invalid", {"transport_outcome": "rejected_by_platform", "errmsg_class": "auth"}, (True, False, False)),
            ("send-invalid", {"transport_outcome": "rejected_by_platform", "errmsg_class": "rate-limit"}, (True, False, False)),
            ("send-invalid", {"transport_outcome": "accepted_by_platform"}, (True, False, False)),
            ("send-invalid", {"transport_outcome": "unknown"}, (False, False, True)),
            ("send-disconnect", {"transport_outcome": "unknown", "reason_class": "disconnected-before-response"}, (True, True, False)),
            ("send-disconnect", {"transport_outcome": "accepted_by_platform", "note": "response-completed-before-disconnect"}, (True, False, True)),
            ("send-disconnect", {"transport_outcome": "unknown", "reason_class": "emission-failed"}, (False, False, True)),
            ("connect-check", {"transport_outcome": "connected"}, (True, True, False)),
            ("connect-check", {"transport_outcome": "connect_failed"}, (True, False, True)),
        ],
    )
    def test_matrix(self, case, result, expected):
        assert driver.evaluate_case(case, result) == expected


class TestPreflightHardening:
    def test_placeholder_alias_rejected(self, monkeypatch):
        monkeypatch.setattr(driver, "verify_committed_self", lambda *a, **k: "")
        monkeypatch.setenv("F61_A2_DM_TARGET", "operator-alias-target")
        args = __import__("types").SimpleNamespace(
            case="send-dm", marker=MARKER, reply="", delivery_alias="absent", attempt=1,
        )
        assert driver.offline_preflight(args) == 2

    def test_non_positive_attempt_rejected(self, monkeypatch):
        monkeypatch.setenv("F61_A2_DM_TARGET", "operator-alias-target")
        args = __import__("types").SimpleNamespace(
            case="send-dm", marker=MARKER, reply="", delivery_alias="delivery-01", attempt=0,
        )
        assert driver.offline_preflight(args) == 2

    def test_oversized_marker_rejected_not_truncated(self, monkeypatch):
        monkeypatch.setenv("F61_A2_DM_TARGET", "operator-alias-target")
        args = __import__("types").SimpleNamespace(
            case="send-dm", marker="x" * 4001, reply="", delivery_alias="delivery-01",
            attempt=1,
        )
        assert driver.offline_preflight(args) == 2

    def test_valid_inputs_pass(self, monkeypatch):
        monkeypatch.setenv("F61_A2_DM_TARGET", "operator-alias-target")
        args = __import__("types").SimpleNamespace(
            case="send-dm", marker=MARKER, reply="", delivery_alias="delivery-01", attempt=1,
        )
        assert driver.offline_preflight(args) == 0


class TestRetryabilityClass:
    @pytest.mark.parametrize(
        "errcode,expected",
        [
            (60011, "permanent"),
            (60111, "permanent"),
            (81013, "permanent"),
            (45009, "transient"),
            (45047, "unknown"),  # absent from the cited appendix as of 2026-08-15
            (42001, "transient"),
            (99999, "unknown"),
            (None, "unknown"),
            (True, "unknown"),
        ],
    )
    def test_documented_sets_only(self, errcode, expected):
        assert driver.retryability_class(errcode) == expected

    def test_45047_falls_out_of_rate_limit_class(self):
        """Regression: until an official source is recorded, 45047 is neither
        transient nor rate-limit-classified."""
        assert driver.classify_result(45047, "some unrecognized text") == "other"

    @pytest.mark.asyncio
    async def test_unknown_errcode_with_target_text_fails_criterion(self):
        """ac-codex repro: errcode=99999 + 'invalid target, retry later' must
        NOT satisfy A2-02 — target text never implies permanent."""
        adapter = FakeAdapter(
            response=good_response(errcode=99999, errmsg="invalid target, retry later")
        )
        result = await driver.attempt_send(adapter, chat_id="t", content="hi")
        assert result["transport_outcome"] == "rejected_by_platform"
        assert result["errmsg_class"] == "target"  # text-derived class, fine as a label
        assert result["retryability_class"] == "unknown"
        complete, criterion, rerun = driver.evaluate_case("send-invalid", result)
        assert complete is True and criterion is False

    @pytest.mark.asyncio
    async def test_documented_permanent_target_error_passes(self):
        adapter = FakeAdapter(
            response=good_response(errcode=60111, errmsg="userid not found")
        )
        result = await driver.attempt_send(adapter, chat_id="t", content="hi")
        assert result["transport_outcome"] == "rejected_by_platform"
        assert result["errmsg_class"] == "target"
        assert result["retryability_class"] == "permanent"
        complete, criterion, rerun = driver.evaluate_case("send-invalid", result)
        assert (complete, criterion, rerun) == (True, True, False)


class TestCapabilityDerivation:
    def test_absent_direction(self, capsys):
        report = driver.capability_report()
        assert report["recall_command_present"] is False
        assert report["adapter_capability"] == "unsupported"
        assert report["conclusion"] == (
            "unsupported_by_selected_adapter_and_undocumented_in_official_protocol"
        )

    def test_present_direction(self, monkeypatch):
        from gateway.platforms import wecom as wecom_module

        monkeypatch.setattr(
            wecom_module, "APP_CMD_RECALL_FAKE", "aibot_recall_msg", raising=False
        )
        report = driver.capability_report()
        assert report["recall_command_present"] is True
        assert report["adapter_capability"] == "supported"
        assert report["conclusion"] == "supported_by_selected_adapter"


class TestRunWiring:
    @pytest.mark.asyncio
    async def test_run_installs_guard_and_suppresses_reconnect(self, monkeypatch):
        adapter = FakeAdapter(response=good_response())
        monkeypatch.setattr(driver, "build_adapter", lambda: adapter)
        import types
        args = types.SimpleNamespace(
            case="send-dm", marker=MARKER, reply="", delivery_alias="delivery-01",
            attempt=1,
        )
        monkeypatch.setenv("F61_A2_DM_TARGET", "operator-alias-target")
        rc = await driver.run(args)
        assert rc == 0
        assert adapter._on_message is not None  # inbound guard installed
        with pytest.raises(RuntimeError, match="reconnect suppressed"):
            await adapter._open_connection()

    @pytest.mark.asyncio
    async def test_takeover_event_fails_the_run(self, monkeypatch, capsys):
        adapter = FakeAdapter(response=good_response())

        async def spy_dispatch(payload):
            return None

        adapter._dispatch_payload = spy_dispatch

        def fake_spy(ad, events):
            events.append("disconnected_event")  # simulate observed takeover

        monkeypatch.setattr(driver, "build_adapter", lambda: adapter)
        monkeypatch.setattr(driver, "install_event_spy", fake_spy)
        import types
        args = types.SimpleNamespace(
            case="send-dm", marker=MARKER, reply="", delivery_alias="d", attempt=1,
        )
        monkeypatch.setenv("F61_A2_DM_TARGET", "operator-alias-target")
        rc = await driver.run(args)
        out = json.loads(capsys.readouterr().out)
        assert rc == 1
        assert out["exclusive_window_valid"] is False
        assert out["requires_rerun"] is True
