from __future__ import annotations

import json
from pathlib import Path

from tests.gateway.test_youpet_bridge import _outbox_item

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "youpet_core_task_escalated_outbox.json"
)


def test_hermes_outbox_fake_matches_vendored_core_task_escalated_fixture() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text())
    assert fixture["provenance"] == {
        "canonical_source": "youpet-core/tests/fixtures/core_outbox_task_escalated.json",
        "canonical_sha256": "178fe00888f97eca2ddf94c3e8df00c03241b7800e6600c31a3b01c17689bea3",
        "fixture_name": "task.escalated hermes envelope",
    }

    expected = fixture["items"][0]
    business_payload = expected["payload"]["payload"]

    assert _outbox_item(expected["event_id"], expected["event_type"], business_payload) == expected
