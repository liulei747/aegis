"""The AI security-inventory stage: after the opening, reconciled, on the blackboard.

The design this pins (2026-09-18): **prep → recon ∥ threat model（各单轮、互不读取）→ AI Security
Inventory → planner**. An earlier shape ran a deterministic regex pre-scan *before* the opening pair
and let the planner read its keyword hits; both the order and the mechanism were wrong, and the regex
module is gone. What must hold now:

* the inventory is an **agent** that runs after both opening agents and reads their conclusions
  (`security_inventory_task` feeds project + architecture + threat model);
* its answer lands on the blackboard (`security_inventory`), which is where the planner reads it --
  through `security_inventory_payload`; Planner receives every row because it has no board tool;
* a run that produces nothing usable leaves the field `None` and says so, rather than fabricating
  an empty inventory that would read as "no surface".
"""

from __future__ import annotations

import json
from pathlib import Path

from services.harness import agents
from services.harness.agents import SecurityInventory
from services.harness.coordinator import HarnessConfig, HarnessCoordinator


def _final(**payload) -> str:
    return json.dumps({"thought": "done", "final": payload})


def _script_opening(client) -> None:
    """The two opening agents answer; the inventory answer is supplied per test."""
    client.stub_agent(
        agents.RECON,
        _final(
            project={"workspace": "/w", "languages": {"java": 2}},
            architecture={"components": [], "trust_boundaries": [], "notes": []},
        ),
    )
    client.stub_agent(
        agents.THREAT_MODEL,
        _final(assets=[], actors=[], threats=[], out_of_scope=[], notes=[]),
    )


_INVENTORY = {
    "entry_points": [
        {"name": "POST /admin-api/infra/file/upload", "file": "AppFileController.java", "line": 38}
    ],
    "authorization_controls": [
        {"file": "SecurityConfiguration.java", "line": 32, "note": "permitAll on /infra/file/*/get/**"}
    ],
    "dangerous_capabilities": [],
    "configurations": [],
    "dependencies": [],
    "state_controls": [],
    "coverage_gaps": ["运行期是否注册动态数据源，静态读取无法确认"],
    "files_reviewed": ["AppFileController.java"],
}


def test_the_inventory_agent_runs_after_the_opening_and_lands_on_the_blackboard(
    tmp_path: Path,
) -> None:
    from tests.test_harness_orchestration import CallCounter, pipeline, two_scope_client

    counter = CallCounter()
    client = two_scope_client(counter)
    _script_opening(client)
    client.stub_agent(agents.SECURITY_INVENTORY, _final(**_INVENTORY))
    client.stub_agent(agents.PLANNER, _final(scopes=[], rationale="file review only"))
    client.stub_agent(agents.DISCOVERY, _final(candidates=[], notes=[]))
    client.stub_agent(agents.VALIDATION_BATCH, _final(verdicts=[]))
    client.stub_agent(agents.ATTACK_PATH_BATCH, _final(paths=[]))

    coordinator: HarnessCoordinator = pipeline(
        tmp_path, client, config=HarnessConfig(max_rounds=1, claim_batch_size=4)
    )
    board = coordinator.run().blackboard

    assert isinstance(board.security_inventory, SecurityInventory)
    assert board.security_inventory.entry_points[0]["name"] == "POST /admin-api/infra/file/upload"
    assert board.security_inventory.coverage_gaps, "uncertainty is recorded, not padded away"
    # The stage ran *after* the opening: the task it was given carries both agents' outputs.
    inventory_task = next(
        user for agent, _scope, user in counter.calls if agent == agents.SECURITY_INVENTORY
    )
    assert "Reconnaissance and threat-model outputs" in inventory_task
    assert "threat_model" in inventory_task
    # And the stage ran after recon's run, not before it: the counter is ordered.
    seen = [agent for agent, _scope, _user in counter.calls]
    assert seen.index(agents.RECON) < seen.index(agents.SECURITY_INVENTORY)
    assert seen.index(agents.THREAT_MODEL) < seen.index(agents.SECURITY_INVENTORY)


def test_the_planner_receives_the_complete_inventory(tmp_path: Path) -> None:
    from tests.test_harness_orchestration import CallCounter, pipeline, two_scope_client

    counter = CallCounter()
    client = two_scope_client(counter)
    _script_opening(client)
    entry_points = [
        {"name": f"GET /api/{index}", "file": "C.java", "line": index} for index in range(30)
    ]
    client.stub_agent(
        agents.SECURITY_INVENTORY,
        _final(**{**_INVENTORY, "entry_points": entry_points}),
    )
    client.stub_agent(agents.PLANNER, _final(scopes=[], rationale="file review only"))
    client.stub_agent(agents.DISCOVERY, _final(candidates=[], notes=[]))
    client.stub_agent(agents.VALIDATION_BATCH, _final(verdicts=[]))
    client.stub_agent(agents.ATTACK_PATH_BATCH, _final(paths=[]))

    coordinator: HarnessCoordinator = pipeline(
        tmp_path, client, config=HarnessConfig(max_rounds=1, claim_batch_size=4)
    )
    coordinator.run()

    planner_task = next(user for agent, _scope, user in counter.calls if agent == agents.PLANNER)
    assert '"count": 30' in planner_task, "the planner sees the real section count"
    assert planner_task.count('"name": "GET /api/') == 30


def test_a_run_without_an_answer_leaves_the_inventory_none_and_says_so(tmp_path: Path) -> None:
    from services.ai.client import AIUnavailable
    from tests.test_harness_orchestration import pipeline, two_scope_client

    client = two_scope_client()
    _script_opening(client)
    # A provider outage is the honest way for this stage to produce nothing: the harness retries it
    # internally, then the run ends with stop_reason=error -- and the field stays `None`, with the
    # note saying why, instead of an empty inventory that would read as "no surface".
    client.stub_agent(agents.SECURITY_INVENTORY, AIUnavailable("provider down"))
    client.stub_agent(agents.PLANNER, _final(scopes=[], rationale="file review only"))
    client.stub_agent(agents.DISCOVERY, _final(candidates=[], notes=[]))

    coordinator: HarnessCoordinator = pipeline(
        tmp_path, client, config=HarnessConfig(max_rounds=1, claim_batch_size=4)
    )
    board = coordinator.run().blackboard

    assert board.security_inventory is None
    assert any("安全清单" in note for note in coordinator.dataflow_notes), coordinator.dataflow_notes


def test_the_payload_caps_sections_but_keeps_the_counts() -> None:
    full = SecurityInventory(
        entry_points=[{"name": f"e{index}"} for index in range(12)],
        coverage_gaps=["gap"],
    )
    payload = agents.security_inventory_payload(full)
    assert payload["entry_points"]["count"] == 12
    assert len(payload["entry_points"]["items"]) == 8
    assert payload["coverage_gaps"] == ["gap"]
    assert agents.security_inventory_payload(None) == {}
