"""The job contract: round-trip fidelity, the funnel/stage vocabulary, and the fingerprint.

Three of these tests exist because something specific went wrong in the design and would
go wrong again quietly:

* the round-trip test pins the *documented* JSON, so adding a required field to
  ``Job`` breaks loudly here instead of in a worker at 3am;
* the fingerprint tests fail if a field is dropped from the digest, which would make two
  genuinely different requests share one job;
* the I/O test keeps the store from being written into the contract module.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from aegis_contracts.jobs import (
    FUNNEL_STEPS,
    SCHEMA_VERSION,
    TERMINAL_STATES,
    TIMED_STAGES,
    FailureMode,
    Job,
    JobFailure,
    JobKind,
    JobProgress,
    JobRequest,
    JobStage,
    JobState,
    JobSubmission,
    JobTiming,
    canonical_json,
    job_id_for,
    request_fingerprint,
)

ROOT = Path(__file__).resolve().parents[1]

# --- fixtures: the two complete samples from docs/QUEUE_PLAN.md §2.5 -----------------

RUNNING_MIDWAY = {
    "schema_version": "1.0",
    "job_id": "J-3f9a1c2b7d4e50618293a4b5c6d7e8f901234567",
    "kind": "assemble",
    "state": "running",
    "cancel_requested": False,
    "cancel_requested_at": None,
    "submission": {
        "schema_version": "1.0",
        "job_id": "J-3f9a1c2b7d4e50618293a4b5c6d7e8f901234567",
        "kind": "assemble",
        "request": {
            "workspace": "/workspace",
            "sarif_path": None,
            "rules": [],
            "rule_config": "p/default",
            "include_globs": [],
            "exclude_globs": [],
            "budget": {"max_depth": 2, "max_nodes": 60, "max_contexts": 20, "expand_concurrency": 6},
            "max_findings": None,
            "lsp": True,
            "package_name": None,
        },
        "fingerprint": "8b1d0f2c9a7e4b3d5c6f8a90b1c2d3e4f5061728",
        "submitted_at": "2025-01-14T09:12:03.114000Z",
        "submitted_by": "gateway",
        "children": [],
    },
    "timing": {
        "submitted_at": "2025-01-14T09:12:03.114000Z",
        "started_at": "2025-01-14T09:12:04.882000Z",
        "finished_at": None,
        "queue_wait_ms": 1768,
        "duration_ms": 0,
    },
    "progress": {
        "stage": "expand",
        "stages": [
            {
                "stage": "scan",
                "state": "done",
                "started_at": "2025-01-14T09:12:04.882000Z",
                "finished_at": "2025-01-14T09:12:14.310000Z",
                "duration_ms": 9428,
                "note": "scan_transport=remote",
                "counters": {"discovered": 37},
            },
            {
                "stage": "setup",
                "state": "done",
                "started_at": "2025-01-14T09:12:14.310000Z",
                "finished_at": "2025-01-14T09:12:15.977000Z",
                "duration_ms": 1667,
                "note": "lsp=python",
                "counters": {},
            },
            {
                "stage": "locate",
                "state": "done",
                "started_at": "2025-01-14T09:12:15.977000Z",
                "finished_at": "2025-01-14T09:12:16.402000Z",
                "duration_ms": 425,
                "note": None,
                "counters": {"located": 34, "focus_methods": 19},
            },
            {
                "stage": "expand",
                "state": "running",
                "started_at": "2025-01-14T09:12:16.402000Z",
                "finished_at": None,
                "duration_ms": None,
                "note": None,
                "counters": {"contexts": 19},
            },
            {"stage": "read", "state": "pending", "counters": {}},
            {"stage": "assemble", "state": "pending", "counters": {}},
            {"stage": "package", "state": "pending", "counters": {}},
            {"stage": "done", "state": "pending", "counters": {}},
        ],
        "counters": {"discovered": 37, "located": 34, "focus_methods": 19, "contexts": 19,
                     "slices": 18},
        "units_done": 11,
        "units_total": 19,
        "unit_label": "slices",
        "worker_id": "aegis-worker:4711:0f2a",
        "attempt": 1,
        "stage_started_at": "2025-01-14T09:12:16.402000Z",
        "worker_heartbeat_at": "2025-01-14T09:12:31.006000Z",
    },
    "result": None,
    "failure": None,
    "revision": 14,
}

SUCCEEDED = {
    "schema_version": "1.0",
    "job_id": "J-3f9a1c2b7d4e50618293a4b5c6d7e8f901234567",
    "kind": "assemble",
    "state": "succeeded",
    "cancel_requested": False,
    "cancel_requested_at": None,
    "submission": RUNNING_MIDWAY["submission"],
    "timing": {
        "submitted_at": "2025-01-14T09:12:03.114000Z",
        "started_at": "2025-01-14T09:12:04.882000Z",
        "finished_at": "2025-01-14T09:12:26.540000Z",
        "queue_wait_ms": 1768,
        "duration_ms": 21658,
    },
    "progress": {
        "stage": "package",
        "stages": [
            {"stage": "scan", "state": "done", "duration_ms": 9428,
             "note": "scan_transport=remote", "counters": {"discovered": 37}},
            {"stage": "setup", "state": "done", "duration_ms": 1667,
             "note": "lsp=python", "counters": {}},
            {"stage": "locate", "state": "done", "duration_ms": 425,
             "counters": {"located": 34, "focus_methods": 19}},
            {"stage": "expand", "state": "done", "duration_ms": 4310,
             "note": "18/19 slices expanded; 1 failed and was recorded as a warning",
             "counters": {"contexts": 19, "slices": 18}},
            {"stage": "read", "state": "done", "duration_ms": 2288,
             "counters": {"proposed": 143, "kept": 121, "read": 118}},
            {"stage": "assemble", "state": "done", "duration_ms": 3011,
             "counters": {"inlined": 176}},
            {"stage": "package", "state": "done", "duration_ms": 529, "counters": {}},
            {"stage": "done", "state": "done", "counters": {}},
        ],
        "counters": {"discovered": 37, "located": 34, "focus_methods": 19, "contexts": 19,
                     "slices": 18, "proposed": 143, "kept": 121, "read": 118, "inlined": 176},
        "units_done": 118,
        "units_total": 121,
        "unit_label": "bodies",
        "worker_id": "aegis-worker:4711:0f2a",
        "attempt": 1,
        "stage_started_at": "2025-01-14T09:12:26.011000Z",
        "worker_heartbeat_at": "2025-01-14T09:12:26.011000Z",
    },
    "result": {
        "bundle_id": "B-c7f830954f",
        "package_path": "/data/packages/B-c7f830954f",
        "run_id": "R-1a2b3c4d5e",
        "sarif_path": "/data/work/R-1a2b3c4d5e/opengrep.sarif",
        "warnings": ["scan ran in the scan service: its raw SARIF is not in this filesystem"],
        "artifacts": {
            "bundle": {"kind": "bundle", "ref": "B-c7f830954f",
                       "path": "/data/packages/B-c7f830954f", "available": True}
        },
    },
    "failure": None,
    "revision": 41,
}


def _canceled_sample() -> dict:
    """A complete canceled job. §2.5 (d) abbreviates its stage list, so this one is
    spelled out: it must still satisfy the full schema, not just the interesting fields."""
    sample = json.loads(json.dumps(SUCCEEDED))
    sample["state"] = "canceled"
    sample["cancel_requested"] = True
    sample["cancel_requested_at"] = "2025-01-14T09:13:02.550000Z"
    sample["revision"] = 22
    sample["result"] = None
    sample["failure"] = None
    sample["timing"]["finished_at"] = "2025-01-14T09:13:03.180000Z"
    sample["timing"]["duration_ms"] = 58298
    stages = sample["progress"]["stages"]
    stages[3] = {
        "stage": "expand",
        "state": "failed",
        "duration_ms": 46800,
        "note": "canceled at slice 11/19; 2 LSP processes terminated",
        "counters": {"contexts": 19, "slices": 11},
    }
    sample["progress"]["stage"] = "expand"
    sample["progress"]["counters"] = {
        "discovered": 37, "located": 34, "focus_methods": 19, "contexts": 19, "slices": 11
    }
    sample["progress"]["units_done"] = 11
    sample["progress"]["units_total"] = 19
    return sample


def _request(**overrides) -> JobRequest:
    base = {
        "workspace": "/workspace",
        "rule_config": "p/default",
        "budget": {"max_depth": 2, "max_nodes": 60},
    }
    base.update(overrides)
    return JobRequest(**base)


# --- 1 ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sample",
    [RUNNING_MIDWAY, SUCCEEDED, _canceled_sample()],
    ids=["running-midway", "succeeded", "canceled"],
)
def test_job_roundtrips_through_json(sample: dict) -> None:
    """The literal samples in the plan must load, and re-serialise unchanged.

    Deeper than "it parses": parse -> dump -> parse must be a fixed point, so a field
    that gains a default or loses a value shows up here.
    """
    job = Job.model_validate(sample)
    dumped = json.loads(job.model_dump_json())
    assert Job.model_validate(dumped) == job
    assert dumped["schema_version"] == SCHEMA_VERSION

    # Every key the sample declared must survive, so relaxing a field to optional is
    # still visible.
    for key in sample:
        assert key in dumped, f"{key} was dropped on the way out"


def test_progress_stage_progress_for_every_stage_is_present_in_samples() -> None:
    for sample in (RUNNING_MIDWAY, SUCCEEDED, _canceled_sample()):
        job = Job.model_validate(sample)
        assert [entry.stage for entry in job.progress.stages] == list(JobStage)


# --- 2, 3 ---------------------------------------------------------------------------


def test_stage_order_is_the_lifecycle_order() -> None:
    assert list(JobStage) == [
        JobStage.SCAN,
        JobStage.SETUP,
        JobStage.LOCATE,
        JobStage.EXPAND,
        JobStage.READ,
        JobStage.ASSEMBLE,
        JobStage.PACKAGE,
        JobStage.DONE,
    ]
    # The sentinel is excluded from anything that measures elapsed time.
    assert JobStage.DONE not in TIMED_STAGES
    assert len(TIMED_STAGES) == 7


def test_funnel_steps_are_the_documented_nine() -> None:
    assert FUNNEL_STEPS == (
        "discovered", "located", "focus_methods", "contexts", "slices",
        "proposed", "kept", "read", "inlined",
    )
    assert len(FUNNEL_STEPS) == 9


def test_progress_stages_are_complete_and_ordered() -> None:
    fresh = JobProgress.fresh()
    assert [entry.stage for entry in fresh.stages] == list(JobStage)
    assert len(fresh.stages) == 8
    assert {entry.state for entry in fresh.stages} == {"pending"}
    assert fresh.counters == {} and fresh.units_total == 0


def test_stage_coverage_matches_the_plan() -> None:
    """Which funnel steps become authoritative when a stage ends (plan §3.2).

    Written as a table so that moving a count between stages is a deliberate edit to
    this test rather than a silent re-assignment. `read` is the awkward one: the funnel
    step and the pipeline stage share a name and are not the same thing.
    """
    mapping = {
        JobStage.SCAN: ("discovered",),
        JobStage.SETUP: (),
        JobStage.LOCATE: ("located", "focus_methods"),
        JobStage.EXPAND: ("contexts", "slices"),
        JobStage.READ: ("proposed", "kept", "read"),
        JobStage.ASSEMBLE: ("inlined",),
        JobStage.PACKAGE: (),
        JobStage.DONE: (),
    }
    for stage, steps in mapping.items():
        assert set(steps) <= set(FUNNEL_STEPS), f"{stage} reports an unknown step"
    reported = [step for steps in mapping.values() for step in steps]
    assert set(reported) == set(FUNNEL_STEPS), (
        "every funnel step must be reported by exactly one stage; "
        f"unreported: {sorted(set(FUNNEL_STEPS) - set(reported))}"
    )


# --- 4 ------------------------------------------------------------------------------


def test_canceled_has_no_failure_mode() -> None:
    assert "canceled_by_request" not in {mode.name for mode in FailureMode}
    assert not [mode for mode in FailureMode if "cancel" in mode.value]

    job = Job.model_validate(_canceled_sample())
    assert job.state is JobState.CANCELED
    assert job.failure is None
    assert job.cancel_requested is True
    assert job.is_terminal


def test_a_canceled_job_cannot_carry_a_failure() -> None:
    """The validator is the enforcement, not the convention."""
    sample = _canceled_sample()
    sample["failure"] = {
        "mode": "pipeline_exception",
        "message": "should not be here",
        "attempt": 1,
        "recoverable": False,
        "scan_record": None,
    }
    with pytest.raises(Exception, match="canceled job must not carry a failure"):
        Job.model_validate(sample)


def test_terminal_states_are_the_three_endings() -> None:
    assert TERMINAL_STATES == {JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELED}
    assert JobState.QUEUED not in TERMINAL_STATES
    assert JobState.RUNNING not in TERMINAL_STATES
    # A job is only terminal if the model agrees.
    assert Job.model_validate(SUCCEEDED).is_terminal
    assert not Job.model_validate(RUNNING_MIDWAY).is_terminal


def test_ai_fanout_is_accepted_by_the_contract() -> None:
    """Reserved so the AI stage needs no schema change; this build's worker refuses it."""
    assert JobKind.AI_FANOUT.value == "ai_fanout"
    sample = json.loads(json.dumps(RUNNING_MIDWAY))
    sample["kind"] = "ai_fanout"
    sample["submission"]["kind"] = "ai_fanout"
    assert Job.model_validate(sample).kind is JobKind.AI_FANOUT


# --- 5, 6, 7 ------------------------------------------------------------------------


def test_fingerprint_is_stable_and_normalised(tmp_path: Path) -> None:
    absolute = tmp_path / "repo"
    absolute.mkdir()

    same_a = request_fingerprint(_request(workspace=str(absolute), rules=["b", "a"]))
    same_b = request_fingerprint(
        _request(workspace=absolute.as_posix(), rules=["a", "b"])
    )
    assert same_a == same_b, "rule order must not change the fingerprint"
    assert len(same_a) == 40

    globs_a = request_fingerprint(_request(include_globs=["z", "a"], exclude_globs=["m", "b"]))
    globs_b = request_fingerprint(_request(include_globs=["a", "z"], exclude_globs=["b", "m"]))
    assert globs_a == globs_b, "glob order must not change the fingerprint"


def test_fingerprint_separates_meaningful_differences(tmp_path: Path) -> None:
    """Each of these fields changes the bundle, so each must change the fingerprint.

    This is the test that fails if someone trims the digest for tidiness, which would
    silently make "run everything" and "run the first 5 findings" the same job.
    """
    workspace = tmp_path / "repo"
    workspace.mkdir()
    sarif = tmp_path / "scan.sarif"
    sarif.write_text('{"runs": []}', encoding="utf-8")

    base = request_fingerprint(_request(workspace=str(workspace), sarif_path=str(sarif)))

    variants = {
        "lsp": _request(workspace=str(workspace), sarif_path=str(sarif), lsp=False),
        "max_findings": _request(workspace=str(workspace), sarif_path=str(sarif), max_findings=5),
        "package_name": _request(workspace=str(workspace), sarif_path=str(sarif), package_name="B-x"),
        "include_globs": _request(workspace=str(workspace), sarif_path=str(sarif), include_globs=["*.py"]),
        "exclude_globs": _request(workspace=str(workspace), sarif_path=str(sarif), exclude_globs=["vendor/*"]),
        "rules": _request(workspace=str(workspace), sarif_path=str(sarif), rules=["p/ci"]),
        "budget": _request(workspace=str(workspace), sarif_path=str(sarif), budget={"max_depth": 5}),
    }
    for name, request in variants.items():
        assert request_fingerprint(request) != base, f"changing {name} must change the fingerprint"

    # Same path, different bytes: path alone must not be enough.
    sarif.write_text('{"runs": [{"tool": {}}]}', encoding="utf-8")
    assert request_fingerprint(
        _request(workspace=str(workspace), sarif_path=str(sarif))
    ) != base, "rewriting the SARIF at the same path must change the fingerprint"

    # The catalog selects which language server runs, so it is part of the request.
    assert request_fingerprint(
        _request(workspace=str(workspace), sarif_path=str(sarif)),
        lsp_config_fingerprint="deadbeef",
    ) != base


def test_fingerprint_ignores_key_order_in_the_budget() -> None:
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert request_fingerprint(_request(budget={"max_depth": 2, "max_nodes": 60})) == (
        request_fingerprint(_request(budget={"max_nodes": 60, "max_depth": 2}))
    )


def test_job_id_is_derived_from_the_fingerprint() -> None:
    fingerprint = request_fingerprint(_request())
    first, second = job_id_for(fingerprint), job_id_for(fingerprint)
    assert first == second
    assert len(first) == 42, "J- plus 40 hex characters"
    assert first.startswith("J-")
    assert set(first[2:]) <= set("0123456789abcdef")
    assert job_id_for("something-else") != first


def test_submission_is_self_consistent() -> None:
    """A submission carries its own id and kind, so a stored job explains itself."""
    request = _request()
    fingerprint = request_fingerprint(request)
    job_id = job_id_for(fingerprint)
    submission = JobSubmission(job_id=job_id, request=request, fingerprint=fingerprint)
    job = Job(
        job_id=job_id,
        submission=submission,
        timing=JobTiming(submitted_at=submission.submitted_at),
    )
    assert job.state is JobState.QUEUED
    assert job.revision == 0
    assert job.progress.stages, "a fresh job still reports the full stage track"


def test_job_failure_keeps_the_scan_ledger() -> None:
    """`scan_record` on a failure is how a canceled scan is auditable at all.

    A cancel during the scan stage never reaches packaging, so no manifest is written;
    the ledger attached to the failure is the only record of what the scanner was doing.
    """
    failure = JobFailure(
        mode=FailureMode.SCAN_ABORTED,
        message="the scan subprocess was terminated",
        detail="rc=-15",
        attempt=1,
        recoverable=True,
    )
    assert failure.scan_record is None
    payload = json.loads(failure.model_dump_json())
    assert payload["mode"] == "scan_aborted"
    assert "scan_record" in payload


# --- 8 ------------------------------------------------------------------------------


def test_the_local_digest_matches_the_shared_helper() -> None:
    """The contract's local digest must equal `aegis_core.utils.sha1` exactly.

    Two implementations of one digest is a smell, so this is the test that makes it safe:
    if either side changes its separator, encoding or truncation, the ids derived from a
    fingerprint would drift between processes and this comparison fails first.
    """
    from aegis_contracts.jobs import _sha1
    from aegis_core.utils import sha1

    cases = [("a",), ("a", "b"), ("/w/repo", "rule_config:p/default", '{"max_depth":2}'), ("", "x")]
    for parts in cases:
        for length in (8, 16, 40):
            assert _sha1(*parts, length=length) == sha1(*parts, length=length)


def test_contracts_module_imports_no_io() -> None:
    """The queue lives in `services/queue/`; if a store leaks in here, the split is fake."""
    banned = {"redis", "httpx", "requests", "socket", "subprocess", "fastapi", "uvicorn"}
    path = ROOT / "aegis_contracts" / "jobs.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module.split(".")[0])
    assert not (found & banned), f"jobs.py must not carry I/O: {sorted(found & banned)}"
    assert "services" not in found and "app" not in found
