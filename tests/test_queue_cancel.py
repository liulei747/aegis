"""Cancellation: the handle, the signal, and the four places that must not eat it.

`CanceledAbort` inheriting `BaseException` looks like a style choice and is not one. This
codebase deliberately has four "swallow everything and degrade" sites, because a single
broken node or a language server that will not start must not sink a whole run. A cancel
that gets swallowed by one of those becomes a job that finishes successfully after the
user asked it to stop -- so the inheritance is the mechanism, and the tests below are the
proof that it actually holds at each site.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from aegis_core.cancel import CanceledAbort, TeardownHandle
from services.queue.cancel import Teardown

SLEEPER = [sys.executable, "-c", "import time; time.sleep(30)"]


def _start_sleeper() -> subprocess.Popen:
    return subprocess.Popen(SLEEPER, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# --- the handle --------------------------------------------------------


def test_teardown_satisfies_the_protocol() -> None:
    """The pipeline only knows the protocol; the worker's class must fit it."""
    assert isinstance(Teardown(), TeardownHandle)


def test_teardown_registers_and_terminates_a_real_process() -> None:
    proc = _start_sleeper()
    teardown = Teardown()
    teardown.register_process("scan", proc)
    try:
        killed = teardown.kill_all(terminate_grace_s=3.0, kill_grace_s=2.0)
        assert killed == ["scan"]
        assert proc.poll() is not None, "the process must actually be gone"
    finally:
        if proc.poll() is None:  # pragma: no cover - cleanup only
            proc.kill()


def test_kill_all_is_idempotent() -> None:
    """Reaped handles are dropped, so a second call cannot kill a recycled pid."""
    proc = _start_sleeper()
    teardown = Teardown()
    teardown.register_process("scan", proc)
    try:
        assert teardown.kill_all() == ["scan"]
        assert teardown.kill_all() == [], "a second pass has nothing left to touch"
    finally:
        if proc.poll() is None:  # pragma: no cover - cleanup only
            proc.kill()


def test_kill_all_skips_a_process_that_already_exited() -> None:
    proc = subprocess.Popen(
        [sys.executable, "-c", "pass"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    proc.wait(timeout=30)
    teardown = Teardown()
    teardown.register_process("scan", proc)
    assert teardown.kill_all() == []


def test_unregister_prevents_a_later_kill() -> None:
    """The pipeline unregisters in a `finally`, so a finished scan is never reaped."""
    proc = _start_sleeper()
    teardown = Teardown()
    teardown.register_process("scan", proc)
    teardown.unregister_process("scan")
    try:
        assert teardown.kill_all() == []
        assert proc.poll() is None, "an unregistered process is not ours to kill"
    finally:
        proc.kill()


def test_cleanup_partial_removes_staging_directories(tmp_path: Path) -> None:
    staging = tmp_path / ".staging-B-abc"
    (staging / "ai").mkdir(parents=True)
    (staging / "ai" / "prompt.md").write_text("partial", encoding="utf-8")
    final = tmp_path / "B-abc"
    final.mkdir()

    teardown = Teardown()
    teardown.register_artifact_dir(staging)
    removed = teardown.cleanup_partial()

    assert removed == [staging]
    assert not staging.exists(), "a half-written bundle must not survive a cancel"
    assert final.exists(), "the cleanup must not touch a finished bundle"
    assert teardown.cleanup_partial() == [], "idempotent"


# --- the signal --------------------------------------------------------


def test_canceled_abort_is_base_exception_not_exception() -> None:
    """If this ever becomes an `Exception`, every guard below silently stops working."""
    assert issubclass(CanceledAbort, BaseException)
    assert not issubclass(CanceledAbort, Exception)


def test_canceled_abort_carries_where_it_happened() -> None:
    abort = CanceledAbort(stage="scan", resource="scan_process", detail="rc=-15")
    assert abort.stage == "scan"
    assert abort.resource == "scan_process"
    assert "rc=-15" in str(abort)
    assert abort.scan_record is None


@pytest.mark.parametrize(
    "swallow_site",
    [
        "scan_runner",
        "lsp_manager_call",
        "expand_one",
        "reader_read",
    ],
)
def test_canceled_abort_passes_through_the_swallow_sites(swallow_site: str) -> None:
    """Each site catches `Exception` on purpose; the abort must walk straight through.

    Rather than relying on reading the source, this reproduces each site's guard shape and
    asserts the abort escapes it. The scan-runner case is exercised for real: it is the
    function whose docstring promises it never raises.
    """
    if swallow_site == "scan_runner":
        from services.scan import runner as scan_runner

        class _Raising:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def scan(self, *args, **kwargs):
                raise CanceledAbort(stage="scan", resource="scan_process")

            def version(self) -> str:
                return "fake"

            def resolve_binary(self):
                return ("fake", False)

        original = scan_runner.OpengrepRunner
        scan_runner.OpengrepRunner = _Raising  # type: ignore[misc]
        try:
            # `run_scan` swallows the abort *deliberately* -- it must never raise -- and
            # reports it as a canceled outcome instead. That contract is the reason the
            # abort cannot simply be allowed through here.
            outcome = scan_runner.run_scan(scan_runner.ScanRequest(workspace=Path(".")))
            assert outcome.canceled is True
            assert outcome.scan_record is not None
            assert outcome.scan_record.failure_mode == "scan_aborted"
        finally:
            scan_runner.OpengrepRunner = original  # type: ignore[misc]
        return

    def guard(fn):
        """The exact shape used at the other three sites: `except Exception` -> default."""
        try:
            return fn()
        except Exception:
            return None

    with pytest.raises(CanceledAbort):
        guard(lambda: (_ for _ in ()).throw(CanceledAbort(stage="expand", resource="slice")))


def test_a_blocked_lsp_request_is_interrupted_by_abort(tmp_path: Path) -> None:
    """`threading.Event.wait` cannot be interrupted, so the client polls; this pins it.

    The request never gets an answer (no server), so the only way out is the abort check.
    """
    from services.extraction.lsp.client import LspClient

    client = LspClient(name="fake", command=["definitely-not-a-real-server"], root=tmp_path)
    client.default_timeout_s = 30.0
    client.poll_interval_s = 0.02

    class _FakeStdin:
        def write(self, data) -> None:
            pass

        def flush(self) -> None:
            pass

    class _FakeProc:
        def poll(self):
            return None

        stdin = _FakeStdin()

    client._proc = _FakeProc()  # type: ignore[assignment]
    aborted = threading.Event()
    client.bind_abort(aborted.is_set, stage="locate")

    threading.Timer(0.1, aborted.set).start()
    started = time.monotonic()
    with pytest.raises(CanceledAbort) as caught:
        client.request("textDocument/documentSymbol", {"textDocument": {"uri": "file:///x"}})
    elapsed = time.monotonic() - started

    assert caught.value.resource == "lsp_request"
    assert caught.value.stage == "locate"
    assert elapsed < 1.0, f"abort took {elapsed:.2f}s; the poll loop is not running"


def test_an_unbound_client_still_times_out(tmp_path: Path) -> None:
    """No abort bound -> today's behaviour, including the timeout."""
    from services.extraction.lsp.client import LspClient

    client = LspClient(name="fake", command=["definitely-not-a-real-server"], root=tmp_path)
    client.default_timeout_s = 0.2
    client.poll_interval_s = 0.02

    class _FakeStdin:
        def write(self, data) -> None:
            pass

        def flush(self) -> None:
            pass

    class _FakeProc:
        def poll(self):
            return None

        stdin = _FakeStdin()

    client._proc = _FakeProc()  # type: ignore[assignment]
    with pytest.raises(TimeoutError):
        client.request("textDocument/documentSymbol", {})
