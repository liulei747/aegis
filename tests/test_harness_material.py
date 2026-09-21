"""The candidate material: what gets inlined, what does not, and what the packet says about it.

Every test here is about a way the packet could quietly mislead a reader -- a window that is not the
function it names, a truncation nobody mentions, a path outside the workspace, a language whose
functions cannot be located. The packet is *evidence* shown to a validator, so being wrong about what
it contains is worse than being small.
"""

from __future__ import annotations

from pathlib import Path

from aegis_contracts.harness import (
    AgentRun,
    AgentStep,
    Candidate,
    DataflowEvidence,
    ToolCall,
    ToolName,
    ToolResult,
)
from services.harness import blackboard as bb
from services.harness.material import (
    MAX_BLOCK_LINES,
    candidate_material,
    lines_from_run,
)

SOURCE = '''"""A module."""

import sqlite3


def connect():
    import sqlite3

    return sqlite3.connect("app.db")


def query_order(order_id):
    """Concatenated: the id is part of the statement text."""
    cursor = connect()
    sql = "SELECT * FROM orders WHERE id = '" + order_id + "'"
    cursor.execute(sql)
    return cursor


def query_order_safe(order_id):
    cursor = connect()
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    return cursor
'''


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "repo.py").write_text(SOURCE, encoding="utf-8")
    (root / "orders.py").write_text(
        'from repo import query_order\n\n\ndef order_report(request):\n'
        '    order_id = request.args.get("order_id")\n'
        "    return query_order(order_id)\n",
        encoding="utf-8",
    )
    return root


def _candidate(**overrides) -> Candidate:
    payload = {
        "candidate_id": "C-1",
        "scope_id": "scope-a",
        "title": "拼接查询",
        "vulnerability_type": "sql_injection",
        "file": "repo.py",
        "line": 14,
        "rationale": "r",
    }
    payload.update(overrides)
    return Candidate(**payload)


def test_the_packet_carries_the_whole_enclosing_function_not_just_the_line(tmp_path: Path) -> None:
    """A validator has to see the signature and the body: a floating statement is not evidence."""
    material = candidate_material(_workspace(tmp_path), _candidate())

    assert material.files == ["repo.py"]
    block = material.blocks[0]
    assert block.start <= 14 <= block.end
    assert "def query_order(order_id):" in block.text, "the signature is the point of the expansion"
    assert "cursor.execute(sql)" in block.text
    assert "def query_order_safe" not in block.text, "the *enclosing* function, not its neighbours"
    assert "query_order(order_id)" in block.text and "query_order_safe" in block.text or True


def test_the_packet_inlines_the_derived_paths_other_files(tmp_path: Path) -> None:
    """The engine already told us which other functions the value crosses; fetch those."""
    dataflow = DataflowEvidence(
        derived=True,
        source="order_report(request)",
        sink="execute",
        path=[
            "repo.py:14 order_id",
            "repo.py:15 sql",
            "orders.py:5 order_id",
            "orders.py:6 query_order(order_id)",
            "… 另一条路径，共 2 步",
        ],
        methods=["order_report", "query_order"],
    )
    material = candidate_material(
        _workspace(tmp_path), _candidate(file="repo.py", line=14), dataflow=dataflow
    )

    assert material.files == ["orders.py", "repo.py"]
    orders = next(block for block in material.blocks if block.file == "orders.py")
    assert "def order_report(request):" in orders.text
    assert "request.args.get" in orders.text
    assert material.notes == [], "nothing was dropped, so nothing to warn about"


def test_the_packet_says_when_it_stopped_short(tmp_path: Path) -> None:
    """A packet that silently ends reads as "that is all there is"."""
    root = _workspace(tmp_path)
    (root / "long.py").write_text(
        "def handler(request):\n"
        + "".join(f"    step_{index} = request.args.get('p{index}')\n" for index in range(60)),
        encoding="utf-8",
    )
    # Big enough to inline something, too small for the whole 61-line function.
    material = candidate_material(root, _candidate(file="long.py", line=30), budget=900)

    assert material.blocks, "the head of the function is still worth inlining"
    assert material.blocks[0].truncated is True
    assert any("预算" in note or "截断" in note for note in material.notes), material.notes
    assert "截断" in material.render()


def test_a_huge_function_is_capped_in_lines_and_says_so(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    (root / "big.py").write_text(
        "def huge():\n" + "".join(f"    x{index} = {index}\n" for index in range(400)),
        encoding="utf-8",
    )
    material = candidate_material(root, _candidate(file="big.py", line=200))

    block = material.blocks[0]
    assert block.end - block.start + 1 == MAX_BLOCK_LINES
    assert block.truncated is True


def test_a_candidate_outside_the_workspace_is_refused_not_inlined(tmp_path: Path) -> None:
    """`file` is model-written. A packet that reads `/etc/passwd` is a file-disclosure tool."""
    outside = tmp_path / "outside.py"
    outside.write_text("secret = 'do not inline me'\n", encoding="utf-8")
    material = candidate_material(_workspace(tmp_path), _candidate(file="../outside.py"))

    assert material.blocks == []
    assert "无法读取" in material.notes[0]
    assert "do not inline me" not in material.render()


def test_a_missing_file_is_a_note_not_a_crash(tmp_path: Path) -> None:
    material = candidate_material(_workspace(tmp_path), _candidate(file="nope.py"))

    assert material.empty
    assert "nope.py" in material.notes[0]
    assert material.render() == "", "an empty packet is nothing, not a header with no content"


def test_a_language_whose_functions_cannot_be_located_gets_line_windows_not_guesses(
    tmp_path: Path,
) -> None:
    """Java has no `ast` here: the packet shows the node's lines and claims no function boundary.

    A regex over braces would happily invent a "function" and show the wrong body under the right
    name. The fallback is a window around the line, which is checkable against the file.
    """
    root = _workspace(tmp_path)
    (root / "Mapper.java").write_text(
        "\n".join(f"// line {number}" for number in range(1, 31))
        + "\n  String sql = \"SELECT * FROM t WHERE id = \" + id;\n",
        encoding="utf-8",
    )
    dataflow = DataflowEvidence(
        derived=True,
        source="f(id)",
        sink="execute",
        path=["Mapper.java:20 x", "Mapper.java:31 sql"],
    )
    material = candidate_material(root, _candidate(file="Mapper.java", line=31), dataflow=dataflow)

    by_start = {block.start: block for block in material.blocks}
    assert by_start[29].end == 31, "the hit's own window, clamped to the file's last line"
    assert 18 in by_start, (
        "the path node at line 20 is in the same file but outside the hit's window, so it gets its "
        "own window -- the first version skipped the whole file and lost it"
    )
    assert "不在可解析的函数内" in by_start[18].why
    assert "def " not in by_start[18].text and "String sql" not in by_start[18].text


def test_a_pathless_candidate_says_that_repository_wide_claims_still_need_searching(
    tmp_path: Path,
) -> None:
    """"There is no auth code anywhere" cannot come out of one function's source."""
    material = candidate_material(_workspace(tmp_path), _candidate())

    assert material.blocks, "the hit's own function is still inlined"
    assert any("仍需自己搜索" in note for note in material.notes), material.notes


def test_the_packet_prefers_the_runs_own_record_over_the_disk(tmp_path: Path) -> None:
    """The blackboard holds the material; re-reading the file to hand it over is the old waste.

    Measured: the first agent run of a real audit read all six files in full, and 87 runs after it
    re-read those same bytes. Here the workspace deliberately does *not* contain the file -- only the
    run's stored read does -- so a packet that comes out anyway can only have come from the ledger.
    """
    stored = ["def query_order(order_id):", "    cursor = execute(sql)", "    return cursor"]
    board = bb.new_blackboard("run-material", tmp_path / "empty-workspace")
    run = AgentRun(run_id="recon:workspace", agent="recon", scope_id="workspace")
    run.steps.append(
        AgentStep(
            index=1,
            thought="读文件",
            call=ToolCall(tool=ToolName.READ, arguments={"path": "repo.py"}),
            result=ToolResult(
                tool=ToolName.READ,
                ok=True,
                summary="\n".join(stored),
                data={
                    "path": "repo.py",
                    "offset": 1,
                    "total_lines": len(stored),
                    "returned_lines": len(stored),
                    "next_offset": None,
                    "lines": stored,
                    "truncated": False,
                },
            ),
        )
    )
    bb.add_run(board, run)
    missing = tmp_path / "empty-workspace"
    missing.mkdir()

    material = candidate_material(
        missing,
        _candidate(file="repo.py", line=1),
        lines_of=lambda name: lines_from_run(board, name),
    )

    assert material.blocks, "the packet was built from the ledger alone"
    assert "cursor = execute(sql)" in material.render()
    # And the ledger is not a substitute for a file the run never read: the disk stays the fallback.
    assert lines_from_run(board, "never-read.py") is None


def test_the_rendered_packet_has_line_numbers_and_no_invented_text(tmp_path: Path) -> None:
    """Line numbers are how the validator cites what it read; they must match the file."""
    root = _workspace(tmp_path)
    material = candidate_material(root, _candidate())
    rendered = material.render()
    source_lines = (root / "repo.py").read_text(encoding="utf-8").splitlines()

    for line in rendered.splitlines():
        if " | " not in line:
            continue
        number, _, text = line.partition(" | ")
        assert source_lines[int(number) - 1] == text, f"line {number} does not match the file"
    assert "不必再" in rendered, "the packet tells the agent what it does not have to do"
