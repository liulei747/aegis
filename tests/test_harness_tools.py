"""The tool layer's refusal surface, one test per way it says no.

The refusals are the product here, not the features. Every tool in this package exists so that a
model -- or a prompt injected into the repository under review -- can look at code without being
able to leave the workspace, write anything, or nominate the answer of a dataflow query. So the
tests are organised around the three layers of ``shell_command`` (binary, subcommand, argument
path), the path policy every tool shares, and the one rule that has no workaround:
``dataflow_verify`` has no sink parameter.

No network and no dataflow fleet: the verifier is injected (``ToolContext.dataflow``) or backed
by a fake client, which is also what proves the tool layer can be exercised without a JVM.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from aegis_contracts.dataflow import FlowBundle, FlowElement, TaintFlow
from aegis_contracts.harness import (
    DataflowEvidence,
    ShellCommandPolicy,
    ToolCall,
    ToolName,
    ToolResult,
)
from services.harness.tools import TOOLS, invoke, schemas
from services.harness.tools import read as read_module
from services.harness.tools.base import ToolContext, ToolLimits
from services.harness.tools.dataflow import WorkerDataflowVerifier, evidence_from_bundle

#: The interpreter's own name, so the shell tests do not depend on which POSIX tools exist on
#: the machine running them (`ls`, `cat` and `grep` do not exist on a stock Windows box).
PYTHON_BIN = Path(shutil.which(sys.executable) or sys.executable).name

#: A policy that lets the tests run a real program while still exercising every refusal layer.
TEST_BINARIES = [PYTHON_BIN, "git", "find", "sed", "cat"]


# ─────────────────────────────────────────────────────────── fixtures


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """A small tree with everything the refusals need: vendored dirs, a binary, a symlink target."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(
        "".join(f"line {number}\n" for number in range(1, 26)), encoding="utf-8"
    )
    (root / "probe.py").write_text("import os\nprint(os.getcwd())\n", encoding="utf-8")
    (root / "handler.py").write_text(
        "def handle_request(request):\n    return request.args.get('id')\n", encoding="utf-8"
    )
    (root / "data.bin").write_bytes(b"\x00\x01\x02not source code")
    (root / ".env").write_text("SECRET=1\n", encoding="utf-8")
    for skipped in ("node_modules", "__pycache__", ".git"):
        (root / skipped).mkdir()
        (root / skipped / "inside.txt").write_text("vendored\n", encoding="utf-8")
    (root / "pkg").mkdir()
    (root / "pkg" / "mod.py").write_text(
        "def handler(request):\n    return request\n", encoding="utf-8"
    )
    return root


@pytest.fixture()
def context(repo: Path) -> ToolContext:
    return ToolContext(workspace=repo)


@pytest.fixture()
def shell_context(repo: Path) -> ToolContext:
    return ToolContext(
        workspace=repo,
        shell_policy=ShellCommandPolicy(allowed_binaries=list(TEST_BINARIES)),
    )


def run_tool(context: ToolContext, tool: ToolName, **arguments) -> ToolResult:
    """Invoke through the public entry point, the way the orchestrator will."""
    return invoke(context, ToolCall(tool=tool, arguments=arguments, reason="test"))


class RecordingVerifier:
    """Stands in for the dataflow fleet: records the call, returns canned evidence."""

    def __init__(self, evidence: DataflowEvidence) -> None:
        self.evidence = evidence
        self.calls: list[tuple[str, int, str | None]] = []

    def verify(self, *, file: str, line: int, source_hint: str | None) -> DataflowEvidence:
        self.calls.append((file, line, source_hint))
        return self.evidence


class FakeClient:
    """A ``WorkerDataflowClient``-shaped double. Records what the worker would have been asked."""

    def __init__(self, bundle: FlowBundle | None = None, error: Exception | None = None) -> None:
        self.bundle = bundle
        self.error = error
        self.calls: list[dict] = []

    def extract(self, **kwargs) -> FlowBundle:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        assert self.bundle is not None
        return self.bundle


class FakeFactory:
    """The injectable client factory: what a real deployment would point at the fleet."""

    def __init__(self, client: FakeClient) -> None:
        self.client = client
        self.configs: list = []
        self.workspaces: list[Path] = []

    def __call__(self, config, workspace: Path) -> FakeClient:
        self.configs.append(config)
        self.workspaces.append(workspace)
        return self.client


def make_bundle(
    *, sink: str = "execute", flows: int = 1, source_candidates: int = 1
) -> FlowBundle:
    """A FlowBundle with `flows` distinct paths, shaped like the worker's real answer."""
    bundle = FlowBundle(
        source_anchor="request.args.get",
        source_kind="call",
        source_expr="request.args.get",
        sink_anchor=sink,
        sink_derived_from="app.py:6" if sink else None,
        engine="joiner-worker/0",
        source_candidates=source_candidates,
        sink_candidates=1,
    )
    for index in range(flows):
        bundle.flows.append(
            TaintFlow(
                index=index,
                elements=[
                    FlowElement(
                        label="CALL",
                        code="request.args.get('id')",
                        method="handle_request",
                        file="app.py",
                        line="6",
                    ),
                    FlowElement(
                        label="CALL",
                        code=f"cursor.execute(query)  # flow {index}",
                        method="run_query",
                        file="app.py",
                        line="9",
                    ),
                ],
            )
        )
    return bundle


# ─────────────────────────────────────────────────────────── the frozen surface


def test_schemas_describe_every_registered_tool() -> None:
    described = schemas()
    assert [schema["name"] for schema in described] == [
        "read",
        "list_files",
        "shell_command",
        "dataflow_verify",
        "record",
        "board",
    ]
    assert {schema["name"] for schema in described} == {tool.value for tool in TOOLS}
    for schema in described:
        assert schema["parameters"]["type"] == "object"
        assert schema["parameters"]["additionalProperties"] is False
        assert schema["description"]


def test_invoke_swallows_a_tool_that_raises(monkeypatch, context: ToolContext) -> None:
    """A raising tool is a message, not a crashed ReAct step."""

    class Boom:
        name = ToolName.READ

        def schema(self) -> dict:
            return {}

        def run(self, tool_context, arguments) -> ToolResult:
            raise ValueError("模型给了坏参数")

    monkeypatch.setitem(TOOLS, ToolName.READ, Boom())
    result = run_tool(context, ToolName.READ, path="app.py")
    assert result.ok is False
    assert result.tool is ToolName.READ
    assert "ValueError" in result.error
    assert "模型给了坏参数" in result.error


def test_invoke_refuses_a_tool_that_returns_a_non_result(monkeypatch, context: ToolContext) -> None:
    class Silent:
        name = ToolName.READ

        def schema(self) -> dict:
            return {}

        def run(self, tool_context, arguments):
            return None

    monkeypatch.setitem(TOOLS, ToolName.READ, Silent())
    result = run_tool(context, ToolName.READ, path="app.py")
    assert result.ok is False
    assert "非 ToolResult" in result.error


def test_invoke_refuses_an_unregistered_tool(monkeypatch, context: ToolContext) -> None:
    monkeypatch.delitem(TOOLS, ToolName.SHELL)
    result = run_tool(context, ToolName.SHELL, argv=["ls"])
    assert result.ok is False
    assert result.data["requested_tool"] == "shell_command"
    assert "未知工具" in result.error
    # `tool=None`, not one of the four: no tool was called, so none may be blamed for the refusal.
    assert result.tool is None


def test_invoke_refuses_a_name_that_is_not_even_a_tool_name(context: ToolContext) -> None:
    """A hallucinated tool name is a string, not a `ToolName`; it must not become a real tool."""

    class FakeCall:
        tool = "bash"
        arguments: dict = {}

    result = invoke(context, FakeCall())
    assert result.ok is False
    assert result.tool is None
    assert result.data["requested_tool"] == "bash"
    assert "bash" in result.summary


# ─────────────────────────────────────────────────────────── read


def test_read_returns_numbered_lines(context: ToolContext) -> None:
    result = run_tool(context, ToolName.READ, path="app.py", offset=3, limit=2)
    assert result.ok is True
    assert result.data["lines"] == ["line 3", "line 4"]
    assert result.summary.splitlines()[1] == "3\tline 3"
    assert result.truncated is True
    assert result.data["next_offset"] == 5
    assert "已截断" in result.summary


def test_read_refuses_parent_traversal(context: ToolContext) -> None:
    result = run_tool(context, ToolName.READ, path="../../../etc/passwd")
    assert result.ok is False
    assert "越出工作区" in result.error
    assert result.data == {} or "lines" not in result.data


def test_read_refuses_absolute_path_outside(context: ToolContext, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("not in the workspace\n", encoding="utf-8")
    result = run_tool(context, ToolName.READ, path=str(outside))
    assert result.ok is False
    assert "越出工作区" in result.error


def test_read_refuses_a_symlink_that_leaves_the_workspace(
    context: ToolContext, repo: Path, tmp_path: Path
) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("secret\n", encoding="utf-8")
    link = repo / "shortcut.txt"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):  # pragma: no cover - Windows without privilege
        pytest.skip("此环境不允许创建符号链接")
    result = run_tool(context, ToolName.READ, path="shortcut.txt")
    assert result.ok is False
    assert "越出工作区" in result.error


def test_read_refuses_binary_files(context: ToolContext) -> None:
    result = run_tool(context, ToolName.READ, path="data.bin")
    assert result.ok is False
    assert "二进制" in result.error


def test_read_refuses_a_directory(context: ToolContext) -> None:
    result = run_tool(context, ToolName.READ, path="pkg")
    assert result.ok is False
    assert "目录" in result.error


def test_read_refuses_a_file_over_the_size_cap(
    context: ToolContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(read_module, "MAX_FILE_BYTES", 16)
    result = run_tool(context, ToolName.READ, path="app.py")
    assert result.ok is False
    assert "过大" in result.error


def test_read_truncates_a_long_file_at_the_call_limit(context: ToolContext, repo: Path) -> None:
    (repo / "long.txt").write_text(
        "".join(f"row {number}\n" for number in range(1, 301)), encoding="utf-8"
    )
    result = run_tool(context, ToolName.READ, path="long.txt", limit=10_000)
    assert result.data["returned_lines"] == ToolLimits().max_read_lines
    assert result.truncated is True
    assert any("上限" in note for note in result.data["notes"])
    assert result.data["next_offset"] == ToolLimits().max_read_lines + 1


def test_read_reports_an_offset_past_the_end_without_lying(context: ToolContext) -> None:
    result = run_tool(context, ToolName.READ, path="app.py", offset=999)
    assert result.ok is True
    assert result.data["lines"] == []
    assert result.data["returned_lines"] == 0
    assert "超出文件末尾" in result.summary


def test_read_clips_its_summary_to_max_output_chars(repo: Path) -> None:
    narrow = ToolContext(workspace=repo, limits=ToolLimits(max_output_chars=200))
    result = run_tool(narrow, ToolName.READ, path="app.py")
    assert result.ok is True
    assert result.truncated is True
    assert len(result.summary) <= 200


def test_read_refuses_a_missing_path_argument(context: ToolContext) -> None:
    result = run_tool(context, ToolName.READ)
    assert result.ok is False
    assert "path" in result.error


# ─────────────────────────────────────────────────────────── list_files


def test_list_files_returns_workspace_relative_sorted_paths(context: ToolContext, repo: Path) -> None:
    result = run_tool(context, ToolName.LIST_FILES)
    assert result.ok is True
    paths = [entry["path"] for entry in result.data["files"]]
    assert paths == sorted(paths)
    assert all(not Path(path).is_absolute() for path in paths)
    assert "pkg/mod.py" in paths  # POSIX separators, even on Windows
    sizes = {entry["path"]: entry["size"] for entry in result.data["files"]}
    assert sizes["app.py"] == (repo / "app.py").stat().st_size


def test_list_files_skips_skip_dirs_and_hidden_directories(context: ToolContext) -> None:
    result = run_tool(context, ToolName.LIST_FILES)
    paths = {entry["path"] for entry in result.data["files"]}
    assert not any(path.startswith(("node_modules/", "__pycache__/", ".git/")) for path in paths)
    assert "inside.txt" not in paths
    # A dotfile at the top of the tree *is* part of the repository, unlike a hidden directory.
    assert ".env" in paths


def test_list_files_respects_max_and_says_it_stopped_early(context: ToolContext) -> None:
    result = run_tool(context, ToolName.LIST_FILES, max=2)
    assert result.ok is True
    assert len(result.data["files"]) == 2
    assert result.data["total_matched"] > 2
    assert result.truncated is True
    assert "已截断" in result.summary


def test_list_files_clamps_max_to_the_call_limit(repo: Path) -> None:
    narrow = ToolContext(workspace=repo, limits=ToolLimits(max_list_files=3))
    result = run_tool(narrow, ToolName.LIST_FILES, max=1000)
    assert len(result.data["files"]) == 3
    assert result.truncated is True
    assert any("上限" in note for note in result.data["notes"])


def test_list_files_pattern_selects_a_subtree(context: ToolContext) -> None:
    result = run_tool(context, ToolName.LIST_FILES, pattern="**/*.py")
    assert {entry["path"] for entry in result.data["files"]} == {
        "app.py",
        "handler.py",
        "probe.py",
        "pkg/mod.py",
    }


def test_list_files_reports_a_complete_empty_listing(context: ToolContext) -> None:
    result = run_tool(context, ToolName.LIST_FILES, pattern="**/*.rs")
    assert result.ok is True
    assert result.data["files"] == []
    assert result.truncated is False
    assert "没有匹配" in result.summary


@pytest.mark.parametrize("pattern", ["../*", "/etc/*", "pkg/../../*"])
def test_list_files_refuses_a_pattern_that_escapes(context: ToolContext, pattern: str) -> None:
    result = run_tool(context, ToolName.LIST_FILES, pattern=pattern)
    assert result.ok is False
    assert "工作区" in result.error


# ─────────────────────────────────────────────────────────── shell_command


def test_shell_runs_an_allowed_binary_with_the_workspace_as_cwd(
    shell_context: ToolContext, repo: Path
) -> None:
    result = run_tool(shell_context, ToolName.SHELL, argv=[sys.executable, "probe.py"])
    assert result.ok is True
    assert result.data["exit_code"] == 0
    assert Path(result.data["stdout"].strip()).resolve() == repo.resolve()
    assert result.data["cwd"] == str(repo)


def test_shell_refuses_a_string_argv(shell_context: ToolContext) -> None:
    result = run_tool(shell_context, ToolName.SHELL, argv="ls -la")
    assert result.ok is False
    assert result.data["refused"] == "argv_is_string"
    assert "数组" in result.error


def test_shell_refuses_argv_that_is_not_a_non_empty_list(shell_context: ToolContext) -> None:
    assert run_tool(shell_context, ToolName.SHELL, argv=[]).data["refused"] == "argv_shape"
    assert run_tool(shell_context, ToolName.SHELL).data["refused"] == "argv_shape"
    assert (
        run_tool(shell_context, ToolName.SHELL, argv=["ls", 3]).data["refused"] == "argv_item_type"
    )


def test_shell_refuses_a_binary_that_is_not_allowlisted(repo: Path) -> None:
    """The interpreter exists and runs, but this policy does not allow it."""
    policy = ShellCommandPolicy(allowed_binaries=["git"])
    context = ToolContext(workspace=repo, shell_policy=policy)
    result = run_tool(context, ToolName.SHELL, argv=[sys.executable, "probe.py"])
    assert result.ok is False
    assert result.data["refused"] == "binary_not_allowed"
    assert "白名单" in result.error


def test_shell_refuses_a_binary_that_is_not_on_path(shell_context: ToolContext) -> None:
    result = run_tool(shell_context, ToolName.SHELL, argv=["aegis-not-a-real-binary", "-x"])
    assert result.ok is False
    assert result.data["refused"] == "binary_not_found"


@pytest.mark.parametrize(
    "argv",
    [
        ["git", "commit", "-m", "x"],
        ["git", "checkout", "main"],
        ["find", ".", "-delete"],
        ["find", ".", "-exec", "cat", "{}", ";"],
        ["sed", "-n", "-i", "1,5p", "app.py"],
        ["cat", "--in-place", "app.py"],
    ],
)
def test_shell_refuses_forbidden_subcommands(shell_context: ToolContext, argv: list[str]) -> None:
    result = run_tool(shell_context, ToolName.SHELL, argv=argv)
    assert result.ok is False
    assert result.data["refused"] == "forbidden_subcommand"


@pytest.mark.parametrize(
    "argv",
    [
        # The first three are measured: on the Java benchmark `formatPath`, `performQuickBackup` and
        # `validateAndFormat` are the command-execution chain's own method names, and every one of
        # them was refused because it contains the letters "rm". `addInterceptors` contains "add",
        # and `--include=*.java` contains "-i". None of them can write anything.
        ["grep", "-rn", "formatPath", "."],
        ["grep", "-rn", "performQuickBackup", "."],
        ["grep", "-rn", "validateAndFormat", "."],
        ["grep", "-rn", "addInterceptors", "."],
        ["grep", "-rn", "--include=*.java", "permitAll", "."],
        ["grep", "-i", "clean", "app.py"],
    ],
)
def test_shell_allows_a_read_only_search_whose_pattern_contains_a_policy_word(
    shell_context: ToolContext, argv: list[str]
) -> None:
    """A pattern is data, not a command.

    Refusing a search because a policy word appears inside its pattern cost 48% of shell calls on
    the Java benchmark and pushed agents onto fallback greps that returned nothing, so the searches
    that would have read the command-execution call chain never ran.
    """
    result = run_tool(shell_context, ToolName.SHELL, argv=argv)
    assert result.data.get("refused") != "forbidden_subcommand", result.error


@pytest.mark.parametrize(
    "argv",
    [
        # Still a write, and not equal to `-i`: the in-place flag with an attached backup suffix.
        ["sed", "-i.bak", "-n", "1,5p", "app.py"],
        ["sed", "--in-place", "1,5p", "app.py"],
    ],
)
def test_shell_still_refuses_in_place_writes_after_the_matching_change(
    shell_context: ToolContext, argv: list[str]
) -> None:
    """Narrowing the match must not open a write path.

    `sed -i.bak` writes and is not the string `-i`; `--in-place` is the long spelling while the
    policy records `in-place` without dashes. Both are why the check compares flag *names*.
    """
    result = run_tool(shell_context, ToolName.SHELL, argv=argv)
    assert result.ok is False
    assert result.data["refused"] == "forbidden_subcommand"


@pytest.mark.parametrize(
    "argv",
    [
        # The subcommand is found past the global options that take a value.
        ["git", "-C", ".", "commit", "-m", "x"],
        ["git", "-c", "core.pager=cat", "checkout", "main"],
        ["git", "--git-dir=.git", "clean", "-fd"],
    ],
)
def test_shell_finds_a_git_subcommand_behind_its_global_options(
    shell_context: ToolContext, argv: list[str]
) -> None:
    """Position, not containment: `git -C . commit` must not slip through as an unknown word."""
    result = run_tool(shell_context, ToolName.SHELL, argv=argv)
    assert result.ok is False
    assert result.data["refused"] == "forbidden_subcommand"


def test_shell_refuses_a_write_program_by_name_before_resolving_path(
    shell_context: ToolContext,
) -> None:
    """`rm` is refused as a program token, not because it happens to be missing from PATH."""
    result = run_tool(shell_context, ToolName.SHELL, argv=["rm", "-rf", "app.py"])
    assert result.ok is False
    assert result.data["refused"] == "forbidden_subcommand"


@pytest.mark.parametrize(
    "argv",
    [
        ["cat", "notes.txt; cat /etc/passwd"],
        ["git", "log", "--pretty=%H` id `"],
        ["cat", "$(cat /etc/passwd)"],
        ["cat", "a && b"],
        ["cat", "name\ncat /etc/passwd"],
    ],
)
def test_shell_refuses_a_shell_string_smuggled_into_argv(
    shell_context: ToolContext, argv: list[str]
) -> None:
    result = run_tool(shell_context, ToolName.SHELL, argv=argv)
    assert result.ok is False
    assert result.data["refused"] == "shell_metacharacter"


def test_shell_refuses_a_binary_that_is_a_hidden_shell(shell_context: ToolContext) -> None:
    """`sh -c "..."` is the whole point of the argv design: the shell is not allow-listed."""
    result = run_tool(shell_context, ToolName.SHELL, argv=["sh", "-c", "cat app.py"])
    assert result.ok is False
    assert result.data["refused"] in {"binary_not_found", "binary_not_allowed"}


def test_shell_refuses_an_absolute_path_outside_the_workspace(
    shell_context: ToolContext, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    result = run_tool(shell_context, ToolName.SHELL, argv=[sys.executable, "probe.py", str(outside)])
    assert result.ok is False
    assert result.data["refused"] == "path_escape"


def test_shell_refuses_a_relative_path_that_escapes(shell_context: ToolContext) -> None:
    result = run_tool(shell_context, ToolName.SHELL, argv=[sys.executable, "probe.py", "../../etc/passwd"])
    assert result.ok is False
    assert result.data["refused"] == "path_escape"


def test_shell_refuses_a_tilde_path_because_no_shell_expands_it(
    shell_context: ToolContext,
) -> None:
    result = run_tool(shell_context, ToolName.SHELL, argv=[sys.executable, "probe.py", "~/.ssh/id_rsa"])
    assert result.ok is False
    assert result.data["refused"] == "tilde_path"


def test_shell_keeps_a_path_inside_the_workspace(shell_context: ToolContext) -> None:
    """`..` is not banned as a character: what is banned is resolving outside the workspace."""
    result = run_tool(shell_context, ToolName.SHELL, argv=[sys.executable, "probe.py", "pkg/../app.py"])
    assert result.ok is True
    assert result.data["argv"][2] == "pkg/../app.py"


def test_shell_times_out_without_raising_and_returns_partial_output(repo: Path) -> None:
    (repo / "slow.py").write_text(
        "import sys, time\nsys.stdout.write('partial output')\nsys.stdout.flush()\ntime.sleep(30)\n",
        encoding="utf-8",
    )
    context = ToolContext(
        workspace=repo,
        shell_policy=ShellCommandPolicy(allowed_binaries=[PYTHON_BIN], max_seconds=0.8),
    )
    result = run_tool(context, ToolName.SHELL, argv=[sys.executable, "slow.py"])
    assert result.ok is False
    assert result.data["timed_out"] is True
    assert result.data["exit_code"] is None
    assert "partial output" in result.data["stdout"]
    assert "超时" in result.summary
    assert result.error and "超时" in result.error


def test_shell_caps_the_output_of_a_command_that_then_times_out(repo: Path) -> None:
    """The tail of a hanging noisy command must not reach the blackboard through `data`."""
    (repo / "noisy_slow.py").write_text(
        "import sys, time\nsys.stdout.write('B' * 50_000)\nsys.stdout.flush()\ntime.sleep(30)\n",
        encoding="utf-8",
    )
    context = ToolContext(
        workspace=repo,
        shell_policy=ShellCommandPolicy(
            allowed_binaries=[PYTHON_BIN], max_seconds=0.8, max_output_bytes=500
        ),
    )
    result = run_tool(context, ToolName.SHELL, argv=[sys.executable, "noisy_slow.py"])
    assert result.data["timed_out"] is True
    assert result.data["truncated"] is True
    assert result.truncated is True
    assert len(result.data["stdout"].encode("utf-8")) <= 500


def test_shell_clamps_timeout_to_the_policy_ceiling(shell_context: ToolContext) -> None:
    result = run_tool(shell_context, ToolName.SHELL, argv=[sys.executable, "probe.py"], timeout_s=3600)
    assert result.ok is True
    assert result.data["timeout_s"] == ShellCommandPolicy().max_seconds
    assert "已裁剪" in result.summary


def test_shell_caps_output_and_makes_the_truncation_visible(repo: Path) -> None:
    (repo / "noisy.py").write_text("print('A' * 5000)\n", encoding="utf-8")
    context = ToolContext(
        workspace=repo,
        shell_policy=ShellCommandPolicy(allowed_binaries=[PYTHON_BIN], max_output_bytes=200),
    )
    result = run_tool(context, ToolName.SHELL, argv=[sys.executable, "noisy.py"])
    assert result.ok is True
    assert result.data["truncated"] is True
    assert result.truncated is True
    assert len(result.data["stdout"].encode("utf-8")) <= 200
    assert "已截断" in result.summary


def test_shell_reports_a_non_zero_exit_with_its_output(shell_context: ToolContext, repo: Path) -> None:
    (repo / "fail.py").write_text(
        "import sys\nsys.stderr.write('boom')\nsys.exit(3)\n", encoding="utf-8"
    )
    result = run_tool(shell_context, ToolName.SHELL, argv=[sys.executable, "fail.py"])
    assert result.ok is False
    assert result.data["exit_code"] == 3
    assert result.data["no_match"] is False
    assert "boom" in result.data["stderr"]
    assert "退出码 3" in result.summary


def test_a_search_that_finds_nothing_is_a_result_not_a_failure(
    shell_context: ToolContext, repo: Path, monkeypatch
) -> None:
    """`grep` exit 1 means "no line was selected", and that negative is often the evidence.

    Measured: on a five-file demo, 21 of 22 "failed" tool calls were negative searches --
    `grep -rni -E 'session|auth|owner|token' .` returning exit 1 with no output. Their authors were
    asking "is there any authorization code here", and the answer *was* the empty result. Recording
    it as a failure turns "we checked and there is none" into "we could not check", which is the
    opposite claim.

    Driven through the real subprocess path by declaring the interpreter itself a search binary, so
    the test does not depend on `grep` existing on the machine running it.
    """
    from services.harness.tools import shell as shell_module

    (repo / "nomatch.py").write_text("import sys\nsys.exit(1)\n", encoding="utf-8")
    monkeypatch.setattr(shell_module, "NO_MATCH_BINARIES", frozenset({PYTHON_BIN}))

    result = run_tool(shell_context, ToolName.SHELL, argv=[sys.executable, "nomatch.py"])

    assert result.ok is True, "the search ran; that it selected no lines is the answer"
    assert result.data["no_match"] is True
    assert result.data["exit_code"] == 1
    assert "没有匹配" in result.summary, "and the summary says so in words, not only as a code"
    assert result.error is None


def test_a_search_error_is_still_a_failure(shell_context: ToolContext, repo: Path, monkeypatch) -> None:
    """Exit 2 is grep's "something went wrong" -- the fix must not swallow that."""
    from services.harness.tools import shell as shell_module

    (repo / "broken.py").write_text("import sys\nsys.exit(2)\n", encoding="utf-8")
    monkeypatch.setattr(shell_module, "NO_MATCH_BINARIES", frozenset({PYTHON_BIN}))

    result = run_tool(shell_context, ToolName.SHELL, argv=[sys.executable, "broken.py"])

    assert result.ok is False
    assert result.data["no_match"] is False
    assert "退出码 2" in result.summary


def test_the_no_match_rule_knows_grep_and_git_grep_only() -> None:
    """The predicate, directly: a convention that applies to searches and to nothing else."""
    from services.harness.tools.shell import _is_no_match

    assert _is_no_match(["grep", "-rn", "x", "."], 1) is True
    assert _is_no_match(["/usr/bin/grep", "x"], 1) is True
    assert _is_no_match(["rg", "x"], 1) is True
    assert _is_no_match(["git", "grep", "-n", "x"], 1) is True
    assert _is_no_match(["git", "-C", "/tmp", "grep", "x"], 1) is True
    # Everything else keeps the ordinary rule: non-zero is a failure.
    assert _is_no_match(["grep", "x"], 2) is False
    assert _is_no_match(["git", "log"], 1) is False
    assert _is_no_match([sys.executable, "fail.py"], 1) is False


def test_shell_never_returns_the_environment(shell_context: ToolContext) -> None:
    """`env`/`printenv` are not allow-listed, and no key of os.environ leaks into the result."""
    result = run_tool(shell_context, ToolName.SHELL, argv=["env"])
    assert result.ok is False
    assert result.data["refused"] in {"binary_not_found", "binary_not_allowed"}
    assert "PATH" not in json.dumps(result.data)


# ─────────────────────────────────────────────────────────── dataflow_verify


def test_dataflow_schema_has_no_sink_field() -> None:
    """The single most important line in the tool layer, asserted on the prompt surface."""
    schema = next(item for item in schemas() if item["name"] == "dataflow_verify")
    properties = schema["parameters"]["properties"]
    assert "sink" not in properties
    assert set(properties) == {"file", "line", "source_hint"}
    assert schema["parameters"]["required"] == ["file", "line"]


def test_dataflow_refuses_a_sink_argument_at_runtime(context: ToolContext) -> None:
    result = run_tool(
        context, ToolName.DATAFLOW_VERIFY, file="app.py", line=6, sink="execute"
    )
    assert result.ok is False
    assert result.data["refused"] == "sink_argument"
    assert "sink" in result.error


def test_dataflow_reports_unavailability_honestly(context: ToolContext) -> None:
    """No verifier means ok=False with an error -- never an empty-but-successful path."""
    result = run_tool(context, ToolName.DATAFLOW_VERIFY, file="app.py", line=6)
    assert result.ok is False
    assert result.data["unavailable"] == "dataflow_verifier_absent"
    evidence = result.data["evidence"]
    assert evidence["error"]
    assert evidence["path"] == []
    assert evidence["derived"] is False
    assert "未接入" in result.error


def test_dataflow_refuses_a_file_outside_the_workspace(context: ToolContext, tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    result = run_tool(context, ToolName.DATAFLOW_VERIFY, file=str(outside), line=1)
    assert result.ok is False
    assert result.data["refused"] == "path_escape"


def test_dataflow_refuses_a_missing_line(context: ToolContext) -> None:
    result = run_tool(context, ToolName.DATAFLOW_VERIFY, file="app.py")
    assert result.ok is False
    assert "line" in result.error


def test_dataflow_returns_the_injected_verifier_evidence(repo: Path) -> None:
    evidence = DataflowEvidence(
        derived=True,
        source="request.args.get",
        sink="execute",
        path=["app.py:6 request.args.get('id')", "app.py:9 cursor.execute(query)"],
        methods=["handle_request", "run_query"],
    )
    verifier = RecordingVerifier(evidence)
    context = ToolContext(workspace=repo, dataflow=verifier)
    result = run_tool(
        context,
        ToolName.DATAFLOW_VERIFY,
        file="pkg/../app.py",
        line=6,
        source_hint="request.args.get",
    )
    assert result.ok is True
    assert verifier.calls == [("app.py", 6, "request.args.get")]
    assert result.data["derived"] is True
    assert result.data["evidence"]["sink"] == "execute"
    assert result.data["evidence"]["path"] == evidence.path
    assert "execute" in result.summary


def test_dataflow_reports_a_verifier_exception_as_evidence(repo: Path) -> None:
    class Exploding:
        def verify(self, *, file: str, line: int, source_hint: str | None) -> DataflowEvidence:
            raise RuntimeError("worker exploded")

    context = ToolContext(workspace=repo, dataflow=Exploding())
    result = run_tool(context, ToolName.DATAFLOW_VERIFY, file="app.py", line=6)
    assert result.ok is False
    assert "worker exploded" in result.error
    assert result.data["evidence"]["error"]
    assert result.data["evidence"]["derived"] is False


def test_dataflow_reports_an_empty_path_as_negative_evidence(repo: Path) -> None:
    """A resolved sink with no flow is a *result*: the engine proved the value cannot get there."""
    evidence = DataflowEvidence(derived=True, source="request.args.get", sink="execute")
    context = ToolContext(workspace=repo, dataflow=RecordingVerifier(evidence))
    result = run_tool(context, ToolName.DATAFLOW_VERIFY, file="app.py", line=6)
    assert result.ok is True
    assert result.data["evidence"]["path"] == []
    assert "没有路径" in result.summary


# ─────────────────────────────────────────────────────────── the real adapter


def _verifier(
    repo: Path,
    *,
    client: FakeClient | None = None,
    config=None,
) -> tuple[WorkerDataflowVerifier, FakeClient, FakeFactory]:
    from aegis_core.config import DataflowConfig

    bundle = make_bundle()
    fake = client or FakeClient(bundle=bundle)
    factory = FakeFactory(fake)
    verifier = WorkerDataflowVerifier(
        repo,
        config=config or DataflowConfig(enabled=True, source="request.args.get"),
        client_factory=factory,
    )
    return verifier, fake, factory


def test_worker_verifier_sends_the_finding_position_and_never_a_sink(repo: Path) -> None:
    verifier, client, _ = _verifier(repo)
    evidence = verifier.verify(file="app.py", line=6, source_hint="request.args.get")
    assert evidence.derived is True
    assert evidence.sink == "execute"
    assert evidence.source == "request.args.get"
    assert evidence.methods == ["handle_request", "run_query"]
    call = client.calls[0]
    assert call["finding_path"] == "app.py"
    assert call["finding_line"] == 6
    assert "sink" not in call
    # Every question is `auto` now. The engine holds the graph, and only the graph can answer
    # "which method contains this line, and what does it take" for a language we do not parse.
    assert call["source_kind"] == "auto"
    assert call["source_method"] == ""
    assert call["source_parameter"] == ""


def test_worker_verifier_passes_a_bare_hint_through_instead_of_classifying_it(repo: Path) -> None:
    """A bare name is ambiguous -- `handle_request` is a method here, `getenv` is a call.

    That ambiguity used to be settled *here*, by parsing this workspace with `ast.parse`, which
    made the answer Python-only: on a Java project the parse raised and the hint was silently
    downgraded to a call anchor. The engine settles it against the CPG instead, so the hint now
    travels unchanged and the classification is the same rule for every language.
    """
    verifier, client, factory = _verifier(repo)
    verifier.verify(file="handler.py", line=2, source_hint="handle_request")
    call = client.calls[0]
    assert call["source_kind"] == "auto"
    assert call["source_method"] == ""
    # The hint travels inside the client's config; there is no per-call argument for it.
    assert factory.configs[0].source == "handle_request"


def test_worker_verifier_passes_a_dotted_hint_through(repo: Path) -> None:
    verifier, client, factory = _verifier(repo)
    verifier.verify(file="app.py", line=6, source_hint="os.getenv")
    assert client.calls[0]["source_kind"] == "auto"
    assert factory.configs[0].source == "os.getenv"


def test_worker_verifier_sends_no_hint_at_all_when_the_model_gave_none(repo: Path) -> None:
    """`auto` with no hint must arrive as **no** source, not as the configured default.

    Sending the default is the bug this replaced: `request.args.get` is a string a call matcher
    looks for, so it turns "let the graph decide" back into "match this literal" -- and on a graph
    built from Java that matches nothing, which the reader then sees as "the value cannot reach the
    sink". The enclosing method and its parameter come from the engine's own sink derivation.
    """
    verifier, client, factory = _verifier(repo)
    verifier.verify(file="pkg/mod.py", line=2, source_hint=None)
    call = client.calls[0]
    assert call["source_kind"] == "auto"
    assert call["source_method"] == ""
    assert factory.configs[0].source == "", "no hint means no hint, not the configured default"


def test_worker_verifier_keeps_separate_clients_per_source_needle(repo: Path) -> None:
    verifier, _client, factory = _verifier(repo)
    verifier.verify(file="app.py", line=6, source_hint="getenv")
    verifier.verify(file="app.py", line=6, source_hint="os.getenv")
    verifier.verify(file="app.py", line=6, source_hint="getenv")
    assert [config.source for config in factory.configs] == ["getenv", "os.getenv"]


def test_worker_verifier_normalises_the_path_it_sends(repo: Path) -> None:
    verifier, client, _ = _verifier(repo)
    verifier.verify(file=str(repo / "pkg" / "mod.py"), line=2, source_hint=None)
    assert client.calls[0]["finding_path"] == "pkg/mod.py"


def test_worker_verifier_refuses_a_path_outside_the_workspace(repo: Path, tmp_path: Path) -> None:
    verifier, client, factory = _verifier(repo)
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    evidence = verifier.verify(file=str(outside), line=1, source_hint=None)
    assert evidence.error
    assert client.calls == []
    assert factory.configs == []


def test_worker_verifier_reports_an_unreachable_worker_as_an_error(repo: Path) -> None:
    from services.extraction.dataflow.client import DataflowUnavailable

    verifier, _client, _factory = _verifier(
        repo, client=FakeClient(error=DataflowUnavailable("worker 0 is unreachable: refused"))
    )
    evidence = verifier.verify(file="app.py", line=6, source_hint=None)
    assert evidence.derived is False
    assert evidence.path == []
    assert evidence.error and "DataflowUnavailable" in evidence.error


def test_worker_verifier_explains_a_workspace_path_mismatch(repo: Path) -> None:
    """A 404 because the worker was handed a host path must not look like a security answer."""
    verifier, _client, _factory = _verifier(
        repo, client=FakeClient(error=RuntimeError('404 workspace not found: /workspace'))
    )
    evidence = verifier.verify(file="app.py", line=6, source_hint=None)
    assert evidence.error
    assert "AEGIS_DATAFLOW__WORKER_WORKSPACE" in evidence.error
    assert evidence.derived is False


def test_worker_verifier_reports_an_unresolved_sink_as_an_error(repo: Path) -> None:
    verifier, _client, _factory = _verifier(repo, client=FakeClient(bundle=make_bundle(sink="")))
    evidence = verifier.verify(file="app.py", line=6, source_hint=None)
    assert evidence.derived is False
    assert evidence.error and "汇聚点" in evidence.error


def test_worker_verifier_refuses_when_dataflow_is_disabled(repo: Path) -> None:
    from aegis_core.config import DataflowConfig

    verifier, client, factory = _verifier(repo, config=DataflowConfig(enabled=False))
    evidence = verifier.verify(file="app.py", line=6, source_hint=None)
    assert evidence.error and "未启用" in evidence.error
    assert client.calls == []
    assert factory.configs == []


def test_evidence_from_bundle_keeps_several_flows_apart() -> None:
    evidence = evidence_from_bundle(make_bundle(flows=2))
    assert evidence.derived is True
    assert any("另一条路径" in step for step in evidence.path)
    assert "app.py:6 request.args.get('id')" in evidence.path
    assert any("flow 1" in step for step in evidence.path)


def test_evidence_from_bundle_never_invents_a_sanitizer() -> None:
    """Nothing in a flow bundle names a sanitizer; guessing one would reject a real finding."""
    assert evidence_from_bundle(make_bundle()).sanitizers == []


def test_evidence_from_bundle_treats_a_source_that_matched_nothing_as_an_error() -> None:
    """An empty path from an anchor that matched no node is a broken question, not a result.

    Measured on the Java project in `var/projects`: a Python-shaped source anchor matched 0
    nodes, and reporting that as "no flows" would have handed the validation stage a negative
    finding about code the engine never actually searched.
    """
    evidence = evidence_from_bundle(make_bundle(source_candidates=0))
    assert evidence.error and "来源锚点" in evidence.error
    assert evidence.derived is False
    assert evidence.path == []
    assert evidence.sink == "execute"  # the sink *was* derived; only the answer is unusable


def test_worker_verifier_reports_a_source_anchor_that_matched_nothing(repo: Path) -> None:
    verifier, _client, _factory = _verifier(
        repo, client=FakeClient(bundle=make_bundle(source_candidates=0))
    )
    evidence = verifier.verify(file="handler.py", line=2, source_hint="getenv")
    assert evidence.error
    assert evidence.derived is False


# ─────────────────────────────────────────────────────────── record


class FakeWriter:
    """A stand-in for the coordinator's `_record`: records what it was handed, returns a verdict."""

    def __init__(self, outcome: dict | None = None) -> None:
        self.records: list[dict] = []
        self.outcome = outcome or {"recorded": True, "revision": 3, "note": "已记入 project.notes"}

    def __call__(self, record: dict) -> dict:
        self.records.append(record)
        return self.outcome


def test_record_refuses_when_nothing_is_attached_to_write_to(repo: Path) -> None:
    """No writer means "there is nowhere to record", not a silent success.

    The rule is the one `dataflow_verify` follows when no verifier is attached: a tool that cannot do
    the thing it was asked to do says so, because a model that believes it recorded a fact will not
    repeat it, and the fact is then nowhere -- in the board or in the transcript.
    """
    result = run_tool(ToolContext(workspace=repo), ToolName.RECORD, kind="note", text="uses aiohttp")

    assert result.ok is False
    assert result.error == "record_writer_absent"
    assert result.data["refused"] == "record_writer_absent"
    assert "黑板" in result.summary


def test_record_refuses_a_kind_it_cannot_place(repo: Path) -> None:
    """An unknown kind is refused *and* the refusal names the ones that exist.

    Storing it would put a fact on the board that the report cannot render, which looks like state and
    is worse than a refused call; the model can recover from the refusal because it is told the
    vocabulary.
    """
    writer = FakeWriter()
    context = ToolContext(workspace=repo, record=writer)

    result = run_tool(context, ToolName.RECORD, kind="vulnerability", text="there is an SQLi here")

    assert result.ok is False
    assert result.error == "unknown_record_kind"
    assert writer.records == [], "a refused record must not reach the blackboard"
    assert "component" in result.summary and "threat" in result.summary


def test_record_hands_the_fact_to_the_writer_and_reports_the_revision(repo: Path) -> None:
    """A landed write says where it went and at which revision, so the model can see it took."""
    writer = FakeWriter({"recorded": True, "revision": 12, "note": "已记入 architecture.components（svc）"})
    context = ToolContext(workspace=repo, record=writer)

    result = run_tool(
        context,
        ToolName.RECORD,
        kind="component",
        text='{"id": "scope-svc", "name": "svc", "kind": "service-layer"}',
        scope="scope-svc",
    )

    assert result.ok is True
    assert writer.records == [
        {
            "kind": "component",
            "text": '{"id": "scope-svc", "name": "svc", "kind": "service-layer"}',
            "scope": "scope-svc",
        }
    ]
    assert "revision=12" in result.summary
    assert result.data["revision"] == 12 and result.data["kind"] == "component"


def test_record_reports_a_duplicate_as_a_landed_write(repo: Path) -> None:
    """A duplicate is not a failure. Calling it one would make an agent retry a fact already there."""
    writer = FakeWriter(
        {"recorded": True, "revision": 12, "note": "已记入 project.notes（与已有内容重复，已去重）"}
    )
    context = ToolContext(workspace=repo, record=writer)

    result = run_tool(context, ToolName.RECORD, kind="note", text="uses aiohttp")

    assert result.ok is True
    assert "去重" in result.summary


def test_record_reports_an_empty_text_as_a_refusal(repo: Path) -> None:
    """An empty note is not a fact: refused before it reaches the board, not stored as a blank line."""
    writer = FakeWriter({"recorded": False, "reason": "empty_text"})
    context = ToolContext(workspace=repo, record=writer)

    result = run_tool(context, ToolName.RECORD, kind="note", text="   ")

    assert result.ok is False
    assert result.error == "empty_text"
    assert writer.records == [], "an empty fact must not reach the blackboard at all"


def test_the_record_schema_is_closed_and_lists_every_kind_it_accepts() -> None:
    """The schema is the model's only documentation of the vocabulary, so it must be exhaustive."""
    from services.harness.tools.record import KINDS

    schema = next(schema for schema in schemas() if schema["name"] == "record")
    kind = schema["parameters"]["properties"]["kind"]

    assert kind["enum"] == sorted(KINDS)
    assert set(kind["enum"]) == {
        "actor",
        "asset",
        "component",
        "entry_point",
        "lead",
        "note",
        "threat",
        "trust_boundary",
    }
    assert schema["parameters"]["additionalProperties"] is False
    assert schema["parameters"]["required"] == ["kind", "text"]


# ─────────────────────────────────────────────────────────── board


class FakeBoard:
    """A stand-in for the coordinator's `_board_view`: hands back a canned section, records the ask."""

    def __init__(self, view: dict | None = None) -> None:
        self.asked: list[str] = []
        self.view = view if view is not None else {"count": 2, "components": [{"id": "scope-svc"}]}

    def __call__(self, section: str) -> dict:
        self.asked.append(section)
        return self.view


def test_board_refuses_when_nothing_is_attached_to_read(repo: Path) -> None:
    """Unreadable is not empty. An empty object would tell the model nothing has been established."""
    result = run_tool(ToolContext(workspace=repo), ToolName.BOARD, section="summary")

    assert result.ok is False
    assert result.error == "board_reader_absent"
    assert result.data["refused"] == "board_reader_absent"
    assert "黑板是空的" in result.summary, "the refusal must warn against reading it as 'nothing known'"


def test_board_refuses_a_section_it_does_not_have(repo: Path) -> None:
    reader = FakeBoard()
    context = ToolContext(workspace=repo, board=reader)

    result = run_tool(context, ToolName.BOARD, section="candidates")

    assert result.ok is False
    assert result.error == "unknown_board_section"
    assert reader.asked == [], "a refused section must not reach the board"
    assert "components" in result.summary and "threats" in result.summary


def test_board_defaults_to_the_summary_and_returns_the_reader_s_view(repo: Path) -> None:
    reader = FakeBoard({"count": 3, "components": [{"id": "scope-a", "kind": "web-route"}]})
    context = ToolContext(workspace=repo, board=reader)

    result = run_tool(context, ToolName.BOARD)

    assert reader.asked == ["summary"], "no argument means the summary, not the whole board"
    assert result.ok is True
    assert "scope-a" in result.summary and '"section": "summary"' in result.summary
    assert result.data["section"] == "summary"
    assert result.truncated is False


def test_board_reports_a_malformed_reader_as_a_failure_not_an_empty_board(repo: Path) -> None:
    """A broken deployment must not read as "nothing has been established"."""
    context = ToolContext(workspace=repo, board=lambda _section: ["not", "a", "dict"])

    result = run_tool(context, ToolName.BOARD, section="components")

    assert result.ok is False
    assert result.error == "board_reader_malformed"
    assert "不代表黑板是空的" in result.summary


def test_board_clips_a_large_section_and_says_so(repo: Path) -> None:
    """A silently shortened list would make the model conclude the rest does not exist."""
    big = {"components": [{"id": f"scope-{index}", "name": "x" * 40} for index in range(200)]}
    context = ToolContext(
        workspace=repo, board=FakeBoard(big), limits=ToolLimits(max_output_chars=400)
    )

    result = run_tool(context, ToolName.BOARD, section="components")

    assert result.ok is True
    assert result.truncated is True
    assert "已截断" in result.summary
    # The view itself is not copied into `data`: every step's data is kept in the run on the board.
    assert "components" not in result.data


def test_the_board_schema_is_closed_and_lists_every_section() -> None:
    from services.harness.tools.board import SECTIONS

    schema = next(schema for schema in schemas() if schema["name"] == "board")
    section = schema["parameters"]["properties"]["section"]

    assert section["enum"] == sorted(SECTIONS)
    assert set(section["enum"]) == {"components", "entry_points", "notes", "summary", "threats"}
    assert schema["parameters"]["additionalProperties"] is False
    assert "只读" in schema["description"]


# ─────────────────────────────────────────────────────────── report fixture


def test_every_tool_returns_one_real_result(repo: Path, capsys: pytest.CaptureFixture) -> None:
    """Not assertions only: prints one real ToolResult per tool, for the hand-off report."""
    shell_context = ToolContext(
        workspace=repo, shell_policy=ShellCommandPolicy(allowed_binaries=list(TEST_BINARIES))
    )
    evidence = DataflowEvidence(
        derived=True,
        source="request.args.get",
        sink="execute",
        path=["app.py:6 request.args.get('id')", "app.py:9 cursor.execute(query)"],
        methods=["handle_request", "run_query"],
    )
    cases = [
        (ToolContext(workspace=repo), ToolName.READ, {"path": "app.py", "offset": 1, "limit": 3}),
        (ToolContext(workspace=repo), ToolName.LIST_FILES, {"pattern": "**/*.py"}),
        (shell_context, ToolName.SHELL, {"argv": [sys.executable, "probe.py"]}),
        (
            ToolContext(workspace=repo, dataflow=RecordingVerifier(evidence)),
            ToolName.DATAFLOW_VERIFY,
            {"file": "app.py", "line": 6, "source_hint": "request.args.get"},
        ),
        (
            ToolContext(workspace=repo, record=FakeWriter()),
            ToolName.RECORD,
            {"kind": "trust_boundary", "text": "HTTP request parameters"},
        ),
        (
            ToolContext(workspace=repo, board=FakeBoard({"count": 1, "notes": ["[workspace] sqlite"]})),
            ToolName.BOARD,
            {"section": "notes"},
        ),
    ]
    for tool_context, name, arguments in cases:
        result = run_tool(tool_context, name, **arguments)
        assert isinstance(result, ToolResult)
        assert result.summary
        print(
            json.dumps(
                {
                    "tool": name.value,
                    "ok": result.ok,
                    "truncated": result.truncated,
                    "error": result.error,
                    "data_keys": sorted(result.data),
                    "summary": result.summary,
                },
                ensure_ascii=False,
            )
        )
    assert capsys is not None
