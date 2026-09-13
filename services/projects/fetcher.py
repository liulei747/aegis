"""Bring source code into a projects root: shallow-clone a public repo, or unpack an archive.

The whole attack surface of this feature is here, and the failure mode of a guard is the
nasty kind: if one stops working, **the feature still works** -- the thing it was supposed to
refuse gets created, with no error anywhere. So every guard below names the concrete thing it
prevents.

Two shapes are shared by both paths:

* build into ``<root>/.staging-<random>`` and ``os.replace`` it into place, so a half-fetched
  project is never visible (the same publish pattern the bundle writer uses);
* count bytes and files and enforce the configured caps, because "clone the internet into a
  volume" has no natural limit.
"""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import shutil
import socket
import subprocess
import zipfile
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlsplit

from aegis_core.config import ProjectsConfig

#: Length cap for a project name. Long enough to be recognisable, short enough to stay well
#: inside every filesystem's per-component limit.
MAX_NAME = 64

#: Directory prefix used while a fetch is in flight. `list_records` skips these, and a stray one
#: after a crash is inert rather than a half-project that looks real.
STAGING_PREFIX = ".staging-"


class ProjectError(Exception):
    """Base for every refusal, carrying a message meant to be shown to the user."""


class ProjectRejected(ProjectError):
    """Bad input: a URL we do not accept, a name that is not a name, an archive that is not one."""


class ProjectExists(ProjectError):
    """A project of that name is already registered."""


class ProjectTooLarge(ProjectError):
    """The sources exceed a configured cap."""


class ProjectFetchFailed(ProjectError):
    """`git` failed, timed out, or produced nothing usable."""


def slugify(raw: str) -> str:
    """A project name, reduced to something safe to use as a single path component.

    This is a path-traversal guard, not cosmetic: a name is concatenated onto the projects
    root, so ``..`` or a separator in it would write outside the root.

    Input that is *trying* to be a path is **refused**, not flattened. ``../etc`` collapsing to
    ``etc`` would silently collide with a real project of that name, and it hides a caller that
    is confused about what a name is. Cosmetic noise (case, spaces, punctuation) is normalised,
    because that is a formatting difference rather than a different intent.
    """
    text = raw.strip()
    if not text:
        raise ProjectRejected("项目名不能为空")
    if "/" in text or "\\" in text or ".." in text or not text.strip("."):
        raise ProjectRejected(f"项目名不能包含路径分隔符或 ..：{raw!r}")
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", text.lower())
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    cleaned = cleaned.strip("-.")[:MAX_NAME].strip("-.")
    if not cleaned:
        raise ProjectRejected(f"项目名不可用：{raw!r} 去掉特殊字符后为空")
    return cleaned


def name_from_url(url: str) -> str:
    """The last path segment of a repository URL, minus a trailing `.git`."""
    path = urlsplit(url).path.rstrip("/")
    tail = path.rsplit("/", 1)[-1] if path else ""
    if tail.endswith(".git"):
        tail = tail[: -len(".git")]
    return slugify(tail or "project")


def validate_git_url(url: str, *, allow_private_hosts: bool = False) -> str:
    """Return the URL if it is one we are willing to clone, else raise.

    Four separate decisions, each of which has been the wrong way round in some tool:

    1. **scheme is `https` only** -- `file://` reads the server's own disk, `git://` and
       `ssh://` bypass TLS, and `http://` is plaintext;
    2. **no credentials in the URL** -- this feature has none to store, so
       `https://user:token@host/x` is refused rather than silently used and then logged;
    3. **the host must resolve, and every address it resolves to must be public** -- otherwise
       a user can point the server at its own metadata service or an internal host (SSRF);
    4. the resolved-address check is a **pre-check, not a defence**: `git` resolves the name
       again, so a name whose DNS answer changes in between (DNS rebinding) is not caught here.
    """
    parts = urlsplit(url.strip())
    if parts.scheme != "https":
        raise ProjectRejected(f"只支持 https:// 的仓库地址，收到的是 {parts.scheme or '（空）'}")
    if parts.username or parts.password:
        raise ProjectRejected("仓库地址里不能带用户名或口令：本项目只支持公开仓库")
    host = parts.hostname
    if not host:
        raise ProjectRejected("仓库地址里没有主机名")
    if not allow_private_hosts:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise ProjectRejected(f"无法解析主机 {host}：{exc}") from exc
        addresses = {info[4][0] for info in infos}
        if not addresses:
            raise ProjectRejected(f"主机 {host} 没有解析到任何地址")
        for raw in addresses:
            address = ipaddress.ip_address(raw)
            if not address.is_global:
                raise ProjectRejected(
                    f"主机 {host} 解析到非公网地址 {raw}，已拒绝（防止服务端被用来访问内网）；"
                    "自建服务请设置 AEGIS_PROJECTS__ALLOW_PRIVATE_HOSTS=true"
                )
    return url.strip()


def git_argv(config: ProjectsConfig, *, url: str, ref: str | None, dest: Path) -> list[str]:
    """The exact argv for a clone. A pure function so a test can assert the flags.

    Every flag is load-bearing:

    * ``--depth 1 --single-branch --no-tags`` -- a full clone of a large history is a cheap
      way to fill the volume, and none of that history is needed to analyse the working tree;
    * ``-c protocol.file.allow=never`` -- without it, a repository can pull in a submodule or
      an alternate object store over ``file://``, reaching the server's own filesystem and
      bypassing the URL checks above;
    * no ``--recurse-submodules`` -- a submodule URL is attacker-controlled and is not
      validated by :func:`validate_git_url` at all;
    * ``--`` before the positionals -- a URL beginning with ``-`` must not become a flag;
    * an argv list, never a shell string -- these arguments are attacker-supplied.
    """
    argv = [
        config.git_bin,
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "-c",
        "protocol.file.allow=never",
    ]
    if ref:
        argv += ["--branch", ref]
    argv += ["--", url, str(dest)]
    return argv


def _clean_env(home: Path) -> dict[str, str]:
    """An environment that cannot be influenced by whoever runs the gateway.

    A developer's global gitconfig can define credential helpers, ``insteadOf`` URL rewrites
    and ``protocol.*.allow`` overrides -- all of which would silently change what a
    server-side clone does. So: no system config, no global config, no terminal prompt, and a
    ``HOME`` inside the staging directory (which is also where git would put anything it
    decides to write).
    """
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(home),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/echo",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_LFS_SKIP_SMUDGE": "1",
        "LC_ALL": "C",
    }
    # A proxy is a legitimate deployment need, so pass it through if the operator set it.
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


def measure(root: Path) -> tuple[int, int]:
    """Total bytes and regular-file count under ``root`` (symlinks are not followed)."""
    total = 0
    count = 0
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        total += path.stat().st_size
        count += 1
    return total, count


#: Suffix -> language, for **programming** languages only.
#:
#: Data and markup formats (JSON, XML, YAML, Markdown, HTML, CSS) are deliberately absent: a
#: project's "languages" answers "what would we have to analyse", and counting a `pom.xml` as a
#: language would make a Java project look bilingual. Suffixes are lowercased before lookup.
LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".groovy": "groovy",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".m": "objective-c",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
    ".pl": "perl",
    ".lua": "lua",
    ".r": "r",
    ".dart": "dart",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hs": "haskell",
    ".clj": "clojure",
    ".vb": "vbnet",
    ".fs": "fsharp",
    ".jl": "julia",
    ".tf": "terraform",
    ".proto": "protobuf",
}


def detect_languages(root: Path) -> dict[str, int]:
    """Files per programming language, most files first.

    Recorded when a project is created because it is the one fact that predicts how much of the
    analysis will work: the deep stages (a real call graph, taint flow) are per-language, so a
    Java archive and a Python archive of the same size produce very different bundles. Knowing
    this up front turns "why is this bundle almost empty?" into a question answered before the
    analysis starts.

    Vendored directories are skipped, using the same list the content hash uses -- `node_modules`
    would otherwise make every front-end project look like a JavaScript project.
    """
    from aegis_core.workspace import SKIP_DIRS

    counts: dict[str, int] = {}
    if not root.is_dir():
        return counts
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
        if language:
            counts[language] = counts.get(language, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _enforce_caps(config: ProjectsConfig, root: Path) -> tuple[int, int]:
    total, count = measure(root)
    if count > config.max_files:
        raise ProjectTooLarge(f"文件数 {count} 超过上限 {config.max_files}")
    if total > config.max_bytes:
        raise ProjectTooLarge(f"源码大小 {total} 字节超过上限 {config.max_bytes} 字节")
    return total, count


def new_staging(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    staging = root / f"{STAGING_PREFIX}{secrets.token_hex(6)}"
    staging.mkdir()
    return staging


def publish(root: Path, staging: Path, name: str) -> Path:
    """Move a finished staging directory to its final name, refusing to overwrite.

    ``os.replace`` on a directory is atomic within a filesystem, so a reader either sees no
    project or sees a complete one. There is no moment at which ``<root>/<name>`` exists but is
    still being written.
    """
    target = root / name
    if target.exists():
        raise ProjectExists(f"项目 {name} 已存在")
    os.replace(staging, target)
    return target


def fetch_git(
    config: ProjectsConfig, *, url: str, ref: str | None, name: str
) -> tuple[Path, str | None, int, int]:
    """Clone ``url`` into a new project called ``name``. Returns (dir, commit, bytes, files)."""
    validated = validate_git_url(url, allow_private_hosts=config.allow_private_hosts)
    root = Path(config.root)
    staging = new_staging(root)
    checkout = staging / "src"
    try:
        completed = subprocess.run(
            git_argv(config, url=validated, ref=ref, dest=checkout),
            env=_clean_env(staging),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=config.clone_timeout_s,
            check=False,
        )
        if completed.returncode != 0:
            tail = (completed.stderr or completed.stdout or "").strip().splitlines()
            raise ProjectFetchFailed(
                f"克隆失败（rc={completed.returncode}）：{tail[-1] if tail else '没有任何输出'}"
            )
        if not checkout.is_dir():
            raise ProjectFetchFailed("克隆报告成功，但没有产出目录")

        commit = _rev_parse(config, checkout, staging)
        total, count = _enforce_caps(config, checkout)

        # The sources move up one level so the project directory *is* the checkout: a job
        # passes `workspace=<project dir>`, and an extra `src/` level would be analysed too,
        # making every path in a bundle one segment longer than it needs to be.
        target = publish(root, staging, name)
        inner = target / "src"
        for entry in inner.iterdir():
            os.replace(entry, target / entry.name)
        inner.rmdir()
        return target, commit, total, count
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _rev_parse(config: ProjectsConfig, checkout: Path, home: Path) -> str | None:
    """The checked-out commit. Recorded because a branch name is not a version."""
    completed = subprocess.run(
        [config.git_bin, "-C", str(checkout), "rev-parse", "HEAD"],
        env=_clean_env(home),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    commit = (completed.stdout or "").strip()
    return commit if completed.returncode == 0 and commit else None


#: `\` is a separator on Windows and a legal character on POSIX, so a name containing one is
#: ambiguous: the two platforms would extract it to different places.
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def _safe_member(name: str, target: Path) -> Path:
    """The extraction path for one archive member, or raise.

    Checked by *resolving* rather than by inspecting the string: string checks miss
    combinations (`a/../../b`, `./..`, percent-encoding), whereas comparing the resolved
    destination against the resolved target catches all of them.
    """
    if not name or name.endswith("/"):
        raise ProjectRejected(f"压缩包里有空条目名：{name!r}")
    if name.startswith("/") or name.startswith("\\") or _WINDOWS_DRIVE.match(name):
        raise ProjectRejected(f"压缩包里有绝对路径条目：{name!r}")
    if "\\" in name:
        raise ProjectRejected(f"压缩包条目名含反斜杠，路径含义不明确：{name!r}")
    destination = (target / name).resolve()
    root = target.resolve()
    if destination != root and root not in destination.parents:
        raise ProjectRejected(f"压缩包条目会写到目标目录之外：{name!r}")
    return destination


def extract_archive(
    config: ProjectsConfig, *, filename: str, stream: BinaryIO, name: str
) -> tuple[Path, int, int]:
    """Unpack a zip into a new project called ``name``. Returns (dir, bytes, files)."""
    root = Path(config.root)
    staging = new_staging(root)
    try:
        if not filename.lower().endswith(".zip"):
            raise ProjectRejected(f"只支持 .zip 压缩包，收到的是 {filename!r}")
        try:
            with zipfile.ZipFile(stream) as archive:
                infos = archive.infolist()
                # Declared sizes first: a zip bomb declares a huge uncompressed size while
                # being tiny on the wire, so this is the cheap refusal before writing anything.
                declared = sum(info.file_size for info in infos)
                if declared > config.max_bytes:
                    raise ProjectTooLarge(
                        f"压缩包解压后约 {declared} 字节，超过上限 {config.max_bytes} 字节"
                    )
                if len(infos) > config.max_files:
                    raise ProjectTooLarge(f"压缩包有 {len(infos)} 个条目，超过上限 {config.max_files}")

                written = 0
                files = 0
                for info in infos:
                    if info.is_dir():
                        continue
                    # A symlink entry is not worth supporting: extraction would either create a
                    # link pointing outside the project or a plain file containing a path, and
                    # both surprise somebody.
                    if (info.external_attr >> 16) & 0o170000 == 0o120000:
                        raise ProjectRejected(f"压缩包里有符号链接条目：{info.filename!r}")
                    destination = _safe_member(info.filename, staging)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as source, destination.open("wb") as sink:
                        while True:
                            chunk = source.read(1 << 20)
                            if not chunk:
                                break
                            written += len(chunk)
                            # Enforced while writing as well as from the declared sizes: the
                            # header can lie.
                            if written > config.max_bytes:
                                raise ProjectTooLarge(
                                    f"解压已写出 {written} 字节，超过上限 {config.max_bytes} 字节"
                                )
                            sink.write(chunk)
                    files += 1
        except zipfile.BadZipFile as exc:
            raise ProjectRejected(f"上传的内容不是有效的 zip 压缩包：{exc}") from exc

        # `measure` rather than the running counters: it is the same number a clone path
        # reports, so the two sources cannot disagree about what "size" means.
        total, count = _enforce_caps(config, staging)
        target = publish(root, staging, name)
        return target, total, count
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
