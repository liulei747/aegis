"""A cheap, deterministic reading of the workspace -- scopes and signals, no model, no tool layer.

Two jobs, both of which have to work while nothing else does:

* **Scope derivation.** The coordinator's discovery scopes must come from *what the system
  actually is* (a route group, a component, a trust boundary), never from a fixed count. The agent
  normally does that; this module is the fallback that keeps the promise when the model is not
  available, and it is also what `--dry-run` reports.
* **A signal scan.** Which files contain the shape of a candidate at all. This is a keyword scan,
  not taint analysis: it says "there is a query being built by concatenation here", never "this is
  exploitable". Everything it produces is a `Candidate` -- something worth checking -- and the
  reason strings say how weak the signal is, because the failure mode of a cheap scan is a report
  that reads like it proved something.

Read-only, no network, no model, no tool layer. That is what makes it the piece `--dry-run` can
run on a checkout where nothing else is configured.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from aegis_contracts.harness import ProjectContext
from aegis_core.logging import get_logger

log = get_logger(__name__)

#: Directories never worth walking. Kept local rather than imported from the tool layer: this
#: module must import and run with the tool package absent.
SKIP_DIRS = frozenset(
    {
        "node_modules", ".git", "target", "build", "dist", "out", "bin", "obj", "vendor",
        "venv", ".venv", "env", "__pycache__", ".idea", ".vscode", ".mvn", ".gradle",
        "coverage", "test-results", "site-packages",
    }
)

#: Extensions worth a signal scan. Deliberately broader than the extractor's Python set: the
#: harness reviews repositories in whatever language they are written in.
SOURCE_SUFFIXES = frozenset(
    {
        ".java", ".kt", ".scala", ".groovy", ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb",
        ".php", ".cs", ".c", ".h", ".cc", ".cpp", ".hpp", ".rs", ".swift", ".m", ".mm", ".pl",
        ".sh", ".ps1", ".sql", ".jsp", ".vue", ".xml", ".yml", ".yaml", ".properties",
    }
)

#: Files whose existence names a build system. Ordered: the first match per directory wins, so a
#: Maven project that also has a Gradle file is reported as Maven.
BUILD_MARKERS: tuple[tuple[str, str], ...] = (
    ("pom.xml", "maven"),
    ("build.gradle", "gradle"),
    ("build.gradle.kts", "gradle"),
    ("settings.gradle", "gradle"),
    ("build.sbt", "sbt"),
    ("package.json", "npm"),
    ("pyproject.toml", "python-packaging"),
    ("setup.py", "setuptools"),
    ("requirements.txt", "pip"),
    ("go.mod", "go-modules"),
    ("Cargo.toml", "cargo"),
    ("Gemfile", "bundler"),
    ("composer.json", "composer"),
    ("Makefile", "make"),
    ("CMakeLists.txt", "cmake"),
)

#: Directory names mapped to the scope kind they name, matched against a *single* path component.
#: Component-wise rather than substring, and deliberately without `resources`/`api`/`util`:
#: `resources/db` is a resource root, not a web-route directory, and a heuristic that reads it as
#: architecture invents a component the repository does not have. The plural `controllers` and
#: `services` are here because those are real directory names; the plural `resources` is not,
#: because in every common layout it means "assets", not "routes".
NAME_ROLES: dict[str, str] = {
    "controller": "web-route", "controllers": "web-route",
    "routes": "web-route", "handlers": "web-route", "endpoints": "web-route",
    "service": "service-layer", "services": "service-layer", "usecase": "service-layer",
    "usecases": "service-layer", "domain": "service-layer",
    "dao": "data-access", "repository": "data-access", "repositories": "data-access",
    "mapper": "data-access", "mappers": "data-access", "entity": "data-access",
    "entities": "data-access", "model": "data-access", "models": "data-access",
    "config": "config", "configuration": "config", "settings": "config",
    "job": "batch-task", "jobs": "batch-task", "scheduler": "batch-task",
    "tasks": "batch-task", "consumer": "batch-task", "consumers": "batch-task",
    "listener": "batch-task", "listeners": "batch-task",
}

#: Source roots stripped before role matching, POSIX and lowercased. Without this, a resources
#: directory and a build directory are read as architecture, and a scope count becomes a property
#: of packaging conventions rather than of the system.
SOURCE_ROOTS: tuple[str, ...] = (
    "src/main/java/", "src/main/kotlin/", "src/main/scala/", "src/test/java/",
    "src/main/", "src/", "app/", "lib/", "pkg/", "internal/", "cmd/",
)

#: Stamped on every component this module derives, and read by the `board` tool. The architecture map
#: is a union of three producers -- this directory walk, recon reading the code, and the threat model's
#: own records -- and a component has to carry which one it came from, because "there is a directory
#: called service" and "recon read a service class" are different claims about the system.
SURVEY_ORIGIN = "survey"

#: Marker files per role. Used when the directory name carries no role -- a flat `handlers.py`
#: or a top-level `utils.go` -- so that file naming is a second, weaker source of evidence rather
#: than no evidence at all.
MARKER_ROLES: tuple[tuple[str, str], ...] = (
    ("controller", "web-route"), ("resource", "web-route"), ("handler", "web-route"),
    ("route", "web-route"), ("views", "web-route"), ("endpoint", "web-route"),
    ("service", "service-layer"), ("repository", "data-access"), ("dao", "data-access"),
    ("mapper", "data-access"), ("entity", "data-access"), ("model", "data-access"),
    ("config", "config"), ("settings", "config"), ("job", "batch-task"),
    ("task", "batch-task"), ("consumer", "batch-task"), ("listener", "batch-task"),
)

#: Extensions that are configuration rather than code, used only when the path carries no role.
CONFIG_SUFFIXES: frozenset[str] = frozenset(
    {".yml", ".yaml", ".properties", ".xml", ".toml", ".ini", ".conf"}
)

#: Spring/Java entry-point markers, matched against file text.
ENTRY_MARKERS: tuple[tuple[str, str], ...] = (
    ("@SpringBootApplication", "Spring Boot application"),
    ("@RestController", "REST controller registration"),
    ("@Controller", "controller registration"),
    ("@RequestMapping", "request mapping"),
    ("@Scheduled", "scheduled task"),
    ("@KafkaListener", "message consumer"),
)

ENTRY_MARKERS_PY = (
    (re.compile(r"if\s+__name__\s*==\s*[\"']__main__[\"']"), "python module entry point"),
    (re.compile(r"@(app|router|bp)\.(get|post|put|patch|delete)\("), "web framework route"),
    (re.compile(r"^(async\s+)?def\s+main\(", re.M), "python main()"),
)


@dataclass
class Scope:
    """One unit of investigation, derived from the tree rather than chosen by a fixed count."""

    scope_id: str
    title: str
    kind: str
    path: str
    rationale: str
    files: list[str] = field(default_factory=list)


@dataclass
class Signal:
    """A keyword hit: a candidate with its weakness class and the line it was seen on."""

    scope_id: str
    file: str
    line: int
    vulnerability_type: str
    title: str
    rationale: str


# ─────────────────────────────────────────────────────────── the survey


def survey_workspace(root: Path, *, scope_limit: int = 40) -> dict:
    """Everything this module can say about a workspace, in one pass over it.

    Returned as a plain dict rather than a dataclass because the coordinator immediately hands the
    pieces to different consumers (`ProjectContext`, `ArchitectureMap`, the scope list) and a
    wrapper type would only be unpacked again.
    """
    root = Path(root)
    scopes = discover_scopes(root, limit=scope_limit)
    languages = languages_of(root)
    project = ProjectContext(
        workspace=str(root),
        languages=languages,
        build_systems=build_systems(root),
        entry_points=entry_points(root),
        notes=[
            "survey: languages, build systems and entry points were counted from the tree by the "
            "orchestrator, not established by a model reading it.",
        ],
    )
    components = [
        {
            "id": scope.scope_id,
            "name": scope.title,
            "kind": scope.kind,
            "path": scope.path,
            "description": scope.rationale,
            "files": scope.files,
            # Where this component came from, carried per component rather than only in the map's
            # `notes`: the architecture is a union of what the pre-scan found, what recon read and what
            # the threat model recorded, and an agent looking at one component has to be able to tell
            # which of those it is holding. Directory names are not evidence about behaviour.
            "origin": SURVEY_ORIGIN,
        }
        for scope in scopes
    ]
    return {
        "project": project,
        "scopes": scopes,
        "components": components,
        "languages": languages,
    }


def languages_of(root: Path) -> dict[str, int]:
    """File count per extension, over source-ish files only. The key is the extension without dot."""
    counts: dict[str, int] = {}
    for path in _walk(root):
        if not path.is_file():
            continue
        suffix = path.suffix.lower().lstrip(".")
        if not suffix:
            continue
        counts[suffix] = counts.get(suffix, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def build_systems(root: Path) -> list[str]:
    found: list[str] = []
    for path in _walk(root):
        if not path.is_file():
            continue
        for marker, name in BUILD_MARKERS:
            if path.name == marker and name not in found:
                found.append(name)
    return found


def entry_points(root: Path) -> list[str]:
    """Files that register a process entry point or a network surface, with the marker seen."""
    out: list[str] = []
    for path in _walk(root):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            text = _read(path)
        except OSError:
            continue
        rel = _rel(root, path)
        marker = _entry_marker(text)
        if marker:
            out.append(f"{rel} ({marker})")
    return out


def _entry_marker(text: str) -> str | None:
    for token, label in ENTRY_MARKERS:
        if token in text:
            return label
    for pattern, label in ENTRY_MARKERS_PY:
        if pattern.search(text):
            return label
    return None


def discover_scopes(root: Path, *, limit: int = 40) -> list[Scope]:
    """Derive scopes from the tree: one per role directory or role-named file, plus config.

    Roles come from directory and file names (a framework convention), which is the weakest part of
    this and is stated as such in every scope's rationale. A tree this does not recognise produces a
    single `workspace` scope rather than no scopes: "we could not tell what this is" is a result, and
    a run with zero scopes would report full coverage of nothing.
    """
    by_role: dict[tuple[str, str], list[str]] = {}
    config_files: list[str] = []
    unclassified: list[str] = []

    for path in _walk(root):
        if not path.is_file():
            continue
        rel = _rel(root, path)
        suffix = path.suffix.lower()
        if suffix not in SOURCE_SUFFIXES:
            continue
        # Role first, extension second -- but a config *directory* only claims configuration
        # *files*. `config/WebConfig.java` is still code (it sets up security, CORS and
        # deserialization, so it is worth reading), while `application.yml` and `pom.xml` are
        # descriptors. Testing the extension first classified every MyBatis mapper XML as
        # configuration, which hides the most productive sink location in a Java repository behind a
        # scope whose stated rationale ("credentials and switches live here") is wrong about it.
        role, group = _role_of(rel)
        if role is not None and role != "config":
            by_role.setdefault((role, group), []).append(rel)
            continue
        if suffix in CONFIG_SUFFIXES:
            config_files.append(rel)
            continue
        unclassified.append(rel)

    scopes: list[Scope] = []
    for (role, group), files in sorted(by_role.items()):
        scopes.append(
            Scope(
                scope_id=_scope_id(role, group),
                title=f"{role}：{group}",
                kind=role,
                path=group,
                rationale=(
                    f"`{group}` 下有 {len(files)} 个源文件，其中目录名/文件名表明它承担 {role} 职责。"
                    "该证据仅来自命名约定，属于启发式；模型驱动的 recon 阶段才是确认或推翻它的地方。"
                ),
                files=sorted(files),
            )
        )
    if config_files:
        scopes.append(
            Scope(
                scope_id="scope-config",
                title="配置与部署描述文件",
                kind="config",
                path=".",
                rationale=(
                    f"{len(config_files)} 个配置文件（yml/properties/xml 等）。"
                    "凭据、端点与安全开关通常在描述文件里而不是代码里，因此单列一个 scope；"
                    "`config/` 目录下的源码不在其中，它仍是代码。"
                ),
                files=sorted(config_files),
            )
        )
    if unclassified:
        scopes.append(
            Scope(
                scope_id="scope-root",
                title="workspace root and unrecognised layout",
                kind="entrypoint",
                path=".",
                rationale=(
                    f"{len(unclassified)} 个源文件不在任何可识别的职责目录中。单列一个 scope，"
                    "是为了让它们被显式计划，而不是被静默丢掉。"
                ),
                files=sorted(unclassified),
            )
        )
    if not scopes:
        scopes.append(
            Scope(
                scope_id="scope-workspace",
                title="whole workspace",
                kind="entrypoint",
                path=".",
                rationale=(
                    "没有识别出任何语言或职责结构；整个工作区算一个 scope，"
                    "这是承认无知，不是计划。"
                ),
                files=[],
            )
        )
    if len(scopes) > limit:
        log.warning("survey: %d scopes derived, capped at %d", len(scopes), limit)
        scopes = scopes[:limit]
    return scopes


def _role_of(rel: str) -> tuple[str | None, str]:
    """`(role, group)` for one workspace-relative path, or `(None, "")`.

    Directory names win over file names, and the *deepest* role-named directory wins over shallower
    ones: `service/order/OrderService.java` belongs to the service component, not to a hypothetical
    `order` component that also happens to exist elsewhere. Grouping by that directory is what keeps
    two sibling role directories from collapsing into one scope.

    When no directory carries a role, the *file's own stem* is checked -- as a word, not a
    substring. `OrderRequestDTO.java` contains "task" and is not a batch task; `TaskConsumer.go` is.
    """
    posix = rel.replace("\\", "/")
    lowered = posix.lower()
    relative = lowered
    for prefix in SOURCE_ROOTS:
        if lowered.startswith(prefix):
            relative = lowered[len(prefix):]
            break
    parts = relative.split("/")
    for index in range(len(parts) - 2, -1, -1):
        role = NAME_ROLES.get(parts[index])
        if role is not None:
            return role, "/".join(parts[: index + 1])
    stem = parts[-1].rsplit(".", 1)[0]
    for word in _words(stem):
        role = _MARKER_ROLE_BY_NAME.get(word)
        if role is not None:
            return role, str(Path(posix).parent.as_posix())
    return None, ""


#: Built from `MARKER_ROLES`: the reversed lookup used by `_role_of`, so the two cannot disagree.
_MARKER_ROLE_BY_NAME: dict[str, str] = {marker: role for marker, role in MARKER_ROLES}


def _words(stem: str) -> list[str]:
    """The identifier words in a file stem: `OrderRequestDTO` -> `order request dto`.

    Split on separators and camel-case boundaries so a marker has to be a whole word. Substring
    matching here is what put `OrderRequestDTO.java` in a `batch-task` scope.
    """
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", stem)
    return [word for word in re.split(r"[^a-z0-9]+", spaced.lower()) if word]


def _scope_id(role: str, group: str) -> str:
    """A stable, readable scope id. Readable because it appears in the report and in every
    coverage reason, and a reviewer has to be able to tell which part of the tree it means."""
    slug = re.sub(r"[^a-z0-9]+", "-", group.lower()).strip("-")
    return f"scope-{role}-{slug}" if slug and slug != "." else f"scope-{role}"


# ─────────────────────────────────────────────────────────── signal scan
#
# Each rule is (vulnerability_type, title, compiled pattern matched per line). Regexes rather than
# token lists because a token rule cannot be made specific enough to be worth reading: "password"
# and "=" on one line fires on every field declaration and every getter, which is exactly the noise
# that makes a scanner's output untrustworthy. What every rule here still is, is a *shape*: none of
# them proves anything about data flow, and each signal's rationale says so.
#
# Lowercased matching, so the patterns are written against lowercase text.

SIGNAL_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "sql_injection",
        "query built by string concatenation",
        re.compile(r"\b(select|insert|update|delete)\b[^;]*(\+|\bconcat\b|\.format\()"),
    ),
    (
        "sql_injection",
        "query assembled from request data",
        re.compile(r"\b(execute|executequery|executupdate|rawquery|createnativequery)\b.*(getparameter|getparam|getquery|getheader|getcookies)"),
    ),
    (
        "sql_injection",
        "unparameterised SQL template substitution",
        # MyBatis `${}` interpolates straight into the statement, while `#{}` binds a parameter.
        # This is the difference between a sortable column and injectable SQL, it is invisible to
        # every generic concatenation rule above, and in a Java/MyBatis repository the mappers are
        # where the SQL actually lives -- so the rule is worth having on its own.
        #
        # The SQL keyword is required as well as the `${}`. Without it the rule fires on every
        # Maven property in `pom.xml` (`${project.version}`), which is the kind of false positive
        # that teaches a reader to skim the findings.
        re.compile(r"\b(select|insert|update|delete|where|from|order\s+by|group\s+by|values)\b[^\n]*\$\{[^}]*\}"),
    ),
    (
        "sql_injection",
        "unparameterised SQL template substitution",
        re.compile(r"\{\{[^}]*\}\}|\{%[^%]*%\}"),  # Jinja and Django templates in a SQL string
    ),
    (
        "command_injection",
        "process launched with a command built from data",
        re.compile(r"(runtime\.getruntime\(\)\s*\.\s*exec|processbuilder|\.exec\()"),
    ),
    (
        "ssrf",
        "outbound request to a computed or requested target",
        re.compile(r"(new\s+url\(|resttemplate|httpclient|urlopen|requests\.(get|post))"),
    ),
    (
        "path_traversal",
        "file path built from data",
        re.compile(r"(new\s+file\(|paths\.get\(|fileinputstream|new\s+fileoutputstream|open\()"),
    ),
    (
        "deserialization",
        "object read from untrusted bytes",
        re.compile(r"(objectinputstream|readobject\(|pickle\.loads|yaml\.load\(|readvalue\()"),
    ),
    (
        "hardcoded_secret",
        "literal credential in source",
        re.compile(r"\b(password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token)\b\s*[:=]\s*[\"'][^\"']{6,}[\"']"),
    ),
    (
        "weak_crypto",
        "broken or deprecated primitive",
        re.compile(r"\b(md5|sha1|des|ecb|random\(\))\b"),
    ),
)


def signals(root: Path, scopes: list[Scope], *, max_per_scope: int = 3) -> list[Signal]:
    """Keyword scan per scope, bounded per scope so one huge directory cannot dominate the run.

    The bound is applied while scanning rather than afterwards, so the *cost* is bounded too: a
    directory of 10 000 generated files is not read just to be mostly discarded.
    """
    out: list[Signal] = []
    for scope in scopes:
        found: list[Signal] = []
        for rel in scope.files:
            if len(found) >= max_per_scope:
                break
            path = root / rel
            suffix = path.suffix.lower()
            if suffix not in SOURCE_SUFFIXES:
                continue
            try:
                text = _read(path)
            except OSError:
                continue
            found.extend(
                _scan_file(rel, text, scope_id=scope.scope_id, budget=max_per_scope - len(found))
            )
        out.extend(found[:max_per_scope])
    return out


def _scan_file(file: str, text: str, *, scope_id: str, budget: int) -> list[Signal]:
    """All signals in one file, up to `budget`, without reporting the same weakness twice per file.

    One hit per (weakness class, file) is enough: a candidate is a place to look, and fifty rows
    for fifty concatenations in one method would spend the whole validation budget on one function.
    """
    out: list[Signal] = []
    seen: set[str] = set()
    for index, line in enumerate(text.splitlines(), start=1):
        if len(out) >= budget:
            break
        lowered = line.lower().strip()
        if not lowered or lowered.startswith(("//", "*", "#", "/*")):
            # A comment describing a vulnerability is not a vulnerability, and this scan is far too
            # cheap to be allowed to make that mistake.
            continue
        for vulnerability_type, title, pattern in SIGNAL_RULES:
            if vulnerability_type in seen:
                continue
            if not pattern.search(lowered):
                continue
            seen.add(vulnerability_type)
            out.append(
                Signal(
                    scope_id=scope_id,
                    file=file,
                    line=index,
                    vulnerability_type=vulnerability_type,
                    title=title,
                    rationale=(
                        f"keyword/regex signal only, not taint analysis: line {index} of `{file}` "
                        f"matches the `{vulnerability_type}` shape. Read the enclosing method and "
                        "its callers to decide whether data from outside the trust boundary "
                        "reaches it."
                    ),
                )
            )
            break
    return out


# ─────────────────────────────────────────────────────────── walking


def _walk(root: Path):
    """Every file under `root`, skipping vendored and hidden directories.

    `os.walk`-style but implemented with `iterdir` so the skip set applies at every level,
    including directories this module has never seen.
    """
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    if entry.name.startswith(".") or entry.name in SKIP_DIRS:
                        continue
                    stack.append(entry)
                else:
                    yield entry
            except OSError:
                continue


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
