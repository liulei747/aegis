"""Projects: the guards that decide what may be created, and the routes that create it.

Most of these assert a **refusal**, not a success. That is deliberate: when a guard in this
feature stops working the feature still works -- the thing it was meant to refuse gets created,
with no error to notice. A test that only covered the happy path would stay green through a
removed scheme check, a removed zip-slip check, or a removed size cap.
"""

from __future__ import annotations

import io
import socket
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from aegis_core.config import ProjectsConfig, get_settings
from app.api.deps import clear_pipeline_cache
from app.main import create_app
from services.projects import fetcher, registry
from services.projects.fetcher import (
    ProjectRejected,
    ProjectTooLarge,
    extract_archive,
    git_argv,
    name_from_url,
    slugify,
    validate_git_url,
)

# ------------------------------------------------------------------ names


@pytest.mark.parametrize("raw", ["..", "../etc", "a/b", "a\\b", "", "   ", "///", "...", "中文"])
def test_a_name_that_could_escape_the_root_is_refused(raw: str) -> None:
    """A name is one path component under the projects root, so `..` and separators are a write
    outside it. Punctuation-only input is refused rather than repaired: silently turning `..`
    into `project` would hide a caller that is confused."""
    with pytest.raises(ProjectRejected):
        slugify(raw)


def test_names_are_reduced_to_a_single_safe_component() -> None:
    assert slugify("My Repo!") == "my-repo"
    assert slugify("  UPPER_case.name  ") == "upper_case.name"
    assert slugify("a---b") == "a-b"
    assert len(slugify("x" * 200)) <= 64
    assert slugify("v1.2.3") == "v1.2.3"


def test_name_from_url_uses_the_last_segment() -> None:
    assert name_from_url("https://github.com/owner/repo.git") == "repo"
    assert name_from_url("https://github.com/owner/repo") == "repo"
    assert name_from_url("https://gitlab.example/group/sub/repo.git") == "repo"


# ------------------------------------------------------------------ urls


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/o/r.git",
        "file:///etc/passwd",
        "git://github.com/o/r.git",
        "ssh://git@github.com/o/r.git",
        "git@github.com:o/r.git",
        "",
        "https://",
    ],
)
def test_only_https_urls_are_accepted(url: str) -> None:
    with pytest.raises(ProjectRejected):
        validate_git_url(url, allow_private_hosts=True)


def test_credentials_in_the_url_are_refused() -> None:
    """This feature stores no credentials, so a URL carrying one is refused rather than used
    and then written into the request log."""
    with pytest.raises(ProjectRejected):
        validate_git_url("https://user:token@github.com/o/r.git", allow_private_hosts=True)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/o/r.git",
        "https://localhost/o/r.git",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/o/r.git",
    ],
)
def test_private_and_link_local_targets_are_refused(url: str) -> None:
    """SSRF: without this, the gateway can be told to fetch its own metadata service. These
    hosts resolve without a network round trip (literals, or localhost), so the test is offline."""
    with pytest.raises(ProjectRejected) as caught:
        validate_git_url(url)
    assert "内网" in str(caught.value)


def test_a_private_target_is_allowed_when_the_operator_opts_in() -> None:
    """A self-hosted GitLab on a private network is a legitimate deployment, so the refusal is
    a default rather than a rule."""
    assert validate_git_url("https://127.0.0.1/o/r.git", allow_private_hosts=True).endswith("r.git")


def test_a_public_host_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """`getaddrinfo` is patched so the test does not depend on DNS: what is being checked is the
    address policy, not the resolver."""
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("140.82.121.3", 0))]
    )
    assert validate_git_url("https://github.com/o/r.git") == "https://github.com/o/r.git"


def test_a_host_that_does_not_resolve_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args, **kwargs):
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(ProjectRejected):
        validate_git_url("https://does-not-exist.invalid/o/r.git")


def test_the_clone_argv_is_hardened_and_never_a_shell_string() -> None:
    """Asserted on the built argv, because these flags are what stand between a server-side
    clone and the filesystem of the container it runs in."""
    config = ProjectsConfig(root=Path("/tmp/x"))
    argv = git_argv(config, url="https://github.com/o/r.git", ref="main", dest=Path("/tmp/x/src"))
    joined = " ".join(argv)
    for flag in ["--depth", "1", "--single-branch", "--no-tags", "protocol.file.allow=never", "--branch", "main"]:
        assert flag in argv, f"{flag} missing from {joined}"
    # The URL must come after `--`, or a URL starting with `-` becomes an option.
    assert argv.index("--") < argv.index("https://github.com/o/r.git")
    assert "clone" in argv and isinstance(argv, list)


# ------------------------------------------------------------------ archives


def _zip(entries: dict[str, bytes]) -> io.BytesIO:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer


@pytest.fixture()
def projects_config(tmp_path: Path) -> ProjectsConfig:
    return ProjectsConfig(root=tmp_path / "projects", max_bytes=1024 * 1024, max_files=50)


def test_a_normal_archive_becomes_a_project(projects_config: ProjectsConfig) -> None:
    stream = _zip({"pkg/app.py": b"print(1)\n", "README.md": b"hi\n"})
    target, total, count = extract_archive(
        projects_config, filename="src.zip", stream=stream, name="demo"
    )
    assert (target / "pkg" / "app.py").read_bytes() == b"print(1)\n"
    assert count == 2 and total > 0
    assert not list(Path(projects_config.root).glob(".staging-*")), "staging must not survive"


@pytest.mark.parametrize("entry", ["../escape.py", "a/../../escape.py", "/tmp/absolute.py", "C:/windows.py"])
def test_archive_entries_that_escape_the_target_are_refused(
    projects_config: ProjectsConfig, entry: str
) -> None:
    """Zip slip. Checked by resolving the destination rather than by scanning the string, which
    is why `a/../../escape.py` is covered as well as a plain `../`."""
    with pytest.raises(ProjectRejected):
        extract_archive(projects_config, filename="evil.zip", stream=_zip({entry: b"x"}), name="evil")
    assert not list(Path(projects_config.root).glob(".staging-*")), "a refused archive leaves nothing"


def test_a_symlink_entry_is_refused(projects_config: ProjectsConfig) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16)  # symlink mode bits
        archive.writestr(info, "/etc/passwd")
    with pytest.raises(ProjectRejected):
        extract_archive(projects_config, filename="evil.zip", stream=buffer, name="evil")


def test_an_archive_that_declares_more_than_the_cap_is_refused(projects_config: ProjectsConfig) -> None:
    """A zip bomb declares a huge uncompressed size in a tiny file, so the cap is checked from
    the header before anything is written."""
    stream = _zip({"big.bin": b"\0" * (2 * 1024 * 1024)})
    with pytest.raises(ProjectTooLarge):
        extract_archive(projects_config, filename="bomb.zip", stream=stream, name="bomb")


def test_content_that_is_not_a_zip_is_refused(projects_config: ProjectsConfig) -> None:
    with pytest.raises(ProjectRejected):
        extract_archive(
            projects_config, filename="not.zip", stream=io.BytesIO(b"plain text"), name="notzip"
        )


def test_only_zip_names_are_accepted(projects_config: ProjectsConfig) -> None:
    with pytest.raises(ProjectRejected):
        extract_archive(projects_config, filename="src.tar.gz", stream=_zip({"a.py": b"x"}), name="t")


def test_a_name_that_already_exists_is_refused(projects_config: ProjectsConfig) -> None:
    extract_archive(projects_config, filename="a.zip", stream=_zip({"a.py": b"x"}), name="dup")
    with pytest.raises(fetcher.ProjectExists):
        extract_archive(projects_config, filename="a.zip", stream=_zip({"a.py": b"x"}), name="dup")


# ------------------------------------------------------------------ git orchestration


def _fake_clone(files: dict[str, bytes], returncode: int = 0, stderr: str = ""):
    """A `subprocess.run` stand-in that materialises the checkout.

    A real local clone is not used because the hardened argv sets
    `protocol.file.allow=never`, which is exactly what blocks cloning from a local path -- and
    a public remote would make the suite depend on the network. The argv itself is asserted
    separately; this covers staging, publish, caps and cleanup.
    """

    def run(argv, **kwargs):
        if "clone" in argv:
            if returncode != 0:
                return SimpleNamespace(returncode=returncode, stdout="", stderr=stderr)
            dest = Path(argv[-1])
            for name, payload in files.items():
                path = dest / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="deadbeef" * 5 + "\n", stderr="")

    return run


def test_a_successful_clone_is_published_with_its_commit(
    projects_config: ProjectsConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fetcher, "validate_git_url", lambda url, **k: url)
    monkeypatch.setattr(subprocess, "run", _fake_clone({"app.py": b"print(1)\n"}))
    target, commit, total, count = fetcher.fetch_git(
        projects_config, url="https://example.test/o/r.git", ref=None, name="cloned"
    )
    assert (target / "app.py").is_file(), "the checkout is the project directory, with no extra level"
    assert commit == "deadbeef" * 5
    assert count == 1 and total > 0
    assert not list(Path(projects_config.root).glob(".staging-*"))


def test_a_failed_clone_leaves_nothing_behind(
    projects_config: ProjectsConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fetcher, "validate_git_url", lambda url, **k: url)
    monkeypatch.setattr(subprocess, "run", _fake_clone({}, returncode=128, stderr="fatal: not found"))
    with pytest.raises(fetcher.ProjectFetchFailed) as caught:
        fetcher.fetch_git(projects_config, url="https://example.test/o/r.git", ref=None, name="gone")
    assert "128" in str(caught.value)
    assert not (Path(projects_config.root) / "gone").exists()
    assert not list(Path(projects_config.root).glob(".staging-*"))


def test_a_clone_over_the_file_cap_is_refused_and_cleaned_up(
    projects_config: ProjectsConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fetcher, "validate_git_url", lambda url, **k: url)
    monkeypatch.setattr(
        subprocess, "run", _fake_clone({f"f{i}.py": b"x" for i in range(projects_config.max_files + 5)})
    )
    with pytest.raises(ProjectTooLarge):
        fetcher.fetch_git(projects_config, url="https://example.test/o/r.git", ref=None, name="huge")
    assert not list(Path(projects_config.root).glob(".staging-*"))


# ------------------------------------------------------------------ registry


def test_records_round_trip_and_staging_is_not_a_project(tmp_path: Path) -> None:
    from aegis_contracts.projects import ProjectRecord, ProjectSource

    root = tmp_path / "projects"
    (root / "one").mkdir(parents=True)
    (root / ".staging-abandoned").mkdir()
    record = ProjectRecord(
        name="one", workspace=str(root / "one"), source=ProjectSource.ARCHIVE, origin="a.zip"
    )
    registry.write_record(root / "one", record)

    assert registry.read_record(root / "one") is not None
    assert [r.name for r in registry.list_records(root)] == ["one"], "a staging dir is not a project"
    assert registry.find_record(root, "one") is not None
    assert registry.find_record(root, "../one") is None, "a name is a component, never a path"


def test_a_damaged_record_does_not_break_the_list(tmp_path: Path) -> None:
    """One unreadable project must not make the others unreachable."""
    root = tmp_path / "projects"
    (root / "broken").mkdir(parents=True)
    (root / "broken" / registry.RECORD_NAME).write_text("{ not json", encoding="utf-8")
    (root / "empty").mkdir()
    assert registry.list_records(root) == []


# ------------------------------------------------------------------ routes


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("AEGIS_WORKSPACE_ROOT", str(tmp_path / "workspace"))
    monkeypatch.setenv("AEGIS_OUTPUT_DIR", str(tmp_path / "packages"))
    monkeypatch.setenv("AEGIS_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("AEGIS_PROJECTS__ROOT", str(tmp_path / "projects"))
    monkeypatch.setenv("AEGIS_LSP_ENABLED", "false")
    get_settings.cache_clear()
    clear_pipeline_cache()
    with TestClient(create_app()) as test_client:
        yield test_client
    get_settings.cache_clear()
    clear_pipeline_cache()


def test_upload_creates_a_project_and_reports_it(client: TestClient) -> None:
    response = client.post(
        "/v1/projects/upload",
        files={"file": ("demo.zip", _zip({"app.py": b"print(1)\n"}).getvalue(), "application/zip")},
        data={"name": "zip-1", "analyze": "false"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["name"] == "zip-1"
    assert body["source"] == "archive"
    assert body["origin"] == "demo.zip"
    assert body["files"] == 1
    assert body["job_id"] is None, "analyze=false must not submit anything"
    # Compared as a path, not by suffix: the separator differs on Windows.
    workspace = Path(body["workspace"])
    assert workspace.name == "zip-1" and workspace.parent.name == "projects"

    listing = client.get("/v1/projects").json()["projects"]
    assert [item["name"] for item in listing] == ["zip-1"]
    assert client.get("/v1/projects/zip-1").status_code == 200
    assert client.get("/v1/projects/nope").status_code == 404


def test_uploading_the_same_name_twice_is_a_conflict(client: TestClient) -> None:
    payload = {"file": ("a.zip", _zip({"a.py": b"x"}).getvalue(), "application/zip")}
    # `analyze=false` throughout: this test is about the name collision, and the submission
    # path needs a queue that this suite deliberately does not provide.
    data = {"name": "dup", "analyze": "false"}
    assert client.post("/v1/projects/upload", files=payload, data=data).status_code == 201
    again = client.post("/v1/projects/upload", files=payload, data=data)
    assert again.status_code == 409
    assert "已存在" in again.json()["detail"]


def test_analyze_true_records_the_submitted_job(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The submission itself is stubbed: what is under test is that the route asks for it and
    records the id, not the queue's own behaviour (which has its own tests)."""
    monkeypatch.setattr("app.api.routes.get_job_queue", lambda: (object(), object()))
    monkeypatch.setattr("app.api.routes._submit_analysis", lambda *a, **k: "J-stub")
    response = client.post(
        "/v1/projects/upload",
        files={"file": ("a.zip", _zip({"a.py": b"x"}).getvalue(), "application/zip")},
        data={"name": "analysed", "analyze": "true"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["job_id"] == "J-stub"
    # Persisted too, not just returned: the list must show the same thing.
    assert client.get("/v1/projects/analysed").json()["job_id"] == "J-stub"


def test_a_bad_repository_url_is_refused_before_the_clone(client: TestClient) -> None:
    response = client.post(
        "/v1/projects", json={"git_url": "http://insecure.example/r.git", "analyze": False}
    )
    assert response.status_code == 400
    assert "https" in response.json()["detail"]
    assert client.get("/v1/projects").json()["projects"] == []


def test_a_private_target_is_refused_before_the_clone(client: TestClient) -> None:
    response = client.post(
        "/v1/projects", json={"git_url": "https://127.0.0.1/r.git", "analyze": False}
    )
    assert response.status_code == 400
    assert "内网" in response.json()["detail"]


def test_the_feature_can_be_switched_off(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_PROJECTS__ENABLED", "false")
    get_settings.cache_clear()
    response = client.post("/v1/projects", json={"git_url": "https://example.test/r.git"})
    assert response.status_code == 503
    assert "关闭" in response.json()["detail"]
    get_settings.cache_clear()


def test_health_reports_whether_projects_can_be_created(client: TestClient) -> None:
    """A front-end can hide the form instead of offering one whose every submission fails."""
    capabilities = client.get("/health").json()["capabilities"]
    assert capabilities["projects"]["enabled"] is True
    assert capabilities["projects"]["writable"] is True
