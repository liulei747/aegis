"""A single LSP server process, spoken to over stdio JSON-RPC.

Thread model (deliberately simple and portable):

* ``_reader`` thread parses stdout frames and settles futures / dispatches notifications.
* ``_writer`` thread drains an outbound queue into stdin.
* callers block on ``request()``; async callers wrap it via ``asyncio.to_thread``.

This avoids asyncio subprocess-transport portability traps while still allowing
concurrent usage from the async pipeline.
"""

from __future__ import annotations

import queue
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis_core.cancel import CanceledAbort
from aegis_core.logging import get_logger
from aegis_core.utils import to_uri
from services.extraction.lsp.protocol import (
    LspError,
    ServerExited,
    encode_message,
    try_decode_message,
)

log = get_logger(__name__)

_INIT_TIMEOUT_S = 90.0


@dataclass
class _Pending:
    event: threading.Event
    result: Any = None
    error: dict[str, Any] | None = None


class LspClient:
    """One language server. Not thread-safe to start twice; requests are."""

    def __init__(
        self,
        *,
        name: str,
        command: list[str],
        root: Path,
        language_id_map: dict[str, str] | None = None,
        default_timeout_s: float = 20.0,
        init_options: dict[str, Any] | None = None,
        settings: dict[str, Any] | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self.command = command
        self.root = root.resolve()
        self.language_id_map = language_id_map or {}
        self.default_timeout_s = default_timeout_s
        self.init_options = init_options or {}
        self.settings = settings or {}
        self.env = env

        self.capabilities: dict[str, Any] = {}
        self.server_info: dict[str, Any] = {}

        self._proc: subprocess.Popen[bytes] | None = None
        self._outbox: queue.Queue[bytes | None] = queue.Queue()
        self._pending: dict[int, _Pending] = {}
        self._pending_lock = threading.Lock()
        self._next_id = 0
        self._id_lock = threading.Lock()
        self._open_docs: set[str] = set()
        self._settled_docs: set[str] = set()
        self._docs_lock = threading.Lock()
        self._stopping = threading.Event()
        self._exit_error: str | None = None
        self._tokens: dict[str, Any] = {}
        self._token_lock = threading.Lock()
        self._started = False
        self.notification_hooks: list[Callable[[str, dict[str, Any]], None]] = []
        # Cancellation. `None` means "not interruptible", which is the default and keeps
        # every existing caller on exactly today's behaviour.
        self._abort: Callable[[], bool] | None = None
        self._stage: str = "setup"
        self.poll_interval_s = 0.05

    # ------------------------------------------------------------------
    # cancellation wiring
    # ------------------------------------------------------------------
    def bind_abort(self, abort: Callable[[], bool] | None, *, stage: str) -> None:
        """Attach the predicate that makes a blocked request interruptible.

        Thread-safe by construction: the attribute is read and written as one reference,
        and both reader and writer only ever call or replace it.
        """
        self._abort = abort
        self._stage = stage

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._started:
            return
        log.info("starting LSP server %s: %s", self.name, " ".join(self.command))
        try:
            self._proc = subprocess.Popen(
                self.command,
                cwd=str(self.root),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self.env,
            )
        except FileNotFoundError as exc:
            raise ServerExited(f"language server command not found: {self.command[0]}") from exc

        threading.Thread(target=self._reader, name=f"lsp-{self.name}-reader", daemon=True).start()
        threading.Thread(target=self._writer, name=f"lsp-{self.name}-writer", daemon=True).start()

        result = self.request(
            "initialize",
            {
                "processId": None,
                "clientInfo": {"name": "aegis", "version": "0.1"},
                "rootUri": self.root.as_uri(),
                "rootPath": str(self.root),
                "capabilities": {
                    "workspace": {
                        "workspaceFolders": True,
                        "configuration": True,
                        "symbol": {"dynamicRegistration": False},
                    },
                    "textDocument": {
                        "documentSymbol": {
                            "hierarchicalDocumentSymbolSupport": True,
                            "symbolKind": {"valueSet": list(range(1, 27))},
                        },
                        "callHierarchy": {"dynamicRegistration": False},
                        "definition": {"linkSupport": True},
                        "implementation": {"linkSupport": True},
                        "references": {},
                        "synchronization": {"didSave": False, "willSave": False},
                    },
                    "window": {"workDoneProgress": True},
                },
                "initializationOptions": self.init_options,
                "workspaceFolders": [
                    {"uri": self.root.as_uri(), "name": self.root.name or "workspace"}
                ],
            },
            timeout=_INIT_TIMEOUT_S,
        )
        result = result or {}
        self.capabilities = result.get("capabilities") or {}
        self.server_info = result.get("serverInfo") or {}
        self.notify("initialized", {})
        if self.settings:
            self.notify(
                "workspace/didChangeConfiguration",
                {"settings": self.settings},
            )
        self._started = True
        log.info(
            "LSP %s ready (%s)",
            self.name,
            self.server_info.get("name") or Path(self.command[0]).stem,
        )

    def stop(self) -> None:
        self._stopping.set()
        if self._proc is None:
            return
        try:
            if self._proc.poll() is None:
                try:
                    self.request("shutdown", None, timeout=2.0, raise_on_error=False)
                except Exception:
                    pass
                self.notify("exit", None)
                try:
                    self._proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._proc.terminate()
                    try:
                        self._proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self._proc.kill()
        finally:
            self._outbox.put(None)
            self._fail_pending("server stopped")
            self._proc = None
            self._started = False

    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def supports(self, *path: str) -> bool:
        node: Any = self.capabilities
        for key in path:
            if not isinstance(node, dict):
                return False
            node = node.get(key)
            if node is None:
                return False
        return bool(node)

    # ------------------------------------------------------------------
    # io
    # ------------------------------------------------------------------
    def _next_request_id(self) -> int:
        with self._id_lock:
            self._next_id += 1
            return self._next_id

    def _reader(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        stream = self._proc.stdout
        buffer = bytearray()
        while not self._stopping.is_set():
            chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536)
            if not chunk:
                break
            buffer.extend(chunk)
            while True:
                msg = try_decode_message(buffer)
                if msg is None:
                    break
                self._dispatch(msg)
        self._exit_error = f"LSP server {self.name} exited"
        self._fail_pending(self._exit_error)

    def _writer(self) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        sink = self._proc.stdin
        while True:
            item = self._outbox.get()
            if item is None:
                break
            try:
                sink.write(item)
                sink.flush()
            except (BrokenPipeError, ValueError):
                break

    def _dispatch(self, msg: dict[str, Any]) -> None:
        if "id" in msg and ("result" in msg or "error" in msg):
            with self._pending_lock:
                pending = self._pending.pop(int(msg["id"]), None)
            if pending is None:
                return
            pending.error = msg.get("error")
            pending.result = msg.get("result")
            pending.event.set()
            return

        method = msg.get("method") or ""
        params = msg.get("params") or {}
        if "id" in msg:
            # Server -> client request. Answer everything benignly so the server proceeds.
            self._answer_server_request(msg)
            return
        if method == "$/progress":
            self._track_progress(params)
            return
        for hook in self.notification_hooks:
            try:
                hook(method, params)
            except Exception:  # pragma: no cover - hooks are best effort
                log.debug("notification hook failed for %s", method, exc_info=True)

    def _answer_server_request(self, msg: dict[str, Any]) -> None:
        method = msg.get("method") or ""
        if method == "workspace/configuration":
            items = (msg.get("params") or {}).get("items") or []
            result: Any = [self.settings for _ in items] if self.settings else [{} for _ in items]
        elif method in {"window/workDoneProgress/create", "client/registerCapability"}:
            result = None
        elif method == "workspace/workspaceFolders":
            result = [{"uri": self.root.as_uri(), "name": self.root.name or "workspace"}]
        elif method == "workspace/applyEdit":
            result = {"applied": False}
        else:
            result = None
        self._send({"jsonrpc": "2.0", "id": msg["id"], "result": result})

    def _track_progress(self, params: dict[str, Any]) -> None:
        token = params.get("token")
        value = params.get("value") or {}
        if token is None:
            return
        with self._token_lock:
            if value.get("kind") == "end":
                self._tokens.pop(str(token), None)
            else:
                self._tokens[str(token)] = value

    def _fail_pending(self, reason: str) -> None:
        with self._pending_lock:
            items = list(self._pending.values())
            self._pending.clear()
        for pending in items:
            pending.error = {"code": -32099, "message": reason}
            pending.event.set()

    def _send(self, payload: dict[str, Any]) -> None:
        if self._proc is None:
            raise ServerExited(f"LSP server {self.name} is not running")
        self._outbox.put(encode_message(payload))

    # ------------------------------------------------------------------
    # public rpc
    # ------------------------------------------------------------------
    def notify(self, method: str, params: Any) -> None:
        try:
            self._send({"jsonrpc": "2.0", "method": method, "params": params})
        except ServerExited:
            log.debug("notify %s dropped: server gone", method)

    def request(
        self,
        method: str,
        params: Any,
        *,
        timeout: float | None = None,
        raise_on_error: bool = True,
    ) -> Any:
        if self._proc is None:
            raise ServerExited(f"LSP server {self.name} is not running")
        if self._exit_error and not self.alive:
            raise ServerExited(self._exit_error)

        req_id = self._next_request_id()
        pending = _Pending(event=threading.Event())
        with self._pending_lock:
            self._pending[req_id] = pending
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})

        if not self._wait_for(pending, req_id, method, timeout):
            raise TimeoutError(f"LSP {self.name}: {method} timed out")
        if pending.error is not None:
            if raise_on_error:
                raise LspError(
                    pending.error.get("code"),
                    pending.error.get("message", "unknown"),
                    pending.error.get("data"),
                )
            return None
        return pending.result

    def _wait_for(self, pending: _Pending, req_id: int, method: str, timeout: float | None) -> bool:
        """Wait for a reply, in short slices, so a cancel can be noticed.

        Python has no interruptible ``Event.wait``: there is no way to wake a blocked
        waiter from outside. Polling is the only portable option, and it is nearly free --
        ``Event.wait`` returns immediately once the event is set, so the added latency is
        at most one poll interval, and only on the path that was going to block anyway.
        """
        deadline = time.monotonic() + (timeout or self.default_timeout_s)
        while True:
            if pending.event.wait(self.poll_interval_s):
                return True
            if self._abort is not None and self._abort():
                with self._pending_lock:
                    self._pending.pop(req_id, None)
                raise CanceledAbort(
                    stage=self._stage,
                    resource="lsp_request",
                    detail=f"{self.name}:{method}",
                )
            if time.monotonic() >= deadline:
                with self._pending_lock:
                    self._pending.pop(req_id, None)
                return False

    def kill(self, *, graceful: bool = False) -> None:
        """Terminate without the LSP parting handshake. The cancel path uses this.

        ``stop()`` is unchanged and still the right call for a normal finish: it asks the
        server to shut down, then escalates. Skipping the pleasantries matters only when we
        are already abandoning the work, and waiting out a handshake there would delay the
        user's cancel for no benefit.

        Safe to call when no server is running, and safe to call twice.
        """
        if graceful:
            self.stop()
            return
        self._stopping.set()
        proc, self._proc = self._proc, None
        self._started = False
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
            except Exception:  # pragma: no cover - best effort teardown
                log.debug("failed to kill LSP %s", self.name, exc_info=True)
        self._outbox.put(None)
        # Wake every blocked request: they are waiting on a server that no longer exists.
        self._fail_pending("canceled: server killed")

    # ------------------------------------------------------------------
    # document sync helpers
    # ------------------------------------------------------------------
    def language_id_for(self, path: Path) -> str:
        suffix = path.suffix.lower()
        return self.language_id_map.get(suffix, self.language_id_map.get(path.name, "plaintext"))

    def open_document(self, path: Path, text: str | None = None) -> str:
        uri = to_uri(path)
        with self._docs_lock:
            if uri in self._open_docs:
                return uri
            self._open_docs.add(uri)
        if text is None:
            text = path.read_text(encoding="utf-8", errors="replace")
        self.notify(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": uri,
                    "languageId": self.language_id_for(path),
                    "version": 1,
                    "text": text,
                }
            },
        )
        return uri

    def close_document(self, path: Path) -> None:
        uri = to_uri(path)
        with self._docs_lock:
            if uri not in self._open_docs:
                return
            self._open_docs.discard(uri)
        self.notify("textDocument/didClose", {"textDocument": {"uri": uri}})

    def close_all(self) -> None:
        with self._docs_lock:
            uris = list(self._open_docs)
            self._open_docs.clear()
        for uri in uris:
            self.notify("textDocument/didClose", {"textDocument": {"uri": uri}})

    def settle(self, seconds: float = 0.15) -> None:
        """Give the server a moment to absorb didOpen before the first query."""
        time.sleep(seconds)

    def settle_document(self, path: Path, seconds: float = 0.2) -> None:
        """Settle once per document, not once per query."""
        uri = to_uri(path)
        with self._docs_lock:
            if uri in self._settled_docs:
                return
            self._settled_docs.add(uri)
        time.sleep(seconds)
