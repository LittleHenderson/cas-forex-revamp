"""Linux read-only observations of one explicitly supervised Ollama process tree.

No process starts, signals, environment reads, system-wide discovery or port scans.
Observe staged file hashes and mapped inode/process identity, not tensor memory or
unobservable internal sampling parameters. All I/O is explicit capture/verify.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import os
import json
from pathlib import Path, PurePosixPath
import re
from cas_forex_revamp.contracts import ContractError, content_digest
from cas_forex_revamp.contracts.primitives import digest, integer


@dataclass(frozen=True, slots=True)
class PinnedFile:
    role: str
    path: str
    bytes: int
    sha256: str
    def __post_init__(self):
        if self.role not in {"ollama", "runner", "manifest", "weight", "template", "parameters", "config", "license"}:
            raise ContractError("unknown staged runtime file role")
        if type(self.path) is not str or not self.path.startswith("/") or self.path.startswith("//") or str(PurePosixPath(self.path)) != self.path or ".." in PurePosixPath(self.path).parts or "\\" in self.path or "\0" in self.path:
            raise ContractError("staged file requires a canonical absolute guest path")
        integer(self.bytes, "staged file bytes", minimum=1)
        digest(self.sha256)


@dataclass(frozen=True, slots=True)
class SupervisorSpec:
    ollama_pid: int
    ollama_start_ticks: int
    files: tuple[PinnedFile, ...]
    def __post_init__(self):
        integer(self.ollama_pid, "supervised Ollama PID", minimum=1)
        integer(self.ollama_start_ticks, "supervised start ticks", minimum=1)
        if type(self.files) is not tuple or any(not isinstance(f, PinnedFile) for f in self.files):
            raise ContractError("typed pinned files required")
        if len(self.files) != 8 or len({f.role for f in self.files}) != 8:
            raise ContractError("all eight uniquely pinned runtime/model file roles required")


def process_stat(raw):
    end = raw.rfind(") ")
    if end < 0:
        raise ContractError("invalid proc stat")
    fields = raw[end + 2:].split()
    try:
        parent, start = int(fields[1]), int(fields[19])
    except (IndexError, ValueError) as exc:
        raise ContractError("incomplete proc identity") from exc
    if parent < 0 or start <= 0 or fields[0] in {"Z", "X"}:
        raise ContractError("invalid or exited process identity")
    return parent, start


def _argument(argv, names):
    found = []
    for i, value in enumerate(argv):
        if value in names:
            if i + 1 == len(argv):
                raise ContractError("missing runner argument value")
            found.append(argv[i + 1])
        else:
            for name in names:
                if value.startswith(name + "="):
                    found.append(value[len(name) + 1:])
    if len(found) != 1:
        raise ContractError("runner must expose one exact argument")
    return found[0]


class LinuxRuntimeObserver:
    def __init__(self, spec: SupervisorSpec, *, proc_root=Path("/proc")):
        if not isinstance(spec, SupervisorSpec):
            raise ContractError("explicit supervisor spec required")
        self.spec, self.proc_root = spec, Path(proc_root)
        self._files = {f.role: f for f in spec.files}
        self._verified = None
        self._last = None

    def verify_staged_files(self):
        """Full hashes once; identity/stat recheck later relies on frozen read-only mounts."""
        result = {}
        for role, pin in self._files.items():
            path = Path(pin.path)
            if path.is_symlink():
                raise ContractError("staged files must be materialized regular files")
            before = path.stat()
            if not path.is_file() or before.st_size != pin.bytes:
                raise ContractError("staged file size/type mismatch")
            if self._verified is None:
                h = sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1048576), b""):
                        h.update(block)
                if h.hexdigest() != pin.sha256:
                    raise ContractError("staged artifact hash mismatch")
            after = path.stat()
            identity = {"path": pin.path, "sha256": pin.sha256, "bytes": pin.bytes,
                        "device": after.st_dev, "inode": after.st_ino, "mtime_ns": str(after.st_mtime_ns)}
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ContractError("staged file changed during observation")
            if self._verified is not None and identity != self._verified[role]:
                raise ContractError("previously hashed frozen file identity changed")
            result[role] = identity
        if self._verified is None:
            raw_manifest = Path(self._files["manifest"].path).read_bytes()
            if len(raw_manifest) > 8192:
                raise ContractError("model manifest exceeds inspected bound")
            manifest = json.loads(raw_manifest)
            expected = {"weight": "application/vnd.ollama.image.model",
                        "template": "application/vnd.ollama.image.template",
                        "parameters": "application/vnd.ollama.image.params",
                        "license": "application/vnd.ollama.image.license"}
            layers = manifest.get("layers", [])
            if type(layers) is not list or len(layers) != len(expected):
                raise ContractError("manifest layers differ from exact inspected model")
            for role, media in expected.items():
                found = [x for x in layers if x.get("mediaType") == media]
                pin = self._files[role]
                if len(found) != 1 or (found[0].get("digest"), found[0].get("size")) != ("sha256:" + pin.sha256, pin.bytes):
                    raise ContractError("manifest does not bind staged model layer")
            config = manifest.get("config", {})
            pin = self._files["config"]
            if (config.get("digest"), config.get("size")) != ("sha256:" + pin.sha256, pin.bytes):
                raise ContractError("manifest does not bind staged configuration")
        self._verified = result
        return result

    def _proc(self, pid):
        root = self.proc_root / str(pid)
        parent, start = process_stat((root / "stat").read_text())
        exe = os.readlink(root / "exe")
        executable = (root / "exe").stat()
        raw = (root / "cmdline").read_bytes()
        if len(raw) > 16384:
            raise ContractError("runner argv bound exceeded")
        argv = [x.decode("utf-8") for x in raw.split(b"\0") if x]
        return {"pid": pid, "parent_pid": parent, "start_ticks": start, "exe": exe, "argv": argv,
                "exe_device": executable.st_dev, "exe_inode": executable.st_ino}

    def _server(self):
        server = self._proc(self.spec.ollama_pid)
        if (server["start_ticks"], server["exe"]) != (self.spec.ollama_start_ticks, self._files["ollama"].path):
            raise ContractError("supervised Ollama process changed")
        pinned = self._verified["ollama"]
        if (server["exe_device"], server["exe_inode"]) != (pinned["device"], pinned["inode"]):
            raise ContractError("supervisor executable differs from hashed inode")
        if "serve" not in server["argv"]:
            raise ContractError("supervised process is not the explicit Ollama server")
        server["listener_inode"] = self._listener(server["pid"], 11434)
        return server

    def _listener(self, pid, port):
        root = self.proc_root / str(pid)
        inodes = set()
        for fd in (root / "fd").iterdir():
            try:
                target = os.readlink(fd)
            except FileNotFoundError:
                continue
            match = re.fullmatch(r"socket:\[([0-9]+)\]", target)
            if match:
                inodes.add(match[1])
        raw = (root / "net" / "tcp").read_text()
        if len(raw) > 1048576:
            raise ContractError("socket table exceeds bound")
        found = []
        for line in raw.splitlines()[1:]:
            fields = line.split()
            if len(fields) > 9 and fields[3] == "0A" and fields[9] in inodes:
                host, number = fields[1].split(":")
                if int(number, 16) == port:
                    found.append((host, fields[9]))
        if len(found) != 1 or found[0][0] != "0100007F":
            raise ContractError("endpoint is not owned by the exact loopback process")
        return found[0][1]

    def prepare(self):
        """Before render: hash frozen files and bind the existing server endpoint."""
        return {"files": self.verify_staged_files(), "server": self._server()}

    def capture(self, *, allow_exited=False):
        files = self.verify_staged_files()
        server = self._server()
        root = self.proc_root / str(self.spec.ollama_pid)
        # Go may spawn on a non-leader thread. Inspect only this server's tasks.
        tasks = list((root / "task").iterdir())
        if len(tasks) > 256:
            raise ContractError("supervised task inventory exceeds bound")
        children = set()
        for task in tasks:
            try:
                child_text = (task / "children").read_text()
            except (FileNotFoundError, ProcessLookupError, OSError):
                continue
            if len(child_text) > 4096:
                raise ContractError("supervised child inventory exceeds bound")
            children.update(child_text.split())
        if len(children) > 64:
            raise ContractError("supervised child inventory exceeds bound")
        candidates = []
        for child in sorted(children):
            cpid = int(child)
            try:
                item = self._proc(cpid)
            except FileNotFoundError:
                continue
            except (ProcessLookupError, PermissionError, OSError, ContractError) as exc:
                if allow_exited and self._last is not None and cpid == self._last["pid"] and (
                    not isinstance(exc, ContractError) or str(exc) in {"invalid or exited process identity", "incomplete proc identity"}
                ):
                    continue
                raise
            if item["exe"] == self._files["runner"].path:
                candidates.append(item)
        if not candidates and allow_exited and self._last is not None:
            # Exited-after-response is distinct from a current mapped model.
            return {"server": server, "runner": None, "last_bound_runner": self._last,
                    "lifecycle": "EXITED_AFTER_RESPONSE", "files": files}
        if len(candidates) != 1:
            raise ContractError("one exact supervised runner child is required")
        runner = candidates[0]
        if runner["parent_pid"] != self.spec.ollama_pid:
            raise ContractError("runner parent identity mismatch")
        executable = files["runner"]
        if (runner["exe_device"], runner["exe_inode"]) != (executable["device"], executable["inode"]):
            raise ContractError("runner executable differs from hashed inode")
        argv = runner["argv"]
        model_path = _argument(argv, {"--model", "-m"})
        try:
            port = int(_argument(argv, {"--port"}))
        except ValueError as exc:
            raise ContractError("invalid runner port") from exc
        if not 1024 <= port <= 65535 or port == 11434 or model_path != self._files["weight"].path:
            raise ContractError("runner model or port differs from the supervised route")
        child_root = self.proc_root / str(runner["pid"])
        same_exiting_runner = allow_exited and self._last is not None and (runner["pid"], runner["start_ticks"]) == (self._last["pid"], self._last["start_ticks"])
        try:
            maps = (child_root / "maps").read_text()
            if len(maps) > 4194304:
                raise ContractError("runner maps bound exceeded")
            weight = files["weight"]
            mapped = []
            for line in maps.splitlines():
                fields = line.split(maxsplit=5)
                if len(fields) == 6 and fields[5] == model_path:
                    major, minor = fields[3].split(":")
                    if (int(fields[4]), os.makedev(int(major, 16), int(minor, 16))) != (weight["inode"], weight["device"]):
                        raise ContractError("mapped model inode/device differs from hashed artifact")
                    mapped.append(fields[:5])
            if not mapped:
                raise ContractError("hashed model mapping has not been observed")
            listener = self._listener(runner["pid"], port)
            runner = {**runner, "port": port, "mapped_model": weight, "listener_inode": listener,
                      "mapped_ranges_sha256": content_digest(mapped)}
            # Recheck PID reuse/exit at the end of the multi-file observation.
            end = self._proc(runner["pid"])
            if any(end[k] != runner[k] for k in ("pid", "parent_pid", "start_ticks", "exe", "argv", "exe_device", "exe_inode")):
                raise ContractError("runner changed during observation")
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError, ContractError) as exc:
            if same_exiting_runner and (
                not isinstance(exc, ContractError)
                or str(exc) in {
                    "hashed model mapping has not been observed",
                    "endpoint is not owned by the exact loopback process",
                    "invalid or exited process identity",
                    "incomplete proc identity",
                }
            ):
                self._server()
                return {"server": server, "runner": None, "last_bound_runner": self._last,
                        "lifecycle": "EXITED_AFTER_RESPONSE", "files": files}
            raise
        self._server()
        self._last = runner
        return {"server": server, "runner": runner, "last_bound_runner": None,
                "lifecycle": "MAPPED", "files": files}

    def require_same(self, expected):
        actual = self.capture()
        if actual["server"] != expected["server"] or actual["runner"] != expected["runner"] or actual["files"] != expected["files"]:
            raise ContractError("supervised runtime changed during preflight")
        return actual
