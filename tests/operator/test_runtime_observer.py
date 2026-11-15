"""Linux fake-proc negative controls; no processes or inference. NOT_RUN."""
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.operator.runtime_observer import LinuxRuntimeObserver, PinnedFile, SupervisorSpec


@unittest.skipUnless(sys.platform == "linux", "Linux proc fixture requires POSIX identity semantics")
class RuntimeObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        model = self.root / "model"
        model.mkdir()
        files = []
        for role in ("ollama", "runner", "weight", "template", "parameters", "config", "license"):
            path = model / role
            body = ("FAKE TEST BYTES " + role).encode()
            path.write_bytes(body)
            files.append(PinnedFile(role, str(path), len(body), sha256(body).hexdigest()))
        pin = {p.role: p for p in files}
        media = {"weight": "model", "template": "template", "parameters": "params", "license": "license"}
        manifest = {"schemaVersion": 2, "config": {"digest": "sha256:"+pin["config"].sha256, "size": pin["config"].bytes},
            "layers": [{"mediaType": "application/vnd.ollama.image."+kind,
                        "digest": "sha256:"+pin[role].sha256, "size": pin[role].bytes} for role,kind in media.items()]}
        body = json.dumps(manifest).encode()
        (model / "manifest").write_bytes(body)
        files.append(PinnedFile("manifest", str(model / "manifest"), len(body), sha256(body).hexdigest()))
        self.files = tuple(files)
        self.pin = {p.role: p for p in files}
        self.proc = self.root / "proc"
        self.make_process(100, 1, 1000, "ollama", ["ollama", "serve"], 11434, 111)
        self.make_process(101, 100, 2000, "runner", ["runner", "--model", pin["weight"].path, "--port", "20001"], 20001, 222)
        task = self.proc / "100/task/100"
        task.mkdir(parents=True)
        (task / "children").write_text("101")
        stat = Path(pin["weight"].path).stat()
        self.maps_line = f"1000-2000 r--p 00000000 {os.major(stat.st_dev):02x}:{os.minor(stat.st_dev):02x} {stat.st_ino} {pin['weight'].path}\n"
        (self.proc / "101/maps").write_text(self.maps_line)
        self.observer = LinuxRuntimeObserver(SupervisorSpec(100, 1000, self.files), proc_root=self.proc)

    def make_process(self, pid, parent, ticks, role, argv, port, inode):
        root = self.proc / str(pid)
        (root / "fd").mkdir(parents=True)
        (root / "net").mkdir()
        fields = ["S", str(parent)] + ["0"]*17 + [str(ticks)]
        (root / "stat").write_text(f"{pid} (fake process) "+" ".join(fields))
        (root / "exe").symlink_to(self.pin[role].path)
        (root / "cmdline").write_bytes(b"\0".join(x.encode() for x in argv)+b"\0")
        (root / "fd/3").symlink_to(f"socket:[{inode}]")
        (root / "net/tcp").write_text("header\n"+f"0: 0100007F:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 {inode}\n")

    def test_capture_binds_hash_inode_pid_and_owned_listener(self):
        actual = self.observer.capture()
        self.assertEqual(actual["runner"]["mapped_model"]["sha256"], self.pin["weight"].sha256)
        self.assertEqual(actual["runner"]["port"], 20001)
        self.assertEqual(actual["runner"]["listener_inode"], "222")
        self.assertEqual(actual["server"]["listener_inode"], "111")
        self.assertEqual(actual["lifecycle"], "MAPPED")

    def test_model_path_without_matching_mapping_inode_is_rejected(self):
        fields = self.maps_line.split(maxsplit=5)
        fields[4] = "999999999"
        (self.proc / "101/maps").write_text(" ".join(fields))
        with self.assertRaises(ContractError):
            self.observer.capture()

    def test_model_path_only_without_mapping_is_rejected(self):
        (self.proc / "101/maps").write_text("")
        with self.assertRaises(ContractError):
            self.observer.capture()

    def test_server_pid_reuse_is_rejected(self):
        path = self.proc / "100/stat"
        path.write_text(path.read_text().rsplit(" ",1)[0]+" 9999")
        with self.assertRaises(ContractError):
            self.observer.prepare()

    def test_unowned_or_nonloopback_tokenizer_socket_is_rejected(self):
        path = self.proc / "101/net/tcp"
        original = path.read_text()
        for raw in (original.replace("222", "333"), original.replace("0100007F", "00000000")):
            path.write_text(raw)
            with self.assertRaises(ContractError):
                self.observer.capture()

    def test_changed_frozen_file_after_hash_is_rejected(self):
        self.observer.prepare()
        Path(self.pin["template"].path).write_bytes(b"changed template")
        with self.assertRaises(ContractError):
            self.observer.capture()

    def test_incorrect_pin_hash_fails_before_runtime_observation(self):
        changed = tuple(replace(pin, sha256="0"*64) if pin.role == "weight" else pin for pin in self.files)
        observer = LinuxRuntimeObserver(SupervisorSpec(100, 1000, changed), proc_root=self.proc)
        with self.assertRaises(ContractError):
            observer.prepare()

    def test_rehashed_manifest_cannot_reference_an_unpinned_template(self):
        path = Path(self.pin["manifest"].path)
        body = path.read_bytes().replace(self.pin["template"].sha256.encode(), b"0"*64)
        path.write_bytes(body)
        changed = tuple(replace(pin, bytes=len(body), sha256=sha256(body).hexdigest()) if pin.role == "manifest" else pin for pin in self.files)
        observer = LinuxRuntimeObserver(SupervisorSpec(100, 1000, changed), proc_root=self.proc)
        with self.assertRaises(ContractError):
            observer.prepare()

    def test_after_response_exit_cannot_invent_a_current_mapping(self):
        before = self.observer.capture()
        (self.proc / "100/task/100/children").write_text("")
        with self.assertRaises(ContractError):
            self.observer.capture()
        after = self.observer.capture(allow_exited=True)
        self.assertIsNone(after["runner"])
        self.assertEqual(after["last_bound_runner"], before["runner"])
        self.assertEqual(after["lifecycle"], "EXITED_AFTER_RESPONSE")

    def test_child_spawned_by_nonleader_server_thread_is_discovered(self):
        leader = self.proc / "100/task/100/children"
        leader.write_text("")
        task = self.proc / "100/task/105"
        task.mkdir()
        (task / "children").write_text("101")
        self.assertEqual(self.observer.capture()["runner"]["pid"], 101)
