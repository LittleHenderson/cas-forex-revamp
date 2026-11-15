"""No-follow protected resolution and immutable, signed V2 registration.

Constructors only retain dependencies. Explicit initialize_registry is for a later
authorized caller and is never called by this package. No directory/principal/key
creation, restore, deletion, automatic retry or fallback store exists. Newly
created object descriptors are explicitly sealed to the existing 0440 mode;
existing paths and metadata are never repaired.
"""
import contextlib
import os
import stat
from cas_forex_operational_contracts import common, method, protected, validation
from .selection_provider import require, same


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))


def _seal_created_object(descriptor, root):
    """Establish the existing 0440 contract independent of process umask."""
    before = os.fstat(descriptor)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == root["expected_uid"] and before.st_gid == root["expected_gid"],
            "NEW_OBJECT_OWNERSHIP")
    # This sets no SUID/SGID bits and is allowed in the existing restricted role.
    os.fchmod(descriptor, 0o440)
    after = os.fstat(descriptor)
    require(_identity(after) == (before.st_dev, before.st_ino, root["expected_uid"],
            root["expected_gid"], 0o440) and stat.S_ISREG(after.st_mode) and after.st_nlink == 1,
            "OBJECT_PUBLICATION_MODE")


class ProtectedFiles:
    def __init__(self, authority): self.authority = authority

    @contextlib.contextmanager
    def root(self, selected_root, selection, now):
        now = self.authority.current(selection, now)
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise common.DependencyUnavailable("linux-protected-root")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        rootfd = os.open("/", flags)
        try:
            common.safe_path(selected_root["absolute_directory"], absolute=True)
            for segment in selected_root["absolute_directory"].split("/")[1:]:
                child = os.open(segment, flags, dir_fd=rootfd)
                os.close(rootfd); rootfd = child
            expected = (selected_root["expected_device"], selected_root["expected_inode"], selected_root["expected_uid"],
                        selected_root["expected_gid"], selected_root["expected_mode"])
            require(_identity(os.fstat(rootfd)) == expected, "ROOT_IDENTITY")
            yield rootfd
            require(_identity(os.fstat(rootfd)) == expected, "ROOT_CHANGED")
            currentfd = os.open("/", flags)
            try:
                for segment in selected_root["absolute_directory"].split("/")[1:]:
                    child = os.open(segment, flags, dir_fd=currentfd)
                    os.close(currentfd); currentfd = child
                require(_identity(os.fstat(currentfd)) == expected, "ROOT_PATH_REPLACED")
            finally: os.close(currentfd)
            self.authority.current(selection, now)
        finally:
            os.close(rootfd)

    @contextlib.contextmanager
    def objects(self, root, selection, now):
        with self.root(root, selection, now) as rootfd:
            descriptor = os.open("objects", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=rootfd)
            try:
                info = os.fstat(descriptor)
                require(info.st_uid == root["expected_uid"] and info.st_gid == root["expected_gid"]
                        and not stat.S_IMODE(info.st_mode) & 0o022 and info.st_dev == root["expected_device"], "OBJECT_DIRECTORY")
                yield descriptor
                require(_identity(os.fstat(descriptor)) == _identity(info), "OBJECT_DIRECTORY_CHANGED")
                current = os.open("objects", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=rootfd)
                try: require(_identity(os.fstat(current)) == _identity(info), "OBJECT_DIRECTORY_REPLACED")
                finally: os.close(current)
            finally: os.close(descriptor)

    def read(self, reference, root, selection, now):
        require(self.authority.local_principal_id in root["reader_principal_ids"], "ROOT_READER_GRANT")
        protected.validate("ProtectedRecordRef", reference)
        with self.objects(root, selection, now) as directory:
            descriptor = os.open(reference["sha256"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            try:
                before = os.fstat(descriptor)
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == root["expected_uid"]
                        and before.st_gid == root["expected_gid"] and not stat.S_IMODE(before.st_mode) & 0o222
                        and before.st_size == reference["bytes"], "OBJECT_METADATA")
                chunks, remaining = [], reference["bytes"] + 1
                while remaining:
                    block = os.read(descriptor, min(remaining, 65536))
                    if not block: break
                    chunks.append(block); remaining -= len(block)
                raw = b"".join(chunks)
                after = os.fstat(descriptor)
                require(_identity(before) == _identity(after) and before.st_size == after.st_size
                        and before.st_mtime_ns == after.st_mtime_ns and before.st_ctime_ns == after.st_ctime_ns, "OBJECT_CHANGED")
                named = os.stat(reference["sha256"], dir_fd=directory, follow_symlinks=False)
                require(_identity(named) == _identity(after) and stat.S_ISREG(named.st_mode), "OBJECT_PATH_REPLACED")
                validation.verify_reference_bytes(reference, raw, protected_reference=True)
            finally: os.close(descriptor)
        self.authority.current(selection, now)
        return raw

    def retain_exact(self, reference, raw, root, selection, now):
        require(self.authority.local_principal_id in root["writer_principal_ids"], "ROOT_WRITER_GRANT")
        validation.verify_reference_bytes(reference, raw, protected_reference=True)
        with self.objects(root, selection, now) as directory:
            try:
                descriptor = os.open(reference["sha256"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o600, dir_fd=directory)
            except FileExistsError:
                # Preserve existing bytes/modes. An incomplete or wrong-mode
                # predecessor cannot be silently repaired into published truth.
                info = os.stat(reference["sha256"], dir_fd=directory, follow_symlinks=False)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and info.st_uid == root["expected_uid"] and info.st_gid == root["expected_gid"]
                        and stat.S_IMODE(info.st_mode) == 0o440, "EXISTING_OBJECT_PUBLICATION_MODE")
                require(self.read(reference, root, selection, now) == raw, "IMMUTABLE_OBJECT_CONFLICT")
                return
            try:
                offset = 0
                while offset < len(raw):
                    count = os.write(descriptor, raw[offset:])
                    require(count > 0, "OBJECT_WRITE_UNCERTAIN"); offset += count
                _seal_created_object(descriptor, root)
                os.fsync(descriptor)
            finally: os.close(descriptor)
            os.fsync(directory)
        require(self.read(reference, root, selection, now) == raw, "OBJECT_READBACK")


class ProtectedRegistry:
    def __init__(self, *, authority, files=None):
        self.authority = authority
        self.files = files if files is not None else ProtectedFiles(authority)

    def _registry_root(self, selection):
        roots = [r for r in selection["roots"] if r["root_id"] == selection["registry_root_id"]]
        require(len(roots) == 1 and selection["registry_authority_id"] in roots[0]["writer_principal_ids"], "REGISTRY_ROOT")
        require(self.authority.local_principal_id == selection["registry_authority_id"], "REGISTRY_PRINCIPAL")
        return roots[0]

    def initialize_registry(self, *, selection, now):
        """Future explicit exclusive initialization only; never auto-called."""
        with self.files.root(self._registry_root(selection), selection, now) as directory:
            descriptor = os.open("registry.v2.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=directory)
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
            os.fsync(directory)

    @contextlib.contextmanager
    def _locked(self, selection, now):
        import fcntl
        root = self._registry_root(selection)
        with self.files.root(root, selection, now) as directory:
            descriptor = os.open("registry.v2.log", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            try:
                info = os.fstat(descriptor)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == root["expected_uid"]
                        and info.st_gid == root["expected_gid"] and stat.S_IMODE(info.st_mode) == 0o600, "REGISTRY_METADATA")
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield descriptor
                named=os.stat("registry.v2.log",dir_fd=directory,follow_symlinks=False)
                require(_identity(named)==_identity(os.fstat(descriptor)) and named.st_nlink==1
                        and stat.S_ISREG(named.st_mode),"REGISTRY_PATH_REPLACED")
                self.authority.current(selection, now)
            finally: os.close(descriptor)

    def _entries(self, descriptor, selection, now):
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks, count = [], 0
        while True:
            block = os.read(descriptor, 65536)
            if not block: break
            count += len(block); require(count <= common.MAX_GRAPH, "REGISTRY_BOUND")
            chunks.append(block)
        raw = b"".join(chunks)
        require(not raw or raw.endswith(b"\n"), "UNCERTAIN_REGISTRY_TAIL")
        previous, entries, seen = common.ZERO_SHA256, [], set()
        for line in raw.splitlines():
            envelope = protected.decode("RegistrySignature", line).payload()
            body = envelope["registration"]
            require(envelope["signer_sha256"] == selection["registry_signer_public_sha256"], "REGISTRY_SIGNER")
            self.authority.signature_check(signer_pin=envelope["signer_sha256"], message=protected.registration_signing_bytes(body), signature=bytes.fromhex(envelope["signature_hex"]))
            require(same(body["binding"], selection["binding"]) and body["publisher_selection_sha256"] == self.authority.pin
                    and body["registry_authority_id"] == selection["registry_authority_id"]
                    and body["sequence"] == len(entries)+1 and body["previous_entry_sha256"] == previous, "REGISTRY_CHAIN")
            record_id = common.digest(common.canonical_bytes(body["record_ref"]))
            require(record_id not in seen, "REGISTRY_DUPLICATE"); seen.add(record_id)
            entries.append(body); previous = common.digest(common.canonical_bytes(body))
            self.authority.current(selection, now)
        return entries

    def register_exact_record(self, raw, reference, publisher_envelope, *, selection, now):
        reference = protected.validate("ProtectedRecordRef", reference).payload()
        root, _, grant, now = self.authority.check_grant(reference, selection, now)
        validation.verify_reference_bytes(reference, raw, protected_reference=True)
        self.authority.validate_payload(raw, grant)
        self.authority.attest(reference, publisher_envelope, selection, now)
        envelope_raw = protected.validate("ProtectedRecordEnvelope", publisher_envelope).raw
        attestation_ref = {**reference, "object_id": common.digest(envelope_raw), "sha256": common.digest(envelope_raw),
                           "bytes": len(envelope_raw), "record_kind": "RECORD_ATTESTATION", "purpose": "record-attestation"}
        attestation_root, _, _, now = self.authority.check_grant(attestation_ref, selection, now, required_use="AUTHORITY_METADATA")
        # Publisher retains its own immutable bytes; registry never writes into
        # another publisher's root or creates an attestation on its behalf.
        require(self.files.read(reference, root, selection, now) == raw, "PUBLISHED_RECORD_READBACK")
        require(self.files.read(attestation_ref, attestation_root, selection, now) == envelope_raw, "PUBLISHED_ATTESTATION_READBACK")
        with self._locked(selection, now) as descriptor:
            entries = self._entries(descriptor, selection, now)
            existing = [entry for entry in entries if same(entry["record_ref"], reference)]
            if existing:
                require(same(existing[0]["attestation_ref"], attestation_ref), "ORIGINAL_ATTESTATION_REPLACED")
                self.authority.attest(reference, publisher_envelope, selection, now)
                return existing[0]
            current = self.authority.current(selection, now)
            body = {"format": "forex.protected-record-registration/2", "binding": selection["binding"],
                "publisher_selection_sha256": self.authority.pin, "registry_authority_id": selection["registry_authority_id"],
                "sequence": len(entries)+1, "previous_entry_sha256": common.digest(common.canonical_bytes(entries[-1])) if entries else common.ZERO_SHA256,
                "record_ref": reference, "attestation_ref": attestation_ref, "registered_at_utc": current["utc"]}
            signed = self.authority.sign_registration(body, selection, current)
            line = protected.validate("RegistrySignature", signed).raw+b"\n"
            os.lseek(descriptor, 0, os.SEEK_END)
            require(os.write(descriptor, line) == len(line), "REGISTRY_WRITE_UNCERTAIN")
            os.fsync(descriptor)
            require(same(self._entries(descriptor, selection, current)[-1], body), "REGISTRY_READBACK")
            self.authority.attest(reference, publisher_envelope, selection, current)
            return body

    def read_registration(self, registration_sha256, *, selection, now):
        self.authority.current(selection, now)
        with self._locked(selection, now) as descriptor:
            rows = self._entries(descriptor, selection, now)
            matches = [row for row in rows if common.digest(common.canonical_bytes(row)) == registration_sha256]
            require(len(matches) == 1, "REGISTRATION_UNAVAILABLE")
            return matches[0]


class ProtectedResolver:
    def __init__(self, *, authority, registry, files=None):
        self.authority, self.registry = authority, registry
        self.files = files if files is not None else ProtectedFiles(authority)

    def resolve(self, use, *, selection, now):
        use = protected.validate("ProtectedReferenceUse", use).payload()
        reference = use["reference"]
        root, _, grant, now = self.authority.check_grant(reference, selection, now, required_use=use["required_use"])
        registration = self.registry.read_registration(use["registration_sha256"], selection=selection, now=now)
        require(same(registration["record_ref"], reference), "REGISTERED_REFERENCE_SUBSTITUTION")
        attestation_ref = registration["attestation_ref"]
        require(attestation_ref["publisher_id"] == reference["publisher_id"] and attestation_ref["record_kind"] == "RECORD_ATTESTATION"
                and attestation_ref["purpose"] == "record-attestation", "ATTESTATION_REFERENCE")
        attestation_root, _, _, now = self.authority.check_grant(attestation_ref, selection, now, required_use="AUTHORITY_METADATA")
        envelope = protected.decode("ProtectedRecordEnvelope", self.files.read(attestation_ref, attestation_root, selection, now)).payload()
        self.authority.attest(reference, envelope, selection, now)
        raw = self.files.read(reference, root, selection, now)
        self.authority.validate_payload(raw, grant)
        # Fresh selection/grant/attestation validation after every final read.
        self.authority.check_grant(reference, selection, now, required_use=use["required_use"])
        self.authority.attest(reference, envelope, selection, now)
        return raw
