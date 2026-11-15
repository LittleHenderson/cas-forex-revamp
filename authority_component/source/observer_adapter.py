"""Validate independently authenticated measurements, never collect or invent them.

The provider must establish actual post-exec identity and completeness, including
every thread/domain and descendant that can receive model or private inputs.
Wrapper reports, same-UID siblings and synthetic data are never runtime proof.
"""
from .evidence_types import (
    OPERATIONS, ROLES, UNTRUSTED_ROLES, content_digest, digest, identifier,
    integer, need, reference, shape, timestamp, utc_now_value,
)
from .trust_ports import StrictAuthority, UnsupportedAuthority

ROLE_FIELDS = frozenset(("pid", "parent_pid", "start_ticks", "uid", "gid", "boot_id",
    "boot_id_source", "namespaces", "mountinfo_sha256", "exe"))
ACTOR_FIELDS = frozenset(("actor_id", "role", "role_identity", "tid", "thread_start_ticks",
    "exec_sequence", "executable_sha256", "security_domain_sha256", "continuity_receipt"))
RAW_FIELDS = frozenset(("format", "observation_id", "observer_binding_sha256", "run_id", "epoch",
    "source_manifest_sha256", "config_sha256", "boot_id", "actor", "stage", "operation",
    "target", "arguments", "started_at_utc", "completed_at_utc", "clock_receipt",
    "return_value", "errno", "bytes_read", "source_artifacts"))
TARGET_FIELDS = frozenset(("target_sha256", "identity_receipt", "existence_receipt", "exists"))
INVENTORIES = frozenset(("mount_inventory", "descriptor_inventory", "channel_peer_inventory",
    "private_target_inventory", "process_inventory", "sentinel_inventory"))
SELECTION_FIELDS = frozenset(("format", "run_id", "epoch", "observer_binding_sha256", "source_manifest_sha256",
    "config_sha256", "boot_id", "observed_after_utc", "expires_at_utc", "roles", "protected_targets",
    "raw_role_ready", "channel_id", "measurement_bundle"))


class ObserverAdapter:
    """Public entry point. Selected reference/provider come from protected config."""
    def __init__(self, *, resolver, selection_reference, selection_authority_sha256, run_id, epoch, authority=None):
        self.resolver = resolver
        self.selection_reference = dict(reference(selection_reference))
        self.selection_authority = digest(selection_authority_sha256)
        self.run_id, self.epoch = identifier(run_id), integer(epoch, 1)
        self.authority = StrictAuthority(authority if authority is not None else UnsupportedAuthority())

    def assemble_disabled_draft(self, *, now):
        _, selected = self.resolver.read(self.selection_reference)
        shape(selected, SELECTION_FIELDS)
        need(selected["format"] == "forex.independent-observer-selection/1"
             and selected["run_id"] == self.run_id and selected["epoch"] == self.epoch)
        self.authority.authenticate(raw_sha256=self.selection_reference["sha256"], purpose="independent-observer-selection",
            publisher_sha256=self.selection_authority, run_id=self.run_id, epoch=self.epoch)
        self.authority.verify_semantics(purpose="independent-observer-selection", record=selected, dependencies={}, selection=selected)
        _, bundle = self.resolver.read(selected["measurement_bundle"])
        self.authority.authenticate(raw_sha256=selected["measurement_bundle"]["sha256"], purpose="actual-role-measurement-bundle",
            publisher_sha256=selected["observer_binding_sha256"], run_id=self.run_id, epoch=self.epoch)
        observed = assemble_observed_roles(selected=selected, measurement=bundle, resolver=self.resolver,
                                          authority=self.authority, now=now)
        return {"format": "forex.disabled-observer-draft/1", "observed_roles": observed}


def role_identity(value):
    shape(value, ROLE_FIELDS)
    for name in ("pid", "start_ticks"):
        integer(value[name], 1)
    for name in ("parent_pid", "uid", "gid"):
        integer(value[name])
    need(value["boot_id_source"] == "EXTERNAL_OBSERVER_PIN")
    identifier(value["boot_id"])
    shape(value["namespaces"], ("mnt", "pid", "net", "time"))
    for item in value["namespaces"].values():
        need(type(item) is str and 0 < len(item) <= 128)
    digest(value["mountinfo_sha256"])
    need(type(value["exe"]) is str and value["exe"].startswith("/") and "\x00" not in value["exe"])


def actor_identity(value):
    shape(value, ACTOR_FIELDS)
    identifier(value["actor_id"])
    need(value["role"] in UNTRUSTED_ROLES)
    role_identity(value["role_identity"])
    for name in ("tid", "thread_start_ticks", "exec_sequence"):
        integer(value[name], 1)
    for name in ("executable_sha256", "security_domain_sha256"):
        digest(value[name])
    reference(value["continuity_receipt"])


def operation_arguments(operation, value):
    if operation == "UNAUTHORIZED_CHANNEL_PEER":
        shape(value, ("syscall", "socket_type", "endpoint_identity_sha256", "peer_identity_sha256", "request_sha256"))
        need(value["syscall"] in ("connect", "sendmsg", "recvmsg"))
        need(value["socket_type"] in ("AF_UNIX_STREAM", "AF_UNIX_SEQPACKET"))
        for name in ("endpoint_identity_sha256", "peer_identity_sha256", "request_sha256"):
            digest(value[name])
    else:
        shape(value, ("syscall", "flags", "dirfd_identity_sha256", "path_identity_sha256"))
        need(value["syscall"] in ("open", "openat", "openat2"))
        integer(value["flags"])
        # O_RDONLY access mode, no create/truncate/append/path-only shortcut.
        need(value["flags"] & (3 | 0x40 | 0x200 | 0x400 | 0x200000) == 0)
        for name in ("dirfd_identity_sha256", "path_identity_sha256"):
            digest(value[name])


def validate_observation(raw, *, expected, selected, resolver, authority, now):
    authority = StrictAuthority(authority)
    shape(raw, RAW_FIELDS)
    need(raw["format"] == "forex.actual-role-operation/1" and raw["stage"] == "POST_EXEC_ACTUAL_ROLE", "ISOLATION_GATE")
    for name in ("run_id", "epoch", "source_manifest_sha256", "config_sha256", "boot_id"):
        need(raw[name] == selected[name], "ISOLATION_GATE")
    need(raw["observer_binding_sha256"] == selected["observer_binding_sha256"], "ISOLATION_GATE")
    identifier(raw["observation_id"])
    actor_identity(raw["actor"])
    need(raw["actor"] == expected["actor"] and raw["operation"] == expected["operation"], "ISOLATION_GATE")
    need(raw["operation"] in OPERATIONS)
    shape(raw["target"], TARGET_FIELDS)
    need(raw["target"]["target_sha256"] == expected["target_sha256"]
         and raw["target"]["exists"] is True, "ISOLATION_GATE")
    digest(raw["target"]["target_sha256"])
    operation_arguments(raw["operation"], raw["arguments"])
    need(raw["arguments"] == expected["arguments"], "ISOLATION_GATE")
    start, end = timestamp(raw["started_at_utc"]), timestamp(raw["completed_at_utc"])
    need(timestamp(selected["observed_after_utc"]) <= start <= end <= utc_now_value(now)
         < timestamp(selected["expires_at_utc"]), "ISOLATION_GATE")
    integer(raw["errno"], 0, 4095)
    integer(raw["return_value"], -1)
    need(raw["bytes_read"] == 0 and type(raw["bytes_read"]) is int, "ISOLATION_GATE")
    if expected["expected"] == "DENY":
        need(raw["return_value"] == -1 and raw["errno"] in (1, 13), "ISOLATION_GATE")
    else:
        need(expected["expected"] == "ALLOW" and raw["operation"] == "OPEN_READ_WITHOUT_READING"
             and raw["return_value"] >= 0 and raw["errno"] == 0, "ISOLATION_GATE")
    need(type(raw["source_artifacts"]) is list and 0 < len(raw["source_artifacts"]) <= 64)
    references = [raw["clock_receipt"], raw["actor"]["continuity_receipt"],
                  raw["target"]["identity_receipt"], raw["target"]["existence_receipt"], *raw["source_artifacts"]]
    sources = {}
    for row in references:
        reference(row)
        sources[row["sha256"]] = resolver.read(row)[1]
    # Must decode authentic collector source events and bind syscall entry/exit,
    # exec/process/thread/domain continuity and clocks. A digest is insufficient.
    authority.verify_observation(raw_record=raw, source_artifacts=sources, selection=selected)
    return raw


def assemble_observed_roles(*, selected, measurement, resolver, authority, now):
    """Pure returned draft; no persistence/publication. All external ports required.

    selected is an independently authenticated runtime selection, never app data.
    measurement contains only pinned references and the full independent matrix.
    """
    authority = StrictAuthority(authority)
    shape(measurement, ("format", "inventories", "actors", "matrix", "observations"))
    need(measurement["format"] == "forex.actual-role-measurement-bundle/1")
    shape(measurement["inventories"], INVENTORIES)
    shape(selected["roles"], ROLES)
    for role in selected["roles"].values():
        role_identity(role)
        need(role["boot_id"] == selected["boot_id"])
    actors = measurement["actors"]
    need(type(actors) is list and 2 <= len(actors) <= 128)
    for actor in actors:
        actor_identity(actor)
    need(len({a["actor_id"] for a in actors}) == len(actors))
    inventories = {}
    for kind, ref in measurement["inventories"].items():
        raw, record = resolver.read(ref)
        authority.authenticate(raw_sha256=ref["sha256"], purpose=kind,
            publisher_sha256=selected["observer_binding_sha256"], run_id=selected["run_id"], epoch=selected["epoch"])
        authority.verify_inventory(kind=kind, record=record,
            selection={**selected, "actors": actors, "matrix": measurement["matrix"]})
        inventories[kind] = record
    # Full actors/matrix membership comes from independently measured process,
    # thread, target, descriptor and peer inventories. Caller subsets are invalid.
    need(inventories["process_inventory"]["actors"] == actors, "ISOLATION_GATE")
    need(inventories["process_inventory"]["required_probe_matrix"] == measurement["matrix"], "ISOLATION_GATE")
    need(inventories["descriptor_inventory"]["process_inventory"] == measurement["inventories"]["process_inventory"]
         and inventories["descriptor_inventory"]["sentinel_inventory"] == measurement["inventories"]["sentinel_inventory"]
         and inventories["descriptor_inventory"]["operation_receipts"] == measurement["observations"], "ISOLATION_GATE")
    targets = selected["protected_targets"]
    protected = {content_digest({"path": r["path"], "sha256": r["sha256"]}) for r in targets}
    need(len(protected) == len(targets) and 5 <= len(targets) <= 32)
    for row in targets:
        reference(row)  # metadata only; never read sealed target contents here
    actual_targets = inventories["private_target_inventory"]["targets"]
    need({r["path"] for r in actual_targets if r["exists"] is True} >= {r["path"] for r in targets})
    matrix = measurement["matrix"]
    observations = measurement["observations"]
    need(type(matrix) is list and type(observations) is list and len(matrix) == len(observations)
         and 0 < len(matrix) <= 8192)
    expected_map = {}
    for item in matrix:
        shape(item, ("observation_id", "actor", "operation", "target_sha256", "arguments", "expected"))
        identifier(item["observation_id"])
        need(item["observation_id"] not in expected_map and item["actor"] in actors)
        need(item["operation"] in OPERATIONS and item["expected"] in ("ALLOW", "DENY"))
        digest(item["target_sha256"])
        operation_arguments(item["operation"], item["arguments"])
        need(item["target_sha256"] not in protected or item["expected"] == "DENY", "ISOLATION_GATE")
        expected_map[item["observation_id"]] = item
    rows, seen = [], set()
    for ref in observations:
        raw, record = resolver.read(ref)
        authority.authenticate(raw_sha256=ref["sha256"], purpose="actual-role-operation",
            publisher_sha256=selected["observer_binding_sha256"], run_id=selected["run_id"], epoch=selected["epoch"])
        observation_id = record.get("observation_id")
        need(observation_id in expected_map and observation_id not in seen, "ISOLATION_GATE")
        seen.add(observation_id)
        expected = expected_map[observation_id]
        validate_observation(record, expected=expected, selected=selected, resolver=resolver, authority=authority, now=now)
        actor = record["actor"]
        row = {"role": actor["role"], "operation": record["operation"],
            "target_sha256": record["target"]["target_sha256"], "expected": expected["expected"],
            "actual": "DENY" if record["return_value"] == -1 else "ALLOW", "errno": record["errno"],
            "target_exists": True, "pid": actor["role_identity"]["pid"],
            "start_ticks": actor["role_identity"]["start_ticks"], "raw_receipt": ref}
        rows.append((actor["actor_id"], row))
    need(seen == set(expected_map), "ISOLATION_GATE")
    for actor in actors:
        own = [row for aid, row in rows if aid == actor["actor_id"]]
        need({r["operation"] for r in own if r["actual"] == "DENY"} == OPERATIONS, "ISOLATION_GATE")
        need(protected <= {r["target_sha256"] for r in own if r["operation"] == "OPEN_READ_WITHOUT_READING"
                          and r["actual"] == "DENY"}, "ISOLATION_GATE")
        need(any(r["operation"] == "OPEN_READ_WITHOUT_READING" and r["actual"] == "ALLOW"
                 and r["target_sha256"] not in protected for r in own), "ISOLATION_GATE")
    main = []
    for role in UNTRUSTED_ROLES:
        matches = [a for a in actors if a["role"] == role and a["role_identity"] == selected["roles"][role]]
        need(matches, "ISOLATION_GATE")
        main.extend(r for aid, r in rows if aid in {a["actor_id"] for a in matches})
    # B08 only accepts main-role PID rows; descendants stay bound in independently
    # authenticated process/descriptor inventories, never relabelled as the parent.
    return {"format": "forex.observed-role-read-isolation/1",
        "observer_binding_sha256": selected["observer_binding_sha256"], "run_id": selected["run_id"],
        "roles": selected["roles"], "source_manifest_sha256": selected["source_manifest_sha256"],
        "config_sha256": selected["config_sha256"], "role_setup_sha256": content_digest(selected["raw_role_ready"]),
        "channel_id": selected["channel_id"], "boot_id": selected["boot_id"],
        "observed_at_utc": utc_now_value(now).isoformat().replace("+00:00", "Z"),
        "expires_at_utc": selected["expires_at_utc"], "actual_private_target_sha256": sorted(protected),
        "access_probes": main, "sentinel_inventory_verified": True,
        "descriptor_inventory_verified": True, "mount_inventory_verified": True,
        **{k: measurement["inventories"][k] for k in ("mount_inventory", "descriptor_inventory",
                                                   "channel_peer_inventory", "private_target_inventory")}}
