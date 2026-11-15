"""Public synthetic fixtures only. Never an appointment or execution record."""
import json
from pathlib import Path
from cas_forex_operational_contracts import common, protected
from custody_runtime.selection_provider import SelectionProvider, SchemaRoute


def packet():
    return json.loads((Path(__file__).parent/"public-structural-example.json").read_text(encoding="utf-8"))


def stamp(seconds):
    return {"utc":f"2030-01-01T00:{seconds//60:02d}:{seconds%60:02d}.000000Z","boottime_ns":seconds*1_000_000_000}


def completion_selection():
    """Explicit synthetic selection input; never read the unresolved completion as a receipt."""
    fixture=json.loads((Path(__file__).parent/"public-test-only-completion-selection.json").read_text(encoding="utf-8"))
    common.require(type(fixture) is dict and set(fixture)=={"classification","warning","selection"},
                   "TEST_COMPLETION_FIXTURE_ENVELOPE")
    common.require(fixture["classification"]=="SYNTHETIC_TEST_ONLY_SELECTION_NOT_COMPLETION_EVIDENCE",
                   "TEST_COMPLETION_FIXTURE_CLASSIFICATION")
    return fixture["selection"]


def fixture_selection():
    binding=packet()["release_receipt"]["binding"]
    # These constant public bytes are fake signature fixtures, never loaded keys.
    key=b"x"*32; pin=common.digest(key)
    selection={"format":"forex.publisher-root-selection/1","selection_id":"public-only-selection","binding":binding,
        "authorizer_id":"public-authorizer","not_before_utc":stamp(0)["utc"],"expires_at_utc":stamp(180)["utc"],
        "roots":[{"root_id":"public-root","root_instance_id":"public-instance","absolute_directory":"/public-only-fixture",
                  "owner_principal_id":"public-issuer","expected_uid":1000,"expected_gid":1000,"expected_mode":0o750,
                  "expected_device":1,"expected_inode":2,"reader_principal_ids":["public-issuer"],
                  "writer_principal_ids":["public-issuer"],"restore_authority_id":"public-restore",
                  "object_layout":"objects/<lowercase-sha256>","maximum_object_bytes":4194304}],
        "publishers":[{"publisher_id":"public-issuer","role":"RELEASE_ISSUER","signer_public_sha256":pin,
                       "component_manifest_sha256":"1"*64,"not_before_utc":stamp(0)["utc"],"expires_at_utc":stamp(170)["utc"],
                       "grants":[{"root_id":"public-root","record_kind":"RELEASE_RECEIPT","purpose":"custody-release-receipt",
                                   "permitted_use":"PRIVATE_RELEASE","payload_schema_sha256":"2"*64}]}],
        "registry_authority_id":"public-registry","registry_root_id":"public-root","registry_signer_public_sha256":pin,
        "registry_component_sha256":"3"*64}
    class FakeVerifier:
        def verify(self,**kwargs): return None
    raw=common.canonical_bytes(selection)
    authority=SelectionProvider(selected_raw=raw,selected_sha256=common.digest(raw),selection_signature=b"s"*64,
        authorizer_public_key=key,authorizer_public_sha256=pin,verifier=FakeVerifier(),public_keys={pin:key},
        schema_routes={"2"*64:SchemaRoute("2"*64,"protected","ReleaseReceipt3")},clock=lambda:stamp(100),
        current_authority_guard=lambda now:None,original_deadline=stamp(180),local_principal_id="public-issuer")
    reference={"format":"forex.protected-record-ref/1","binding":binding,"publisher_selection_sha256":common.digest(raw),
        "root_id":"public-root","object_id":"4"*64,"bytes":1,"sha256":"4"*64,"record_kind":"RELEASE_RECEIPT",
        "publisher_id":"public-issuer","purpose":"custody-release-receipt"}
    return selection,authority,reference


def journal_row():
    receipt=packet()["release_receipt"]
    raw=protected.validate("ReleaseReceipt3",receipt).raw
    reference={**packet()["release_receipt_ref"],"bytes":len(raw),"sha256":common.digest(raw),"object_id":common.digest(raw)}
    envelope={"body":{"format":"forex.protected-record-attestation/1","record_ref":reference,
        "attestation_id":"public-fake-attestation","publisher_id":receipt["issuer_id"],"purpose":"custody-release-receipt",
        "issued_at_utc":receipt["issued_at_utc"],"expires_at_utc":receipt["expires_at_utc"]},
        "algorithm":"Ed25519","signer_sha256":"5"*64,"signature_hex":"6"*128}
    return {"receipt":receipt,"envelope":envelope}
