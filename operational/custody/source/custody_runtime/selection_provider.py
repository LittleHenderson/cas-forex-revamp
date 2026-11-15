"""Externally pinned publisher selection, fresh authority and schema checks.

No file, clock, signature or key access on construction. Callers must supply the
reviewed authority implementation and current original clock; no positive default.
"""
from dataclasses import dataclass
from cas_forex_operational_contracts import common, protected, method, validation

# Exact accepted candidate03 publisher-purpose matrix; checked against its pin.
PUBLISHER_ROUTES = {'AGGREGATE_BODY': {'public-aggregate-body': 'CUSTODY'},
 'BUNDLE_FINALIZATION': {'retained-bundle-finalization': 'CUSTODY'},
 'COLLECTION_INVENTORY': {'test-collection-inventory': 'INDEPENDENT_REVIEWER'},
 'COMMAND_PIN': {'test-command-pin': 'INDEPENDENT_REVIEWER'},
 'COMPLETION_SELECTION': {'completion-selection': 'INDEPENDENT_REVIEWER'},
 'EXTERNAL_CUSTODY_AUTHORITY': {'external-custody-authority': 'RELEASE_ISSUER'},
 'EXTERNAL_RELEASE_EVIDENCE': {'release-evidence:accepted_private_mapping_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:approved_topology_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:authorized_current_frame_channel_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:complete_freeze_manifest_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:controller_identity_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:custody_manifest_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:execution_identity_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:independent_review_attestation_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:inherited_exposure_heads_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:issuer_authentication_evidence_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:issuer_binding_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:original_clock_and_budget_binding_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:role_read_isolation_receipt_sha256': 'CONTROLLER',
                               'release-evidence:scope_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:separate_execution_authorization_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:stop_egress_deadline_proofs_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER',
                               'release-evidence:trusted_observer_binding_sha256': 'EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER'},
 'PARSER_PIN': {'test-parser-pin': 'INDEPENDENT_REVIEWER'},
 'PROTECTED_REGISTRATION': {'protected-record-registration': 'REGISTRY_CUSTODIAN'},
 'PROVIDER_SELECTION': {'independent-aggregate-selection': 'EXTERNAL_AUTHORIZER',
                        'independent-observer-selection': 'EXTERNAL_AUTHORIZER',
                        'independent-runtime-selection': 'EXTERNAL_AUTHORIZER'},
 'PUBLIC_AGGREGATE_BINDINGS': {'approved-public-aggregate-bindings': 'INDEPENDENT_REVIEWER'},
 'RECORD_ATTESTATION': {'record-attestation': 'SAME_PUBLISHER_AS_ATTESTED_RECORD'},
 'REDACTION_APPROVAL': {'independent-aggregate-redaction': 'INDEPENDENT_REDACTOR'},
 'RELEASE_CONSUMPTION': {'release-consumption': 'CONTROLLER'},
 'RELEASE_RECEIPT': {'custody-release-receipt': 'RELEASE_ISSUER'},
 'RELEASE_SELECTION': {'custody-release-selection': 'RELEASE_ISSUER'},
 'RETAINED_ATTEMPT_BUNDLE': {'complete-retained-evaluation-bundle': 'CUSTODY'},
 'RETAINED_FACT': {'retained-attempt': 'TRANSPORT_OBSERVER',
                   'retained-authorization': 'CORE_OBSERVER',
                   'retained-context': 'CUSTODY',
                   'retained-dispatch': 'CORE_OBSERVER',
                   'retained-outcome': 'TRANSPORT_OBSERVER',
                   'retained-post_state': 'VENUE_OBSERVER',
                   'retained-pre_state': 'VENUE_OBSERVER',
                   'retained-venue_effect': 'VENUE_OBSERVER'},
 'ROOT_OBSERVATION': {'protected-root-observation': 'EXTERNAL_AUTHORIZER'},
 'SCORING_PLAN': {'independent-scoring-plan': 'PRIVATE_MAPPER'},
 'SCORING_PLAN_REVIEW': {'scoring-plan-review': 'INDEPENDENT_REVIEWER'},
 'SOURCE_INVENTORY': {'completion-source-inventory': 'INDEPENDENT_REVIEWER'},
 'SOURCE_TEST_COMPLETION': {'source-test-completion': 'COMPLETION_OBSERVER'},
 'SOURCE_TEST_OBSERVATION': {'source-test-observation': 'COMPLETION_OBSERVER'},
 'SOURCE_TEST_REPORT': {'original-source-test-report': 'CUSTODY'},
 'TERMINAL_SCORE': {'independent-terminal-score': 'INDEPENDENT_SCORER'},
 'TEST_DISCOVERY_REPORT': {'test-discovery-report': 'COMPLETION_OBSERVER'},
 'TEST_FRAMEWORK_REPORT': {'test-framework-report': 'COMPLETION_OBSERVER'},
 'TEST_GROUP_REPORT': {'test-group-report': 'COMPLETION_OBSERVER'},
 'TEST_PROCESS_CAPTURE': {'test-process-capture': 'COMPLETION_OBSERVER'},
 'TEST_STREAM': {'test-stream': 'COMPLETION_OBSERVER'}}


def same(a, b):
    return common.canonical_bytes(a, limit=common.MAX_GRAPH) == common.canonical_bytes(b, limit=common.MAX_GRAPH)


def require(value, code):
    common.require(value, code)


def call_none(function, *args, **kwargs):
    if function is None: raise common.DependencyUnavailable()
    try:
        result = function(*args, **kwargs)
    except common.ContractError:
        raise
    except Exception:
        raise common.DependencyUnavailable() from None
    require(result is None, "PROVIDER_PROTOCOL")


def fresh(clock, guard, supplied, deadline):
    """Actual paired clock and externally selected authority guard, both required."""
    if clock is None or guard is None: raise common.DependencyUnavailable()
    now = method.validate("Stamp", clock()).payload()
    prior = method.validate("Stamp", supplied).payload()
    end = method.validate("Stamp", deadline).payload()
    require(common.utc(prior["utc"]) <= common.utc(now["utc"]) < common.utc(end["utc"])
            and prior["boottime_ns"] <= now["boottime_ns"] < end["boottime_ns"], "ORIGINAL_CLOCK_BOUND")
    call_none(guard, now)
    after = method.validate("Stamp", clock()).payload()
    require(common.utc(now["utc"]) <= common.utc(after["utc"]) < common.utc(end["utc"])
            and now["boottime_ns"] <= after["boottime_ns"] < end["boottime_ns"], "ORIGINAL_CLOCK_BOUND")
    return after


@dataclass(frozen=True)
class SchemaRoute:
    """Externally selected schema bytes and validator; never picked by payload."""
    schema_sha256: str
    namespace: str
    type_name: str
    shape_validator: common.SelectedShapeValidator | None = None
    limits: common.ValidationLimits | None = None

    def decode(self, raw):
        return validation.decode_record(self.namespace, self.type_name, raw,
            shape_validator=self.shape_validator, limits=self.limits).payload()


class SelectionProvider:
    def __init__(self, *, selected_raw, selected_sha256, selection_signature,
                 authorizer_public_key, authorizer_public_sha256, verifier,
                 public_keys, schema_routes, clock, current_authority_guard, original_deadline,
                 local_principal_id, registry_signer=None):
        self.raw = bytes(selected_raw)
        self.pin = selected_sha256
        self.signature = bytes(selection_signature)
        self.authorizer_key = bytes(authorizer_public_key)
        self.authorizer_pin = authorizer_public_sha256
        self.verifier = verifier
        self.keys = {k: bytes(v) for k, v in public_keys.items()}
        self.schemas = dict(schema_routes)
        self.clock, self.authority_guard = clock, current_authority_guard
        self.deadline = common.decode_canonical(common.canonical_bytes(original_deadline))
        self.registry_signer = registry_signer
        self.local_principal_id = local_principal_id

    def current(self, selection, now):
        now = fresh(self.clock, self.authority_guard, now, self.deadline)
        require(common.digest(self.raw) == self.pin, "SELECTION_PIN")
        selected = protected.decode("PublisherRootSelection", self.raw).payload()
        require(same(selected, selection), "SELECTION_SUBSTITUTION")
        require(common.digest(self.authorizer_key) == self.authorizer_pin and len(self.authorizer_key) == 32,
                "AUTHORIZER_KEY_PIN")
        require(len(self.signature) == 64, "SELECTION_SIGNATURE_SHAPE")
        call_none(self.verifier.verify, public_key=self.authorizer_key,
            message=protected.selection_signing_bytes(selected), signature=self.signature)
        now = fresh(self.clock, self.authority_guard, now, self.deadline)
        require(common.utc(selected["not_before_utc"]) <= common.utc(now["utc"]) < common.utc(selected["expires_at_utc"]), "SELECTION_EXPIRED")
        return now

    def check_grant(self, reference, selection, now, *, required_use=None):
        now = self.current(selection, now)
        ref = protected.validate("ProtectedRecordRef", reference).payload()
        require(ref["publisher_selection_sha256"] == self.pin and same(ref["binding"], selection["binding"]), "REFERENCE_BINDING")
        roots = [r for r in selection["roots"] if r["root_id"] == ref["root_id"]]
        publishers = [p for p in selection["publishers"] if p["publisher_id"] == ref["publisher_id"]]
        require(len(roots) == len(publishers) == 1, "UNSELECTED_ROOT_OR_PUBLISHER")
        require(ref["bytes"] <= roots[0]["maximum_object_bytes"], "SELECTED_ROOT_OBJECT_BOUND")
        publisher = publishers[0]
        require(common.utc(publisher["not_before_utc"]) <= common.utc(now["utc"]) < common.utc(publisher["expires_at_utc"]), "PUBLISHER_EXPIRED")
        grants = [g for g in publisher["grants"] if g["root_id"] == ref["root_id"] and g["record_kind"] == ref["record_kind"]
                  and g["purpose"] == ref["purpose"] and (required_use is None or g["permitted_use"] == required_use)]
        require(bool(grants) and len({g["payload_schema_sha256"] for g in grants}) == 1
                and (required_use is None or len(grants) == 1), "EXACT_GRANT_REQUIRED")
        grant = grants[0]
        private = ref["record_kind"] in ("RETAINED_FACT", "SCORING_PLAN", "SCORING_PLAN_REVIEW", "RETAINED_ATTEMPT_BUNDLE", "BUNDLE_FINALIZATION", "TERMINAL_SCORE")
        require(not private or all(g["permitted_use"] not in ("PRIVATE_RELEASE", "FINAL_AGGREGATE") for g in grants), "PRIVATE_GRANT_EXPANSION")
        route = PUBLISHER_ROUTES.get(ref["record_kind"], {}).get(ref["purpose"])
        if route not in ("SAME_PUBLISHER_AS_ATTESTED_RECORD", "EXACT_EXTERNALLY_SELECTED_SLOT_PUBLISHER"):
            require(route == publisher["role"], "PUBLISHER_ROLE")
        return roots[0], publisher, grant, now

    def validate_payload(self, raw, grant):
        route = self.schemas.get(grant["payload_schema_sha256"])
        if route is None: raise common.DependencyUnavailable("selected-schema")
        require(route.schema_sha256 == grant["payload_schema_sha256"], "SCHEMA_PIN")
        return route.decode(raw)

    def signature_check(self, *, signer_pin, message, signature):
        key = self.keys.get(signer_pin)
        if key is None: raise common.DependencyUnavailable("selected-public-verifier")
        require(len(key) == 32 and common.digest(key) == signer_pin, "SIGNER_PIN")
        call_none(self.verifier.verify, public_key=key, message=message, signature=signature)

    def attest(self, reference, envelope, selection, now):
        _, publisher, _, now = self.check_grant(reference, selection, now)
        envelope = protected.validate("ProtectedRecordEnvelope", envelope).payload()
        body = envelope["body"]
        require(same(body["record_ref"], reference) and body["publisher_id"] == reference["publisher_id"]
                and body["purpose"] == reference["purpose"] and envelope["signer_sha256"] == publisher["signer_public_sha256"], "ATTESTATION_BINDING")
        self.signature_check(signer_pin=envelope["signer_sha256"], message=protected.record_signing_bytes(body), signature=bytes.fromhex(envelope["signature_hex"]))
        now = self.current(selection, now)
        require(common.utc(publisher["not_before_utc"]) <= common.utc(body["issued_at_utc"]) <= common.utc(now["utc"])
                < common.utc(body["expires_at_utc"]) <= min(common.utc(publisher["expires_at_utc"]), common.utc(selection["expires_at_utc"])), "ATTESTATION_EXPIRED")
        return now

    def sign_registration(self, body, selection, now):
        now = self.current(selection, now)
        if self.registry_signer is None: raise common.DependencyUnavailable("registry-signer")
        raw = protected.validate("ProtectedRegistration", body).raw
        signature = self.registry_signer.sign(domain=protected.REGISTRATION_DOMAIN, canonical_body=raw)
        require(type(signature) is bytes and len(signature) == 64, "SIGNATURE_SHAPE")
        self.signature_check(signer_pin=selection["registry_signer_public_sha256"], message=protected.REGISTRATION_DOMAIN+raw, signature=signature)
        self.current(selection, now)
        return {"registration": body, "algorithm": "Ed25519", "signer_sha256": selection["registry_signer_public_sha256"], "signature_hex": signature.hex()}
