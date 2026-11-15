"""Small accepted clock migration adapter. No new shared record or authority.

The direct tagged body follows candidate03 REFERENCE_MIGRATION.md. The original
window identity remains the exact original five-field canonical content hash.
Other opaque evidence bodies have no invented shape or success fallback here.
"""
import re
from dataclasses import dataclass
from datetime import datetime
from cas_forex_operational_contracts import common, protected, completion
from .selection_provider import require, same, fresh

CLOCK_SLOT="original_clock_and_budget_binding_sha256"
CLOCK_FORMAT="forex.release-evidence-original_clock_and_budget_binding_sha256/1"
CLOCK_FIELDS={"model_window","model_calls","retry_calls","bootstrap_started_utc","test_deadline_utc"}
WINDOW_FIELDS={"started_at","deadline","total_generation_limit","probe_limit","acceptance_limit","includes"}


def clock_utc(value, *, window=False):
    """Accepted source02 original-content grammar, not the S0 Stamp grammar.

    Parse only for arithmetic. Never normalize or rewrite the original string.
    """
    require(type(value) is str,"ORIGINAL_CLOCK_UTC")
    if not window:
        require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z",value) is not None,"ORIGINAL_CLOCK_UTC")
    try:
        parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
        require(parsed.tzinfo is not None and parsed.utcoffset().total_seconds()==0,"ORIGINAL_CLOCK_UTC")
        return parsed
    except (ValueError,OverflowError,AttributeError):
        raise common.ContractError("ORIGINAL_CLOCK_UTC") from None


def original_clock_bytes(raw):
    """Explicit original or accepted tagged successor; never rewrite timestamps.

    The selected protected schema still fixes which record may use each route.
    This helper does not authenticate or select a schema/publisher.
    """
    value=common.decode_canonical(raw)
    require(type(value) is dict,"ORIGINAL_CLOCK_SHAPE")
    if set(value)==CLOCK_FIELDS|{"format"}:
        require(value["format"]==CLOCK_FORMAT,"CLOCK_SUCCESSOR_FORMAT")
        value={k:value[k] for k in CLOCK_FIELDS}
    else:require(set(value)==CLOCK_FIELDS,"ORIGINAL_CLOCK_SHAPE")
    require(type(value["model_calls"]) is int and value["model_calls"]==32
            and type(value["retry_calls"]) is int and value["retry_calls"]==0,"ORIGINAL_CALL_BUDGET")
    window=value["model_window"]
    require(type(window) is dict and set(window)==WINDOW_FIELDS,"ORIGINAL_WINDOW_SHAPE")
    for key,expected in (("total_generation_limit",32),("probe_limit",2),("acceptance_limit",30)):
        require(type(window[key]) is int and window[key]==expected,"ORIGINAL_WINDOW_DENOMINATOR")
    require(window["includes"]==["startup","render","tokenize","probes","acceptance","export","shutdown"],"ORIGINAL_WINDOW_INCLUSIONS")
    begin,end=clock_utc(window["started_at"],window=True),clock_utc(window["deadline"],window=True)
    bootstrap,test_end=clock_utc(value["bootstrap_started_utc"]),clock_utc(value["test_deadline_utc"])
    require(0<(end-begin).total_seconds()<=5400 and 0<(test_end-bootstrap).total_seconds()<=7200
            and bootstrap<=begin,"ORIGINAL_WINDOW_LIMITS")
    return common.canonical_bytes(value)


@dataclass(frozen=True)
class OriginalClockSchema:
    """Selected schema-route adapter for the explicit tagged successor only.

    schema_sha256 is appointed externally in the exact publisher grant; this
    class neither creates the grant nor treats shape validation as gate success.
    """
    schema_sha256: str

    def decode(self, raw):
        body=common.decode_canonical(raw)
        require(type(body) is dict and set(body)==CLOCK_FIELDS|{"format"}
                and body["format"]==CLOCK_FORMAT,"CLOCK_SUCCESSOR_REQUIRED")
        original_clock_bytes(raw)
        return body


class OriginalClockGate:
    """GateCheck.verify adapter; all deployment selections remain external.

    original_clock_raw is independently selected original canonical content,
    never extracted from the proposed successor to appoint its expected value.
    The selected completion verifier still recomputes all thirteen groups.
    """
    def __init__(self, *, original_clock_raw, work_started_utc, work_deadline_utc,
                 component_sha256, resolver, publishers, clock,
                 current_authority_guard, original_deadline):
        self.original=bytes(original_clock_raw)
        require(original_clock_bytes(self.original)==self.original,"ORIGINAL_CLOCK_REQUIRED")
        self.work_started,self.work_deadline=work_started_utc,work_deadline_utc
        self.component,self.resolver=component_sha256,resolver
        self.publishers=common.decode_canonical(common.canonical_bytes(publishers))
        self.clock,self.guard=clock,current_authority_guard
        self.deadline=common.decode_canonical(common.canonical_bytes(original_deadline))

    def verify(self, *, record, selection, dependencies, component_sha256, now):
        now=fresh(self.clock,self.guard,now,self.deadline)
        require(component_sha256==self.component,"CLOCK_GATE_COMPONENT")
        body=common.decode_canonical(record)
        require(type(body) is dict and set(body)==CLOCK_FIELDS|{"format"}
                and body["format"]==CLOCK_FORMAT,"CLOCK_SUCCESSOR_REQUIRED")
        original=original_clock_bytes(record)
        require(original==self.original,"ORIGINAL_CLOCK_SUBSTITUTION")
        selected=protected.decode("ReleaseSelection3",selection).payload()
        require(same(selected["binding"],self.publishers["binding"])
                and common.digest(original)==selected["binding"]["original_window_sha256"],"ORIGINAL_CLOCK_PIN")
        matches=[use["evidence"] for use in selected["release_evidence"] if use["slot"]==CLOCK_SLOT]
        require(len(matches)==1 and matches[0]["reference"]["sha256"]==common.digest(record)
                and matches[0]["reference"]["bytes"]==len(record),"CLOCK_SUCCESSOR_PIN")
        require(type(dependencies) is tuple and len({slot for slot,_ in dependencies})==len(dependencies)
                and dict(dependencies).get(CLOCK_SLOT)==record,"CLOCK_DEPENDENCY_BINDING")
        completion_use=selected["source_test_completion"]
        require(completion_use["required_use"]=="SOURCE_COMPLETION"
                and completion_use["reference"]["record_kind"]=="SOURCE_TEST_COMPLETION"
                and completion_use["reference"]["purpose"]=="source-test-completion","CLOCK_COMPLETION_ROUTE")
        receipt=completion.decode("CompletionReceipt2",self.resolver.resolve(completion_use,selection=self.publishers,now=now)).payload()
        require(same(receipt["binding"],selected["binding"])
                and receipt["original_clock_record_content_sha256"]==common.digest(original),"CLOCK_COMPLETION_BINDING")
        self.check_global(original,work_started_utc=self.work_started,work_deadline_utc=self.work_deadline,
                          completed_at_utc=receipt["completed_at_utc"],now_utc=now["utc"])
        fresh(self.clock,self.guard,now,self.deadline)

    @staticmethod
    def check_global(original, *, work_started_utc, work_deadline_utc, completed_at_utc, now_utc):
        value=common.decode_canonical(original_clock_bytes(original));window=value["model_window"]
        work_start,work_end=clock_utc(work_started_utc),clock_utc(work_deadline_utc)
        bootstrap,test_end=clock_utc(value["bootstrap_started_utc"]),clock_utc(value["test_deadline_utc"])
        model_start,model_end=clock_utc(window["started_at"],window=True),clock_utc(window["deadline"],window=True)
        completed,current=common.utc(completed_at_utc),common.utc(now_utc)
        require((work_end-work_start).total_seconds()==13200 and work_start<=bootstrap<=model_start<=current<model_end
                and bootstrap<test_end<=work_end and bootstrap<=completed<=test_end and completed<=model_start
                and model_end<=work_end and ((model_end-model_start).total_seconds()==5400 or model_end==work_end),"ORIGINAL_GLOBAL_CLOCK")
