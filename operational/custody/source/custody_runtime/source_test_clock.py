"""Explicit source-only clock successor. No model budget or new time allowance."""
from dataclasses import dataclass
from cas_forex_operational_contracts import common
from .gate_adapters import original_clock_bytes, clock_utc

SOURCE_CLOCK_FORMAT='forex.original-source-test-clock/1'
SOURCE_CLOCK_FIELDS={'format','bootstrap_started_utc','test_deadline_utc'}


def source_test_clock_bytes(raw):
    value=common.decode_canonical(raw)
    common.require(type(value) is dict and set(value)==SOURCE_CLOCK_FIELDS
                   and value['format']==SOURCE_CLOCK_FORMAT,'SOURCE_TEST_CLOCK_SHAPE')
    begin,end=clock_utc(value['bootstrap_started_utc']),clock_utc(value['test_deadline_utc'])
    common.require(0<(end-begin).total_seconds()<=7200,'SOURCE_TEST_CLOCK_LIMIT')
    return bytes(raw)


def completion_clock_bytes(raw):
    value=common.decode_canonical(raw)
    if type(value) is dict and value.get('format')==SOURCE_CLOCK_FORMAT:
        return source_test_clock_bytes(raw)
    return original_clock_bytes(raw)


@dataclass(frozen=True)
class SourceTestClockSchema:
    schema_sha256: str

    def decode(self, raw):
        return common.decode_canonical(source_test_clock_bytes(raw))
