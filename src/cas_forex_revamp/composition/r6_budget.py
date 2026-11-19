"""One immutable model window and atomic total budget, including failed calls."""
from datetime import datetime, timedelta
import time

from ..contracts import ContractError
from ..contracts.primitives import digest, utc_time
from .model_evidence_bridge import AnchoredModelStore


def need(value, message):
    if not value:
        raise ContractError(message)


class ModelWindow:
    def __init__(self, *, absolute_deadline, clock, monotonic=time.monotonic):
        self.clock, self.monotonic = clock, monotonic
        self.started, self.tick = clock(), monotonic()
        self.end = min(absolute_deadline, self.started + timedelta(seconds=5400))
        self.require_remaining(0)

    def require_remaining(self, seconds):
        now, elapsed = self.clock(), self.monotonic()-self.tick
        need(type(seconds) in (int, float) and seconds >= 0 and 0 <= elapsed
             and self.started <= now and now+timedelta(seconds=seconds) < self.end
             and elapsed+seconds < (self.end-self.started).total_seconds(),
             'original shared 90-minute model window exhausted or clock moved backward')

    def record(self):
        return {'started_at': self.started.isoformat(), 'deadline': self.end.isoformat(),
                'total_generation_limit': 32, 'probe_limit': 2, 'acceptance_limit': 30,
                'includes': ['startup','render','tokenize','probes','acceptance','export','shutdown']}


class SharedBudgetModelStore(AnchoredModelStore):
    def bind_window(self, window):
        need(self.deadline == window.end, 'store deadline must be the original model deadline')
        self.window = window

    def retain_window(self, *, now):
        return self.append('shared-model-window', 'MODEL_WINDOW', self.window.record(), now=now)

    def begin_http(self, *, phase, operation, invocation_sha256, body_sha256, timeout_seconds, now, observer_token=None):
        caps = {'probe': (2,60,600), 'acceptance': (30,120,5400)}
        need(phase in caps and operation in ('render','tokenize','generation'), 'unsupported model operation')
        limit, call_seconds, phase_seconds = caps[phase]
        need(type(timeout_seconds) is int and 0 < timeout_seconds <= call_seconds, 'call timeout exceeds phase cap')
        digest(invocation_sha256); digest(body_sha256); utc_time(now, 'now')
        self.window.require_remaining(timeout_seconds)
        receipt_id = operation+'-attempt-'+invocation_sha256
        with self._db() as db:
            records = self._read(db)
            window = [r for r in records if r['kind'] == 'MODEL_WINDOW']
            need(len(window) == 1 and window[0]['payload'] == self.window.record(), 'original model window missing or replaced')
            attempts = [r for r in records if r['kind'] == 'MODEL_HTTP_ATTEMPT']
            need(not any(r['receipt_id'] == receipt_id for r in attempts), 'spent attempt cannot be repeated')
            own = [r for r in attempts if r['payload']['phase'] == phase]
            need(sum(r['payload']['operation'] == operation for r in own) < limit, 'phase operation count exhausted')
            if operation == 'generation':
                need(sum(r['payload']['operation'] == 'generation' for r in attempts) < 32, 'total generation count exhausted')
                if phase == 'acceptance':
                    need(sum(r['payload']['phase'] == 'probe' and r['payload']['operation'] == 'generation' for r in attempts) == 2,
                         'the two spent probes must precede acceptance')
            first = datetime.fromisoformat(own[0]['recorded_at'].replace('Z','+00:00')) if own else now
            need(first <= now and (now-first).total_seconds()+timeout_seconds <= phase_seconds
                 and now+timedelta(seconds=timeout_seconds) < self.deadline, 'shared or phase time exhausted')
            payload = {'phase': phase, 'operation': operation, 'invocation_sha256': invocation_sha256,
                'body_sha256': body_sha256, 'reserved_seconds': timeout_seconds if operation == 'generation' else 0,
                'requested_timeout_seconds': timeout_seconds}
            result = self._insert(db, records, receipt_id, 'MODEL_HTTP_ATTEMPT', payload, now, observer_token=observer_token)
        self._anchor()  # any anchor failure propagates before transport
        return result
