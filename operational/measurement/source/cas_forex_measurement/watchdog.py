"""Independent Linux pidfd watchdog mechanism, with lane-local diagnostics only.

Accepted S0 has no WATCHDOG_BINDING body schema. The shared port fails closed;
this mechanism cannot issue an accepted binding or activate authority.
"""
from __future__ import annotations
import os
import select
import signal
import time
from cas_forex_operational_contracts import method as m, capture as c
from cas_forex_operational_contracts.common import canonical_bytes,decode_canonical,digest,require,DependencyUnavailable,utc


class IndependentWatchdog:
    def __init__(self,*,clock,inventory,execution_gate):
        require(callable(execution_gate),'WATCHDOG_GATE');self.clock,self.inventory,self.gate=clock,inventory,execution_gate
        self._armed=False;self.pid=None;self.pidfd=None;self.control=None;self.reports=None;self.budget=None;self.binding=None
    def arm_original(self,budget:m.SetupBudget,*,selected_processes:tuple[c.CaptureSubject,...])->m.ObjectRef:
        raise DependencyUnavailable('reviewed_WATCHDOG_BINDING_body_and_selection')
    def observe(self,original_binding:m.ObjectRef,*,now:m.Stamp)->m.ObjectRef:
        raise DependencyUnavailable('reviewed_WATCHDOG_BINDING_body_and_selection')
    def arm_diagnostic(self,budget,*,selected_processes):
        require(not self._armed and self.gate() is None,'WATCHDOG_ONE_SHOT_OR_GATE')
        self._armed=True;budget=m.validate('SetupBudget',budget).payload()
        require(1<=len(selected_processes)<=32,'WATCHDOG_SUBJECT_COUNT')
        require(len({(x['pid'],x['start_ticks']) for x in selected_processes})==len(selected_processes),'WATCHDOG_DUPLICATE_SUBJECT')
        require(self.clock.domain()==budget['clock_domain'],'WATCHDOG_CLOCK_DOMAIN')
        descriptors=[];pipes=[];pid=None
        try:
            for selected in selected_processes:
                c.validate('CaptureSubject',selected)
                require(self.inventory.subject(selected['pid'],selected['role'])==selected,'WATCHDOG_SUBJECT_CHANGED')
                fd=os.pidfd_open(selected['pid']);descriptors.append(fd)
                require(self.inventory.subject(selected['pid'],selected['role'])==selected,'WATCHDOG_SUBJECT_CHANGED')
            control=os.pipe2(os.O_CLOEXEC);report=os.pipe2(os.O_CLOEXEC);pipes=[*control,*report]
            require(len(os.listdir('/proc/self/task'))==1,'FORK_REQUIRES_SINGLE_THREAD')
            pid=os.fork()
            if pid==0:
                try:
                    keep={control[0],report[1],*descriptors}
                    for name in os.listdir('/proc/self/fd'):
                        fd=int(name)
                        if fd not in keep:
                            try:os.close(fd)
                            except OSError:pass
                    self._watch(budget,tuple(descriptors),control[0],report[1])
                except BaseException:
                    for fd in descriptors:
                        try:signal.pidfd_send_signal(fd,signal.SIGKILL)
                        except OSError:pass
                finally:os._exit(0)
            self.pidfd=os.pidfd_open(pid);self.pid=pid
            os.close(control[0]);pipes.remove(control[0]);os.close(report[1]);pipes.remove(report[1])
            for fd in descriptors:os.close(fd)
            descriptors=[]
            ready,_,_=select.select([report[0]],[],[],1.0);require(ready,'WATCHDOG_ARM_UNOBSERVED')
            require(os.read(report[0],16)==b'ARMED\n','WATCHDOG_ARM_UNOBSERVED')
            self.control,self.reports=control[1],report[0];pipes=[];self.budget=budget
            self.binding={'format':'forex.measurement-watchdog-diagnostic/1','accepted_binding':False,
                'budget_sha256':digest(canonical_bytes(budget)),'clock_domain':budget['clock_domain'],
                'watchdog_subject':self.inventory.subject(pid,'CONTROLLER'),'selected_processes':list(selected_processes),
                'original_deadline':budget['deadline'],'outer_deadline':budget['outer_deadline'],'armed_observed':self.clock.stamp(),
                'scope':'EXACT_SELECTED_PIDFDS_ONLY','descendant_discovery':'NOT_PROVIDED'}
            return decode_canonical(canonical_bytes(self.binding))
        finally:
            for fd in descriptors+pipes:
                try:os.close(fd)
                except OSError:pass
            # Closing the control writer after a failed arm causes the independent
            # child to terminate selected PIDfds. It is never reported as success.
    def _watch(self,budget,pidfds,control,report):
        os.set_blocking(control,False);os.write(report,b'ARMED\n')
        first=budget['started'];last=None;reason='UNKNOWN'
        while True:
            stamp=self.clock.stamp()
            if self.clock.domain()!=budget['clock_domain']:reason='CLOCK_DOMAIN_CHANGED';break
            elapsed=int((utc(stamp['utc'])-utc(first['utc'])).total_seconds()*1_000_000_000)
            if abs(elapsed-(stamp['boottime_ns']-first['boottime_ns']))>1_000_000_000:reason='CLOCK_DRIFT';break
            if last and (stamp['boottime_ns']<last['boottime_ns'] or utc(stamp['utc'])<utc(last['utc'])):reason='CLOCK_ROLLBACK';break
            if any(stamp['boottime_ns']>=budget[k]['boottime_ns'] or utc(stamp['utc'])>=utc(budget[k]['utc']) for k in ('deadline','outer_deadline')):reason='ORIGINAL_DEADLINE';break
            ready,_,_=select.select([control],[],[],0.02)
            if ready:
                data=os.read(control,64)
                reason='PARENT_EOF' if not data else 'CONTROL_INPUT_REJECTED';break
            last=stamp
        observations=[]
        for fd in pidfds:
            try:signal.pidfd_send_signal(fd,signal.SIGKILL);observations.append('SIGNAL_SENT')
            except ProcessLookupError:observations.append('ALREADY_EXITED')
            except OSError:observations.append('SIGNAL_FAILED')
        # Successful signal delivery is not proof of exit; pidfd readability is.
        pending=set(pidfds);end=time.monotonic()+1.0
        while pending and time.monotonic()<end:
            ready,_,_=select.select(list(pending),[],[],min(0.02,max(0,end-time.monotonic())))
            pending.difference_update(ready)
        raw=canonical_bytes({'reason':reason,'signals':observations,'all_selected_exited':not pending,
            'unconfirmed_count':len(pending),'observed':self.clock.stamp()})
        require(len(raw)<=4096,'WATCHDOG_REPORT_BOUND');os.write(report,raw)
    def observe_diagnostic(self):
        require(self.binding is not None and self.gate() is None,'WATCHDOG_NOT_ARMED')
        ready,_,_=select.select([self.reports],[],[],0)
        if ready:
            raw=os.read(self.reports,4097);require(0<len(raw)<=4096,'WATCHDOG_REPORT_UNAVAILABLE')
            observation=decode_canonical(raw)
        else:
            exited,_,_=select.select([self.pidfd],[],[],0)
            require(not exited,'WATCHDOG_EXIT_UNOBSERVED')
            observation={'status':'RUNNING_OBSERVED','observed':self.clock.stamp()}
        return {'binding':decode_canonical(canonical_bytes(self.binding)),'observation':observation,'accepted_binding':False}
