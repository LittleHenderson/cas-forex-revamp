"""Actual bounded subprocess/stream/framework observation; never test acceptance."""
from __future__ import annotations
from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import select
import struct
import time
import unittest
from cas_forex_operational_contracts import completion as co, protected as pr, capture as c, method as m
from cas_forex_operational_contracts.validation import verify_reference_bytes
from .inventory import stat_record,require_owned_child_lifecycle,terminate_owned_child
from cas_forex_operational_contracts.common import (canonical_bytes,decode_json,decode_canonical,digest,require,ContractError,
    DependencyUnavailable,ValidationLimits,utc)


def python_framework_report(suite,*,group_id):
    """Selected test driver calls explicitly in its observed subprocess only."""
    def flatten(node):
        if isinstance(node,unittest.TestSuite):
            for item in node:yield from flatten(item)
        else:yield node.id()
    collected=list(flatten(suite));require(len(collected)==len(set(collected)),'DUPLICATE_TEST_ID')
    class Result(unittest.TestResult):
        def __init__(self):super().__init__();self.executed=[];self.passed=0
        def startTest(self,test):self.executed.append(test.id());super().startTest(test)
        def addSuccess(self,test):self.passed+=1;super().addSuccess(test)
    result=Result();suite.run(result)
    counts={'discovered':len(collected),'ran':result.testsRun,'passed':result.passed,'skipped':len(result.skipped),
            'failures':len(result.failures)+len(result.unexpectedSuccesses),'errors':len(result.errors),
            'cancelled':int(result.shouldStop),'todo':len(result.expectedFailures)}
    value={'format':'forex.python-framework-report/2','group_id':group_id,'collected_test_ids':collected,
        'executed_test_ids':result.executed,'counts':counts,'status':'PASS' if result.wasSuccessful() and not result.shouldStop else 'FAIL'}
    return co.validate('PythonFrameworkReport2',value).payload()


def parse_python(raw,*,group_id):
    value=co.validate('PythonFrameworkReport2',decode_json(raw.strip(),limit=524288)).payload()
    require(value['group_id']==group_id,'FRAMEWORK_GROUP')
    return value


def parse_flat_tap(raw):
    """Strict pinned flat TAP route; nested/ambiguous names are unavailable, never guessed."""
    text=raw.decode('utf-8','strict');names=[];results=[];plan=None;pending=None;summary={};in_diag=False
    for line in text.splitlines():
        if line=='TAP version 13':continue
        if line=='  ---':in_diag=True;continue
        if in_diag:
            if line=='  ...':in_diag=False
            continue
        require(not line.startswith(('    # Subtest:', '    ok ', '    not ok ')),'NESTED_TAP_UNSUPPORTED')
        if line.startswith('# Subtest: '):
            require(pending is None,'AMBIGUOUS_TAP');pending=line[len('# Subtest: '):];require(pending and pending not in names,'DUPLICATE_TEST_ID');names.append(pending);continue
        match=re.fullmatch(r'(not ok|ok) ([1-9][0-9]*) - (.*?)(?: # (SKIP|TODO)(?: .*)?)?',line)
        if match:
            status,number,name,directive=match.groups();require(int(number)==len(results)+1 and name==pending,'TAP_NAME_OR_SEQUENCE')
            result=directive if directive else ('PASS' if status=='ok' else 'FAIL')
            results.append({'test_id':name,'result':result});pending=None;continue
        if re.fullmatch(r'1\.\.[0-9]+',line):require(plan is None,'DUPLICATE_TAP_PLAN');plan=int(line[3:]);continue
        match=re.fullmatch(r'# (tests|suites|pass|fail|cancelled|skipped|todo) ([0-9]+)',line)
        if match:require(match[1] not in summary,'DUPLICATE_TAP_COUNT');summary[match[1]]=int(match[2]);continue
        if re.fullmatch(r'(?:# )?duration_ms: [0-9.]+',line.strip()) or re.fullmatch(r'# duration_ms [0-9.]+',line):continue
        require(not line.strip(),'UNRECOGNIZED_TAP')
    require(not in_diag and pending is None and plan==len(results)>0,'INCOMPLETE_TAP')
    counts={'discovered':len(names),'ran':len(results),'passed':sum(x['result']=='PASS' for x in results),
            'skipped':sum(x['result']=='SKIP' for x in results),'failures':sum(x['result']=='FAIL' for x in results),
            'errors':0,'cancelled':0,'todo':sum(x['result']=='TODO' for x in results)}
    expected={'tests':counts['ran'],'suites':0,'pass':counts['passed'],'fail':counts['failures'],
              'cancelled':0,'skipped':counts['skipped'],'todo':counts['todo']}
    require(summary==expected,'TAP_SUMMARY_MISMATCH')
    return co.validate('NodeTapReport1',{'format':'forex.node-tap-report/1','group_id':'ui','collected_test_ids':names,
        'test_results':results,'counts':counts,'complete':True}).payload()


MAX_DISCOVERY_BODY=524_288


def selected_driver_arguments(command):
    """Read fixed selected argv; never insert report-supplied flags or values."""
    co.validate('CommandPin',command)
    argv=command['argv'];result={}
    for name in ('discovery-fd','release-fd','group','inventory-sha256'):
        flag='--'+name
        positions=[i for i,value in enumerate(argv) if value==flag]
        require(len(positions)==1 and positions[0]+1<len(argv) and
                not any(value.startswith(flag+'=') for value in argv),'EXACT_DISCOVERY_ARGUMENTS')
        result[name]=argv[positions[0]+1]
    require(result['group']==command['group_id'],'DISCOVERY_GROUP')
    pin=result['inventory-sha256']
    require(len(pin)==64 and all(x in '0123456789abcdef' for x in pin),'DISCOVERY_INVENTORY_PIN')
    for name in ('discovery-fd','release-fd'):
        text=result[name]
        require(re.fullmatch(r'[1-9][0-9]*',text) is not None and 3<=int(text)<=1024,'DISCOVERY_FD_SELECTION')
        result[name]=int(text)
    require(result['discovery-fd']!=result['release-fd'],'DISCOVERY_FD_COLLISION')
    require(command['stdin_policy']=='CLOSED','DISCOVERY_STDIN_POLICY')
    return result


def parse_discovery(raw,*,group_id,inventory_sha256):
    require(type(raw) is bytes and 0<len(raw)<=MAX_DISCOVERY_BODY,'DISCOVERY_BODY_BOUND')
    value=decode_canonical(raw,limit=MAX_DISCOVERY_BODY)
    require(type(value) is dict and set(value)=={'format','group_id','inventory_sha256','test_ids'},'DISCOVERY_FIELDS')
    require(value['format']=='forex.test-driver-discovery/1' and value['group_id']==group_id
            and value['inventory_sha256']==inventory_sha256,'DISCOVERY_SELECTION')
    ids=value['test_ids']
    require(type(ids) is list and len(ids)<=100000 and all(type(x) is str and 0<len(x)<=1024 for x in ids)
            and len(ids)==len(set(ids)),'DISCOVERY_IDS')
    require(bool(ids)==(group_id!='node-version'),'DISCOVERY_VERSION_MEMBERSHIP')
    return value


class DiscoveryFrame:
    """A single bounded frame is usable only after its actual pipe EOF."""
    def __init__(self):self.buffer=bytearray();self.size=None;self.closed=False
    def feed(self,block):
        require(not self.closed and type(block) is bytes and block,'DISCOVERY_FEED_STATE')
        require(len(self.buffer)+len(block)<=MAX_DISCOVERY_BODY+4,'DISCOVERY_FRAME_BOUND')
        self.buffer.extend(block)
        if self.size is None and len(self.buffer)>=4:
            self.size=struct.unpack('!I',self.buffer[:4])[0]
            require(0<self.size<=MAX_DISCOVERY_BODY,'DISCOVERY_FRAME_BOUND')
        require(self.size is None or len(self.buffer)<=self.size+4,'DISCOVERY_EXTRA_FRAME')
    def eof(self):
        require(not self.closed and self.size is not None and len(self.buffer)==self.size+4,'DISCOVERY_TRUNCATED_FRAME')
        self.closed=True
    @property
    def body(self):
        require(self.closed,'DISCOVERY_EOF_REQUIRED');return bytes(self.buffer[4:])
    @property
    def wire(self):
        require(self.closed,'DISCOVERY_EOF_REQUIRED');return bytes(self.buffer)


def release_frame(group_id,discovery_raw):
    body=canonical_bytes({'format':'forex.test-driver-start/1','group_id':group_id,
        'discovery_sha256':digest(discovery_raw)})
    return struct.pack('!I',len(body))+body


@dataclass(frozen=True)
class DiscoveryObservation:
    """Immutable local actual capture, not a shared signed record."""
    process_bytes:bytes
    spawned_bytes:bytes
    collected_bytes:bytes
    body_bytes:bytes
    @property
    def process(self):return c.decode('CaptureSubject',self.process_bytes).payload()
    @property
    def spawned(self):return m.decode('Stamp',self.spawned_bytes).payload()
    @property
    def collected(self):return m.decode('Stamp',self.collected_bytes).payload()
    @property
    def body(self):return decode_canonical(self.body_bytes,limit=MAX_DISCOVERY_BODY)


@dataclass(frozen=True)
class ObservedGroupRun:
    discovery:DiscoveryObservation
    execution_started_bytes:bytes
    exited_bytes:bytes
    exit_code:int
    stdout:bytes
    stderr:bytes
    discovery_publication_bytes:bytes
    discovery_frame_ref_bytes:bytes
    release_frame_ref_bytes:bytes
    @property
    def execution_started(self):return m.decode('Stamp',self.execution_started_bytes).payload()
    @property
    def exited(self):return m.decode('Stamp',self.exited_bytes).payload()
    @property
    def discovery_publication(self):return pr.decode('ProtectedReferenceUse',self.discovery_publication_bytes).payload()
    @property
    def discovery_frame_ref(self):return m.decode('ObjectRef',self.discovery_frame_ref_bytes).payload()
    @property
    def release_frame_ref(self):return m.decode('ObjectRef',self.release_frame_ref_bytes).payload()


class ForkExecCapture:
    """One observed child, with collection publication before execution release.

    Exact argv selects child FD numbers. Anonymous pipe sources are remapped in
    the child only; executable/argv/environment pins are never rewritten.
    """
    def __init__(self,*,inventory,guard,execution_gate,capture_sink):
        require(callable(execution_gate),'EXECUTION_GATE_REQUIRED')
        self.inventory,self.guard,self.gate,self.sink=inventory,guard,execution_gate,capture_sink
    def _retain(self,raw):
        ref=self.sink.retain(raw,artifact_kind='NATIVE_CAPTURE_BYTES')
        verify_reference_bytes(ref,raw)
        require(ref['artifact_kind']=='NATIVE_CAPTURE_BYTES' and self.sink.readback(ref)==raw,'DISCOVERY_CAPTURE_RETENTION')
        return canonical_bytes(ref)
    def _live(self,pid,pidfd,subject):
        require(not select.select([pidfd],[],[],0)[0] and self.inventory.subject(pid,'COMPLETION_OBSERVER')==subject,
                'DISCOVERY_CHILD_NOT_LIVE')
    def _release(self,fd,raw):
        os.set_blocking(fd,False);offset=0
        while offset<len(raw):
            self.guard.now()
            if not select.select([],[fd],[],min(0.05,self.guard.remaining()))[1]:continue
            try:count=os.write(fd,raw[offset:offset+65536])
            except BlockingIOError:continue
            require(count>0,'DISCOVERY_RELEASE_WRITE');offset+=count
        self.guard.now()
    def run(self,command,*,environment,maximum_stream_bytes,on_discovery,before_release):
        require(callable(on_discovery) and callable(before_release),'DISCOVERY_CALLBACKS_REQUIRED')
        require(type(maximum_stream_bytes) is int and 0<maximum_stream_bytes<=524_288,'STREAM_BOUND')
        selected_args=selected_driver_arguments(command)
        require(self.gate() is None,'RUNTIME_APPROVAL_ABSENT');self.guard.now()
        selected=command['executable'];fd=os.open(selected['selected_path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        pipes=[];pid=None;pidfd=None
        def pipe(*,nonblocking=False):
            pair=os.pipe2(os.O_CLOEXEC|(os.O_NONBLOCK if nonblocking else 0));pipes.extend(pair);return pair
        def close_owned(n):
            os.close(n);pipes.remove(n)
        try:
            st=os.fstat(fd);h=hashlib.sha256();size=0
            while True:
                self.guard.now();block=os.read(fd,1048576)
                if not block:break
                size+=len(block);require(size<=selected['bytes'],'EXECUTABLE_SIZE');h.update(block)
            require((size,h.hexdigest(),st.st_dev,st.st_ino)==(selected['bytes'],selected['sha256'],selected['device'],selected['inode']),'EXECUTABLE_PIN')
            require(stat_record(os.fstat(fd))==stat_record(st),'EXECUTABLE_CHANGED')
            stdout,stderr,failure=pipe(),pipe(),pipe()
            discovery,release=pipe(nonblocking=True),pipe(nonblocking=True)
            require_owned_child_lifecycle();self.guard.now();pid=os.fork()
            if pid==0:
                error_fd=failure[1]
                try:
                    # Duplicate sources above every selected child target before
                    # remapping, so arbitrary allocation/target collisions are safe.
                    floor=max(16,selected_args['discovery-fd']+1,selected_args['release-fd']+1)
                    out,err,exe,error_fd,dis,rel=[fcntl.fcntl(n,fcntl.F_DUPFD_CLOEXEC,floor)
                        for n in (stdout[1],stderr[1],fd,failure[1],discovery[1],release[0])]
                    os.dup2(out,1);os.dup2(err,2)
                    os.dup2(dis,selected_args['discovery-fd'],inheritable=True)
                    os.dup2(rel,selected_args['release-fd'],inheritable=True)
                    try:os.close(0)
                    except OSError:pass
                    keep={1,2,exe,error_fd,selected_args['discovery-fd'],selected_args['release-fd']}
                    for item in os.listdir('/proc/self/fd'):
                        n=int(item)
                        if n not in keep:
                            try:os.close(n)
                            except OSError:pass
                    os.chdir(command['cwd']);os.kill(os.getpid(),signal.SIGSTOP)
                    os.execve(exe,command['argv'],dict(environment))
                except BaseException:
                    try:os.write(error_fd,b'EXEC_FAILED')
                    finally:os._exit(127)
            spawned=self.guard.now() # Actual successful fork observed by parent.
            pidfd=os.pidfd_open(pid)
            for n in (stdout[1],stderr[1],failure[1],discovery[1],release[0]):close_owned(n)
            while True:
                self.guard.now();got,status=os.waitpid(pid,os.WNOHANG|os.WUNTRACED)
                if got:require(os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGSTOP,'TEST_SPAWN_FAILED');break
                time.sleep(min(0.005,self.guard.remaining()))
            subject=self.inventory.subject(pid,'COMPLETION_OBSERVER')
            signal.pidfd_send_signal(pidfd,signal.SIGCONT)
            chunks={stdout[0]:bytearray(),stderr[0]:bytearray(),failure[0]:bytearray()}
            frame=DiscoveryFrame();exec_eof=False;notice=None;publication=None;execution_started=None;dis_ref=None;release_ref=None
            with selectors.DefaultSelector() as selector:
                for n in (*chunks,discovery[0]):os.set_blocking(n,False);selector.register(n,selectors.EVENT_READ)
                while selector.get_map():
                    self.guard.now();events=selector.select(min(0.05,self.guard.remaining()))
                    for key,_ in events:
                        n=key.fd
                        try:block=os.read(n,65536)
                        except BlockingIOError:continue
                        if not block:
                            selector.unregister(n)
                            if n==discovery[0]:frame.eof()
                            if n==failure[0]:exec_eof=True
                            continue
                        if n==discovery[0]:frame.feed(block)
                        else:
                            chunks[n].extend(block)
                            require(len(chunks[n])<=(64 if n==failure[0] else maximum_stream_bytes),'TEST_STREAM_OVERFLOW')
                    if frame.closed and exec_eof and execution_started is None:
                        require(not chunks[failure[0]],'TEST_EXEC_FAILED')
                        self._live(pid,pidfd,subject)
                        parse_discovery(frame.body,group_id=command['group_id'],inventory_sha256=selected_args['inventory-sha256'])
                        collected=self.guard.now()
                        notice=DiscoveryObservation(canonical_bytes(subject),canonical_bytes(spawned),canonical_bytes(collected),frame.body)
                        dis_ref=self._retain(frame.wire)
                        publication=on_discovery(notice)
                        pr.validate('ProtectedReferenceUse',publication)
                        publication=canonical_bytes(publication) # Callback cannot later mutate it.
                        require(before_release(process=notice.process,now=self.guard.now()) is None,'DISCOVERY_RELEASE_AUTHORITY')
                        self._live(pid,pidfd,subject)
                        require(self.gate() is None,'RUNTIME_APPROVAL_ABSENT')
                        wire=release_frame(command['group_id'],frame.body)
                        execution_started=self.guard.now()
                        self._release(release[1],wire);close_owned(release[1])
                        # Retained after the actual write/EOF, not an intended ACK.
                        release_ref=self._retain(wire)
            require(not chunks[failure[0]] and notice is not None and execution_started is not None and release_ref is not None,'TEST_DISCOVERY_INCOMPLETE')
            while True:
                self.guard.now();got,status=os.waitpid(pid,os.WNOHANG)
                if got:break
                time.sleep(min(0.005,self.guard.remaining()))
            require(os.WIFEXITED(status),'TEST_EXIT_UNKNOWN')
            finish=self.guard.now();exit_code=os.WEXITSTATUS(status);pid=None
            return ObservedGroupRun(notice,canonical_bytes(execution_started),canonical_bytes(finish),exit_code,
                bytes(chunks[stdout[0]]),bytes(chunks[stderr[0]]),publication,dis_ref,release_ref)
        finally:
            try:
                if pid is not None:terminate_owned_child(pid,pidfd)
            finally:
                for n in pipes:
                    try:os.close(n)
                    except OSError:pass
                if pidfd is not None:os.close(pidfd)
                os.close(fd)


class CompletionObserver:
    def __init__(self,*,resolver,publishers,publish_record,guard,original_clock_verifier,
                 environment,environment_profile_sha256,process_capture,observer_id,parser_component_sha256,
                 authenticate_selection,parser_schema_sha256):
        require(callable(publish_record) and callable(original_clock_verifier) and callable(authenticate_selection),'COMPLETION_DEPENDENCY')
        self.authenticate_selection=authenticate_selection;self.parser_schema_sha256=dict(parser_schema_sha256)
        self.resolver,self.publishers,self.publish=resolver,publishers,publish_record
        self.guard,self.verify_clock=guard,original_clock_verifier
        self.environment=dict(environment);self.environment_hash=environment_profile_sha256
        self.process_capture=process_capture;self.observer_id=observer_id;self.parser_component=parser_component_sha256
        self.used=set()
    def _resolve(self,use,type_name):
        raw=self.resolver.resolve(use,selection=self.publishers,now=self.guard.now())
        return co.decode(type_name,raw).payload()
    def _publish(self,value,kind,purpose):
        raw=canonical_bytes(value,limit=4194304)
        use=self.publish(raw,record_kind=kind,purpose=purpose,now=self.guard.now())
        pr.validate('ProtectedReferenceUse',use)
        require(use['reference']['sha256']==digest(raw) and use['reference']['bytes']==len(raw),'PUBLICATION_BYTES')
        require(use['reference']['record_kind']==kind and use['reference']['purpose']==purpose
            and use['reference']['publisher_id']==self.observer_id and use['required_use']=='SOURCE_COMPLETION','PUBLICATION_ROUTE')
        require(self.resolver.resolve(use,selection=self.publishers,now=self.guard.now())==raw,'PUBLICATION_READBACK')
        return use
    def observe(self,selection:co.CompletionSelection2,*,group:co.GroupSelection)->tuple[co.ProcessCapture2,co.TestStream2,co.TestStream2,co.GroupReport2]:
        selection=co.validate('CompletionSelection2',selection).payload();group=co.validate('GroupSelection',group).payload()
        now=self.guard.now()
        require(self.authenticate_selection(selection,now=now) is None,'COMPLETION_SELECTION_AUTHENTICATION')
        require(utc(selection['not_before_utc'])<=utc(now['utc'])<utc(selection['expires_at_utc']),'COMPLETION_SELECTION_INTERVAL')
        require(selection['publisher_selection_sha256']==digest(canonical_bytes(self.publishers)),'PUBLISHER_SELECTION_PIN')
        key=(digest(canonical_bytes(selection)),group['group_id']);require(key not in self.used,'COMPLETION_ONE_SHOT')
        require(group in selection['groups'] and selection['observer_id']==self.observer_id,'COMPLETION_SELECTION')
        require(self.verify_clock(selection['original_clock_ref'],self.guard.now()) is None,'ORIGINAL_CLOCK_UNAVAILABLE')
        command=self._resolve(group['command'],'CommandPin');parser=self._resolve(group['parser'],'ParserPin')
        require(command['binding']==selection['binding'] and command['group_id']==group['group_id'],'COMPLETION_COMMAND')
        require(command['environment_profile_sha256']==self.environment_hash and digest(canonical_bytes(self.environment))==self.environment_hash,'ENVIRONMENT_PROFILE')
        require(parser['component_manifest_sha256']==self.parser_component and parser['mode']==group['mode'],'PARSER_PIN')
        expected_entry={'PYTHON_METHODS':'cas_forex_measurement.completion.parse_python','NODE_TAP':'cas_forex_measurement.completion.parse_flat_tap','NODE_VERSION':'cas_forex_measurement.completion.node_version_report'}[group['mode']]
        require(parser['entrypoint']==expected_entry,'PARSER_ENTRYPOINT')
        fmt,encoding={'PYTHON_METHODS':('forex.python-framework-report/2','QUALIFIED_UNITTEST_ID'),'NODE_TAP':('forex.node-tap-report/1','FULL_NODE_TEST_NAME'),'NODE_VERSION':('forex.node-version-report/1','NO_TEST_IDS')}[group['mode']]
        require(parser['binding']==selection['binding'] and parser['accepted_report_format']==fmt and parser['test_id_encoding']==encoding
            and parser['report_schema_sha256']==self.parser_schema_sha256[fmt],'PARSER_SCHEMA_PIN')
        source=self._resolve(selection['source_inventory_ref'],'SourceInventory')
        require(source['binding']==selection['binding'] and source['source_manifest_sha256']==command['source_manifest_sha256'],'COMPLETION_SOURCE_PIN')
        inventory=self._resolve(group['expected_inventory'],'CollectionInventory')
        require(inventory['binding']==selection['binding'] and inventory['group_id']==group['group_id']
            and inventory['source_manifest_sha256']==source['source_manifest_sha256'],'DISCOVERY_SOURCE_INVENTORY')
        expected_ids=sorted(entry['test_id'] for entry in inventory['entries'])
        require(len(expected_ids)==len(set(expected_ids))==inventory['expected_count']==group['expected_test_count']
            and digest(canonical_bytes(expected_ids,limit=4194304))==inventory['test_ids_sha256'],'DISCOVERY_EXPECTED_IDS')
        files={(entry['source_relative_path'],entry['source_file_sha256'],entry['group_id']) for entry in source['test_files']}
        require(all((entry['source_relative_path'],entry['source_file_sha256'],group['group_id']) in files for entry in inventory['entries']),
            'DISCOVERY_TEST_FILE_PIN')
        selected_args=selected_driver_arguments(command)
        frozen=((group['command'],'CommandPin',command),(group['parser'],'ParserPin',parser),
            (group['expected_inventory'],'CollectionInventory',inventory),(selection['source_inventory_ref'],'SourceInventory',source))
        def current(*,process=None,now=None):
            current_time=self.guard.now() if now is None else now
            if process is not None:c.validate('CaptureSubject',process)
            require(self.authenticate_selection(selection,now=current_time) is None,'COMPLETION_SELECTION_AUTHENTICATION')
            require(utc(selection['not_before_utc'])<=utc(current_time['utc'])<utc(selection['expires_at_utc']),'COMPLETION_SELECTION_EXPIRED')
            require(self.verify_clock(selection['original_clock_ref'],current_time) is None,'ORIGINAL_CLOCK_UNAVAILABLE')
            for use,type_name,value in frozen:
                require(self._resolve(use,type_name)==value,'DISCOVERY_SELECTED_INPUT_CHANGED')
            self.guard.now()
        registered=[]
        def collect(notice):
            require(type(notice) is DiscoveryObservation and not registered,'DISCOVERY_ONE_SHOT')
            value=parse_discovery(notice.body_bytes,group_id=group['group_id'],inventory_sha256=selected_args['inventory-sha256'])
            require(sorted(value['test_ids'])==expected_ids,'INDEPENDENT_DISCOVERY_MISMATCH')
            require(utc(notice.spawned['utc'])<=utc(notice.collected['utc']) and
                notice.spawned['boottime_ns']<=notice.collected['boottime_ns'],'DISCOVERY_CAPTURE_ORDER')
            current(process=notice.process)
            discovery={'format':'forex.test-discovery-report/1','binding':selection['binding'],'selection_sha256':key[0],
                'group_id':group['group_id'],'process':notice.process,'source_inventory_sha256':digest(canonical_bytes(source)),
                'collected_test_ids':value['test_ids'],'collected_at_utc':notice.collected['utc']}
            co.validate('TestDiscoveryReport',discovery)
            use=self._publish(discovery,'TEST_DISCOVERY_REPORT','test-discovery-report')
            registered.append((canonical_bytes(discovery),canonical_bytes(use)))
            return use
        current();self.used.add(key)
        actual=self.process_capture.run(command,environment=self.environment,maximum_stream_bytes=parser['maximum_stream_bytes'],
            on_discovery=collect,before_release=current)
        require(type(actual) is ObservedGroupRun and len(registered)==1,'ACTUAL_DISCOVERY_UNAVAILABLE')
        subject=actual.discovery.process;spawned=actual.discovery.spawned;start=actual.execution_started;end=actual.exited
        code,out,err=actual.exit_code,actual.stdout,actual.stderr
        require(registered[0][1]==actual.discovery_publication_bytes,'DISCOVERY_PUBLICATION_SUBSTITUTED')
        discovery=co.decode('TestDiscoveryReport',registered[0][0]).payload()
        require(discovery['process']==subject and discovery['collected_at_utc']==actual.discovery.collected['utc']
            and discovery['collected_test_ids']==actual.discovery.body['test_ids'],'DISCOVERY_OBSERVATION_SUBSTITUTED')
        require(utc(spawned['utc'])<=utc(discovery['collected_at_utc'])<=utc(start['utc'])<=utc(end['utc'])
            and spawned['boottime_ns']<=actual.discovery.collected['boottime_ns']<=start['boottime_ns']<=end['boottime_ns'],
            'DISCOVERY_EXECUTION_ORDER')
        discovery_ref=actual.discovery_publication
        current(process=subject)
        streams=[];uses=[]
        for name,raw in (('STDOUT',out),('STDERR',err)):
            value={'format':'forex.test-stream/2','binding':selection['binding'],'group_id':group['group_id'],'process':subject,
                'stream':name,'encoding':'UTF8_STRICT','utf8':raw.decode('utf-8','strict'),'raw_sha256':digest(raw),'bytes':len(raw),'complete':True}
            co.validate('TestStream2',value,limits=ValidationLimits(stream_bytes=parser['maximum_stream_bytes']))
            streams.append(value);uses.append(self._publish(value,'TEST_STREAM','test-stream'))
        if group['mode']=='PYTHON_METHODS':framework=parse_python(out,group_id=group['group_id'])
        elif group['mode']=='NODE_TAP':framework=parse_flat_tap(out)
        else:framework=node_version_report(out,err)
        require(len(canonical_bytes(framework))<=parser['maximum_report_bytes'],'FRAMEWORK_REPORT_BOUND')
        framework_ref=self._publish(framework,'TEST_FRAMEWORK_REPORT','test-framework-report')
        counts=framework.get('counts',dict(discovered=0,ran=0,passed=0,skipped=0,failures=0,errors=0,cancelled=0,todo=0))
        collected=framework.get('collected_test_ids',[])
        executed=framework.get('executed_test_ids',[x['test_id'] for x in framework.get('test_results',[])])
        require(sorted(collected)==sorted(discovery['collected_test_ids'])==expected_ids
            and sorted(executed)==expected_ids and len(executed)==len(set(executed)), 'DISCOVERY_FRAMEWORK_MISMATCH')
        # This is the original prior-discovery record. Final TAP/framework output
        # is only compared with it; it cannot create or replace that observation.
        require(self.resolver.resolve(discovery_ref,selection=self.publishers,now=self.guard.now())==registered[0][0],
            'DISCOVERY_FINAL_READBACK')
        capture={'format':'forex.test-process-capture/2','binding':selection['binding'],'selection_sha256':key[0],
            'group_id':group['group_id'],'command_sha256':command['command_sha256'],'executable_sha256':command['executable']['sha256'],
            'events':[{'sequence':1,'kind':'SPAWN','process':subject,'at_utc':spawned['utc'],'exit_code':None},
                      {'sequence':2,'kind':'EXIT','process':subject,'at_utc':end['utc'],'exit_code':code}],
            'lost_events':0,'stdout_ref':uses[0],'stderr_ref':uses[1]}
        co.validate('ProcessCapture2',capture);capture_ref=self._publish(capture,'TEST_PROCESS_CAPTURE','test-process-capture')
        report={'format':'forex.observed-test-group/2','binding':selection['binding'],'selection_sha256':key[0],
            'group_id':group['group_id'],'process':subject,'command_ref':group['command'],'parser_ref':group['parser'],
            'expected_inventory_ref':group['expected_inventory'],'capture_ref':capture_ref,'stdout_ref':uses[0],'stderr_ref':uses[1],
            'original_framework_report_ref':framework_ref,'started_at_utc':start['utc'],'finished_at_utc':end['utc'],'exit_code':code,
            'collected_test_ids':collected,'executed_test_ids':executed,'counts':counts,
            'node_version_utf8':out.decode() if group['mode']=='NODE_VERSION' else None,'discovery_report_ref':discovery_ref}
        co.validate('GroupReport2',report)
        # No status/acceptance field exists here. Custody alone compares all thirteen groups.
        return capture,streams[0],streams[1],report


def node_version_report(out,err):
    return co.validate('NodeVersionReport1',{'format':'forex.node-version-report/1','group_id':'node-version',
        'stdout_utf8':out.decode('utf-8','strict'),'stderr_utf8':err.decode('utf-8','strict')}).payload()
