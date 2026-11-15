"""Selected role handlers for source-completion endpoints. No server is started.

Call serve_connection only from a separately reviewed launcher with an already
accepted socket. Each role keeps its actual principal, roots and signing port.
"""
import os
import stat
from threading import RLock
from cas_forex_operational_contracts import common, protected as pr, completion as co, method
from .selection_provider import call_none, same
from .protected_registry import ProtectedRegistry
from .completion_transport import closed
from .source_completion import PUBLISH_ROUTES, _pin, _hex, _snapshot, validate_registry_chain

require=common.require


class CurrentSelectionFile:
    """Fresh read of the selected authoritative public register on every call.

    Writer authority and deployment selection appoint this file. A copied
    snapshot is not an allowed substitute. Replacing/withdrawing its identity
    fails closed; this source never repairs or reappoints the register.
    """
    def __init__(self, *, path, device, inode, uid, gid, mode, maximum_bytes,
                 authorizer_public_key, authorizer_public_sha256, verifier, clock, original_deadline):
        common.safe_path(path,absolute=True)
        require(all(type(v) is int and v>=0 for v in (device,inode,uid,gid,mode,maximum_bytes))
                and inode>0 and 0<maximum_bytes<=common.MAX_OBJECT and mode<=0o777 and not mode & 0o022,'CURRENT_REGISTER_SELECTION')
        self.path=path;self.identity=(device,inode,uid,gid,mode);self.maximum=maximum_bytes
        self.key=bytes(authorizer_public_key);self.key_pin=_pin(authorizer_public_sha256)
        require(len(self.key)==32 and common.digest(self.key)==self.key_pin,'CURRENT_REGISTER_AUTHORIZER')
        self.verifier,self.clock=verifier,clock;self.deadline=method.validate('Stamp',original_deadline).payload()

    @staticmethod
    def _identity(info):return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))

    def __call__(self, request):
        require(request['operation']=='CURRENT_SELECTION','CURRENT_REGISTER_OPERATION')
        closed(request['payload'],set(),'CURRENT_REGISTER_PAYLOAD')
        require(os.name=='posix','CURRENT_REGISTER_LINUX')
        now=method.validate('Stamp',self.clock()).payload()
        require(common.utc(now['utc'])<common.utc(self.deadline['utc']) and now['boottime_ns']<self.deadline['boottime_ns'],'CURRENT_REGISTER_DEADLINE')
        directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            parts=self.path.split('/')[1:]
            for segment in parts[:-1]:
                child=os.open(segment,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
                os.close(directory);directory=child
            fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            try:
                before=os.fstat(fd)
                require(self._identity(before)==self.identity and stat.S_ISREG(before.st_mode)
                        and before.st_nlink==1 and 0<before.st_size<=self.maximum,'CURRENT_REGISTER_IDENTITY')
                chunks=[];remaining=before.st_size+1
                while remaining:
                    block=os.read(fd,min(remaining,65536))
                    if not block:break
                    chunks.append(block);remaining-=len(block)
                raw=b''.join(chunks);after=os.fstat(fd)
                named=os.stat(parts[-1],dir_fd=directory,follow_symlinks=False)
                require(len(raw)==before.st_size==after.st_size==named.st_size and self._identity(after)==self._identity(named)==self.identity
                        and before.st_mtime_ns==after.st_mtime_ns==named.st_mtime_ns
                        and before.st_ctime_ns==after.st_ctime_ns==named.st_ctime_ns,'CURRENT_REGISTER_CHANGED')
            finally:os.close(fd)
        finally:os.close(directory)
        value=common.decode_canonical(raw,limit=self.maximum)
        closed(value,{'selection','signature_hex'},'CURRENT_REGISTER_BODY')
        selected=pr.validate('PublisherRootSelection',value['selection']).payload()
        call_none(self.verifier.verify,public_key=self.key,message=pr.selection_signing_bytes(selected),signature=_hex(value['signature_hex'],64))
        require(common.digest(pr.validate('PublisherRootSelection',selected).raw)==request['publisher_selection_sha256'],'CURRENT_REGISTER_SELECTION_CHANGED')
        current=method.validate('Stamp',self.clock()).payload()
        require(common.utc(selected['not_before_utc'])<=common.utc(now['utc'])<=common.utc(current['utc'])
                <min(common.utc(selected['expires_at_utc']),common.utc(self.deadline['utc']))
                and now['boottime_ns']<=current['boottime_ns']<self.deadline['boottime_ns'],'CURRENT_REGISTER_EXPIRED')
        return value


class SourceRegistryHost:
    def __init__(self, *, registry, publishers, maximum_entries, clock):
        require(type(registry) is ProtectedRegistry,'LOCAL_REGISTRY_IMPLEMENTATION')
        self.registry,self.publishers,self.clock=registry,pr.validate('PublisherRootSelection',publishers).payload(),clock
        self.pin=common.digest(pr.validate('PublisherRootSelection',self.publishers).raw)
        require(registry.authority.local_principal_id==self.publishers['registry_authority_id'],'ACTUAL_REGISTRY_PRINCIPAL')
        require(type(maximum_entries) is int and 0<maximum_entries<=4096,'REGISTRY_CHAIN_BOUND');self.maximum=maximum_entries

    def signed_chain(self, registration_sha256, *, selection, now):
        require(same(selection,self.publishers),'REGISTRY_HOST_SELECTION')
        # Reuse the original registry's no-follow, lock, signature and journal
        # validation. Read the exact signed lines; never sign a reminted row.
        with self.registry._locked(selection,now) as fd:
            rows=self.registry._entries(fd,selection,now)
            matches=[i for i,row in enumerate(rows) if common.digest(pr.validate('ProtectedRegistration',row).raw)==registration_sha256]
            require(len(matches)==1 and matches[0]+1<=self.maximum,'REGISTRY_ORIGINAL_PREFIX')
            os.lseek(fd,0,os.SEEK_SET);chunks=[];size=0
            while True:
                chunk=os.read(fd,65536)
                if not chunk:break
                size+=len(chunk);require(size<=common.MAX_GRAPH,'REGISTRY_BOUND');chunks.append(chunk)
            raw=b''.join(chunks);require(raw.endswith(b'\n'),'REGISTRY_INCOMPLETE_TAIL')
            lines=raw.splitlines();require(len(lines)==len(rows),'REGISTRY_PREFIX_CHANGED')
            chain=[pr.decode('RegistrySignature',line).payload() for line in lines[:matches[0]+1]]
            result={'registry_chain':chain}
            validate_registry_chain(result,publishers=selection,authority=self.registry.authority,now=self.registry.authority.current(selection,now),
                maximum_entries=self.maximum,expected_hash=registration_sha256)
            return result

    def __call__(self, request):
        require(request['publisher_selection_sha256']==self.pin,'REGISTRY_HOST_SELECTION')
        payload=request['payload'];now=self.registry.authority.current(self.publishers,self.clock())
        if request['operation']=='READ_REGISTRATION':
            closed(payload,{'registration_sha256'},'REGISTRY_READ_REQUEST');digest=_pin(payload['registration_sha256'])
        else:
            require(request['operation']=='REGISTER_EXACT_RECORD','REGISTRY_HOST_OPERATION')
            closed(payload,{'record_hex','reference','publisher_envelope'},'REGISTRY_WRITE_REQUEST')
            reference=pr.validate('ProtectedRecordRef',payload['reference']).payload()
            self.registry.authority.check_grant(reference,self.publishers,now,required_use='SOURCE_COMPLETION')
            row=self.registry.register_exact_record(_hex(payload['record_hex']),reference,payload['publisher_envelope'],selection=self.publishers,now=now)
            digest=common.digest(pr.validate('ProtectedRegistration',row).raw)
        return self.signed_chain(digest,selection=self.publishers,now=now)


class SourcePublisherHost:
    def __init__(self, *, authority, files, registry, resolver, publishers, publisher_id,
                 signer, routes, expires_at_utc, clock, completion_bindings=None):
        self.authority,self.files,self.registry,self.resolver=authority,files,registry,resolver
        self.publishers=pr.validate('PublisherRootSelection',publishers).payload();self.publisher_id=publisher_id
        self.pin=common.digest(pr.validate('PublisherRootSelection',self.publishers).raw)
        require(authority.local_principal_id==publisher_id,'ACTUAL_PUBLISHER_PRINCIPAL')
        selected=[p for p in self.publishers['publishers'] if p['publisher_id']==publisher_id]
        require(len(selected)==1 and selected[0]['role'] in {'CUSTODY','COMPLETION_OBSERVER'},'SOURCE_PUBLISHER_ROLE')
        self.role=selected[0]['role'];self.signer=signer;self.clock=clock;self.expiry=expires_at_utc
        common.utc(expires_at_utc);self.routes={}
        for row in routes:
            closed(row,{'record_kind','purpose','format','root_id','schema_sha256'},'SOURCE_PUBLISHER_ROUTE')
            require(PUBLISH_ROUTES.get(row['record_kind'])==(row['purpose'],self.role),'SOURCE_PUBLISHER_ROUTE')
            key=(row['record_kind'],row['purpose'],row['format']);require(key not in self.routes,'SOURCE_PUBLISHER_ROUTE_DUPLICATE')
            self.routes[key]=_snapshot(row)
        self.completion_bindings=completion_bindings
        self._lock=RLock();self._attempted=set();self._published={};self._failed=False

    def __call__(self, request):
        require(request['operation']=='PUBLISH' and request['publisher_selection_sha256']==self.pin,'SOURCE_PUBLISH_REQUEST')
        payload=request['payload'];closed(payload,{'record_hex','record_kind','purpose'},'SOURCE_PUBLISH_PAYLOAD')
        raw=_hex(payload['record_hex']);value=common.decode_canonical(raw)
        require(type(value) is dict and type(value.get('format')) is str,'SOURCE_PUBLISH_BODY')
        kind,purpose=payload['record_kind'],payload['purpose'];route=self.routes.get((kind,purpose,value['format']))
        require(route is not None,'SOURCE_PUBLISH_ROUTE_UNSELECTED')
        identity=(kind,purpose,common.digest(raw))
        with self._lock:
            require(not self._failed,'SOURCE_PUBLISHER_UNAVAILABLE')
            if identity in self._published:
                use=self._published[identity]
                require(self.resolver.resolve(use,selection=self.publishers,now=self.clock())==raw,'ORIGINAL_PUBLICATION_READBACK')
                result=self.registry.signed_chain(use['registration_sha256'],selection=self.publishers,now=self.clock())
                return {'use':_snapshot(use),'registry_chain':result['registry_chain']}
            require(identity not in self._attempted,'SOURCE_PUBLICATION_ALREADY_ATTEMPTED');self._attempted.add(identity)
            try:
                now=self.authority.current(self.publishers,self.clock())
                reference={'format':'forex.protected-record-ref/1','binding':self.publishers['binding'],'publisher_selection_sha256':self.pin,
                    'root_id':route['root_id'],'object_id':common.digest(raw),'bytes':len(raw),'sha256':common.digest(raw),
                    'record_kind':kind,'publisher_id':self.publisher_id,'purpose':purpose}
                root,publisher,grant,now=self.authority.check_grant(reference,self.publishers,now,required_use='SOURCE_COMPLETION')
                require(grant['payload_schema_sha256']==route['schema_sha256'],'SOURCE_PUBLISH_SCHEMA')
                self.authority.validate_payload(raw,grant)
                require(value.get('binding',self.publishers['binding'])==self.publishers['binding'],'SOURCE_PUBLISH_BINDING')
                if kind=='SOURCE_TEST_COMPLETION':
                    require(self.completion_bindings is not None,'INDEPENDENT_COMPLETION_REQUIRED')
                    receipt=co.decode('CompletionReceipt2',raw).payload()
                    verified=self.completion_bindings.verify_completion(receipt['original_source_test_report'],receipt['observation_evidence'],now=now)
                    require(verified==raw,'INDEPENDENT_COMPLETION_SUBSTITUTION')
                require(common.utc(now['utc'])<common.utc(self.expiry)<=min(common.utc(publisher['expires_at_utc']),
                        common.utc(self.publishers['expires_at_utc']),common.utc(self.authority.deadline['utc'])),'SOURCE_ATTESTATION_EXPIRY')
                body={'format':'forex.protected-record-attestation/1','record_ref':reference,
                    'attestation_id':'source-'+common.digest(pr.validate('ProtectedRecordRef',reference).raw),
                    'publisher_id':self.publisher_id,'purpose':purpose,'issued_at_utc':now['utc'],'expires_at_utc':self.expiry}
                signature=self.signer.sign(domain=pr.RECORD_DOMAIN,canonical_body=pr.validate('ProtectedAttestationBody',body).raw)
                require(type(signature) is bytes and len(signature)==64,'SOURCE_PUBLISH_SIGNATURE')
                envelope={'body':body,'algorithm':'Ed25519','signer_sha256':publisher['signer_public_sha256'],'signature_hex':signature.hex()}
                self.authority.attest(reference,envelope,self.publishers,self.clock())
                envelope_raw=pr.validate('ProtectedRecordEnvelope',envelope).raw
                att={**reference,'object_id':common.digest(envelope_raw),'sha256':common.digest(envelope_raw),'bytes':len(envelope_raw),
                    'record_kind':'RECORD_ATTESTATION','purpose':'record-attestation'}
                att_root,_,_,now=self.authority.check_grant(att,self.publishers,self.clock(),required_use='AUTHORITY_METADATA')
                self.files.retain_exact(reference,raw,root,self.publishers,now)
                self.files.retain_exact(att,envelope_raw,att_root,self.publishers,self.clock())
                row=self.registry.register_exact_record(raw,reference,envelope,selection=self.publishers,now=self.clock())
                use={'reference':reference,'registration_sha256':common.digest(pr.validate('ProtectedRegistration',row).raw),'required_use':'SOURCE_COMPLETION'}
                require(self.resolver.resolve(use,selection=self.publishers,now=self.clock())==raw,'SOURCE_PUBLISH_READBACK')
                chain=self.registry.signed_chain(use['registration_sha256'],selection=self.publishers,now=self.clock())
                self._published[identity]=_snapshot(use)
                return {'use':use,'registry_chain':chain['registry_chain']}
            except BaseException:
                # No retry, rollback, deletion or timestamp remint after an
                # uncertain write/sign/registration. Originals remain retained.
                self._failed=True;raise
