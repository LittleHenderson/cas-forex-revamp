"""Explicit four-role source-completion service. No listener or signer on import."""
import argparse
import os
from pathlib import Path
import select
import socket
import stat
import sys

def validate_prepared_objects(published, s, c):
    """Read-only validation: root prepared SGID before releasing this role."""
    objects=s.directory_identity(published['path']+'/objects')
    c.need(objects['device']==published['device'] and objects['inode']>0
        and objects['uid']==published['uid'] and objects['gid']==published['gid']
        and objects['mode']==0o2750,'Root-prepared objects directory differs')
    return objects

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument('--role',required=True,choices=('current','registry','observer','custody'))
    parser.add_argument('--startup',required=True);parser.add_argument('--startup-sha256',required=True)
    args=parser.parse_args(argv)
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    import launch_common as c
    import source_runtime_common as s
    c.need(sys.platform=='linux' and sys.version_info[:2]==(3,12) and os.getuid()==os.geteuid()>0,
           'Non-root selected Python3.12 role')
    c.need(os.path.samefile('/proc/self/exe','/usr/bin/python3.12'),'Actual role Python differs')
    raw,_=c.read_protected(args.startup);c.need(c.digest(raw)==args.startup_sha256,'Startup pin')
    startup=c.decode(raw)
    s.closed(startup,{'format','role','source_selection','controller','test_deadline_utc',
        'reader_group_gid','unit','source_runtime_files'},'Role startup')
    c.need(startup['format']=='forex.source-role-startup/1' and startup['role']==args.role,
           'Selected role')
    for record in startup['source_runtime_files']:c.pinned(record)
    selected=c.decode(c.pinned(startup['source_selection'])[0])
    s.load_source(selected)
    from source_test_bootstrap import observe_current_user_namespace
    namespace=observe_current_user_namespace()
    deadline=c.Deadline(startup['test_deadline_utc'])
    c.need(c.process_identity(startup['controller']['pid'])==startup['controller']
           and startup['controller']['uid']==0,'Controller unavailable')
    c.need(startup['reader_group_gid'] in os.getgroups(),'Reader group absent')
    c.need(set(os.listdir('/sys/class/net'))=={'lo'},'Role network isolation')
    status=Path('/proc/self/status').read_text()
    c.need('NoNewPrivs:\t1' in status,'No new privileges required')
    for line in status.splitlines():
        if line.startswith(('CapEff:','CapPrm:','CapAmb:','CapBnd:')):
            c.need(int(line.split()[1],16)==0,'Role capabilities')
    state=os.environ['STATE_DIRECTORY']
    c.need(state=='/var/lib/'+startup['unit'],'Fixed role state')
    actual=str(Path(state).resolve(strict=True))
    c.need(actual in {state,'/var/lib/private/'+startup['unit']},'Systemd state alias')
    st=s.directory_identity(actual)
    c.need(st['uid']==os.getuid() and st['gid']==os.getgid() and st['mode']==0o700,'Private role state')
    who=s.public_identity()
    s.write_frame(1,{'format':'forex.source-role-parked/1','role':args.role,
        'process':who,'state':st,'namespace':namespace,'clock_domain':deadline.domain,
        'clock_anchor_stamp':deadline.anchor},deadline)
    prepare=s.read_frame(0,deadline)
    s.closed(prepare,{'format','socket_parent','published_root'},'Prepare role')
    c.need(prepare['format']=='forex.source-role-prepare/1','Prepare phase')
    parent=prepare['socket_parent'];published=prepare['published_root']
    c.need(parent['path']==s.IPC+'/'+args.role and parent['uid']==who['uid']
        and parent['gid']==startup['reader_group_gid'] and parent['mode']==0o2750
        and s.directory_identity(parent['path'])==parent,'Socket parent binding')
    c.need(published['path']==s.IPC+'/'+args.role+'-records'
        and published['uid']==who['uid'] and published['gid']==startup['reader_group_gid']
        and published['mode']==0o2750 and s.directory_identity(published['path'])==published,
        'Published root binding')
    validate_prepared_objects(published,s,c)
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    secret=None
    try:
        path=parent['path']+'/rpc.sock'
        c.need(not os.path.lexists(path),'Preexisting listener')
        listener.bind(path);os.chmod(path,0o660);listener.listen(8);listener.setblocking(False)
        prepared={'format':'forex.source-role-prepared/1','role':args.role,'process':who,
                  'endpoint':s.endpoint(path,who),'published_root':published,
                  'clock_domain':deadline.domain,'clock_anchor_stamp':deadline.anchor}
        s.write_frame(1,prepared,deadline)
        arm=s.read_frame(0,deadline)
        s.closed(arm,{'format','config'},'Arm role')
        c.need(arm['format']=='forex.source-role-arm/1','Arm phase')
        config_raw,_=c.pinned(arm['config']);config=c.decode(config_raw)
        s.closed(config,s.ROLE_FIELDS,'Role config')
        c.need(config['format']=='forex.source-role-binding/1' and config['role']==args.role
            and config['controller']==startup['controller']
            and config['prepared_sha256']==c.digest(c.canonical(prepared))
            and config['source_selection']==startup['source_selection']
            and config['test_deadline_utc']==startup['test_deadline_utc']
            and config['clock_domain']==deadline.domain,'Role binding')
        c.need(config['client_config'][args.role+'_endpoint']==prepared['endpoint'],'Own endpoint changed')
        c.need(observe_current_user_namespace()==namespace,'Role namespace changed')
        keys=s.fixed_keys(config['public_keys'])
        s.bind_principal(config,prepared,keys)
        from cas_forex_operational_contracts import protected as pr
        signer=None
        if args.role!='current':
            delivered=s.read_frame(0,deadline,4096)
            domain=pr.REGISTRATION_DOMAIN if args.role=='registry' else pr.RECORD_DOMAIN
            signer,secret=s.signer_from_frame(delivered,config['signer_public_sha256'],keys,domain)
        else:c.need(config['signer_public_sha256'] is None,'Current role has no signer')
        ports=s.make_ports(config,config_raw,arm['config'],deadline,signer)
        authority,files,registry,resolver,publishers,clock,base,current=ports
        from custody_runtime.completion_hosts import SourceRegistryHost,SourcePublisherHost
        from custody_runtime.completion_transport import serve_connection
        if args.role=='current':handler=current
        elif args.role=='registry':
            registry.initialize_registry(selection=publishers,now=clock())
            handler=SourceRegistryHost(registry=registry,publishers=publishers,maximum_entries=4096,clock=clock)
        else:
            bindings=None
            if args.role=='observer':
                from custody_runtime.source_completion import bind_source_completion
                bindings=bind_source_completion(config=config['client_config'],public_keys=keys,
                    clock=clock,original_deadline=s.paired_deadline(deadline),base_execution_gate=base,
                    source_manifest_raw=c.pinned(config['source_manifest'])[0],
                    completion_material_raw=c.pinned(config['completion_material'])[0],
                    completion_selection_raw=c.pinned(config['completion_selection'])[0],
                    selection_use=config['selection_use'])
            handler=SourcePublisherHost(authority=authority,files=files,registry=registry,
                resolver=resolver,publishers=publishers,publisher_id=config['client_config']['local_principal_id'],
                signer=signer,routes=config['publish_routes'],expires_at_utc=publishers['expires_at_utc'],
                clock=clock,completion_bindings=bindings)
        authority.current(publishers,clock())
        s.write_frame(1,{'format':'forex.source-role-armed/1','role':args.role,
            'config_sha256':c.digest(config_raw),'prepared_sha256':config['prepared_sha256']},deadline)
        while True:
            base()
            ready,_,_=select.select([listener,0],[],[],min(.2,deadline.remaining()))
            if 0 in ready:
                stop=s.read_frame(0,deadline,4096)
                c.need(stop=={'format':'forex.source-role-stop/1'},'Unexpected lifecycle request')
                return 0
            if listener in ready:
                connection,_=listener.accept()
                try:
                    peer=s.authenticate_peer(connection,config['peers'])
                    def dispatch(request):
                        c.need(request['operation'] in peer['operations'],'Peer operation not selected')
                        base()
                        return handler(request)
                    serve_connection(connection,peer=peer['selection'],clock=clock,
                        original_deadline=s.paired_deadline(deadline),handler=dispatch)
                finally:connection.close()
    finally:
        listener.close()
        if secret is not None:secret[:]=b'\0'*len(secret)
        # Socket and durable records remain retained; supervisor owns termination.
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print('{"status":"INCOMPLETE","component":"source-role"}',file=sys.stderr)
        raise SystemExit(1)

