"""Protected-root external observer/issuer adapter. Never creates approval.

Configuration pins the producer and exact record locations before role setup.
An external trusted producer can publish those read-only visible records after
observing the newly created roles; the application cannot write them. A config
hash is checked by the freeze record, avoiding a self-referential hash cycle.
"""
from datetime import datetime
from hashlib import sha256
import json
import time
from pathlib import Path

from model_guest_boundary import load, need, regular, read_record


def selected_record(path, base):
    target=regular(path,base,readonly=True,root_owned=True)
    need(0<target.stat().st_size<=4194304,'bounded protected external record required')
    raw=target.read_bytes()
    return load(raw),sha256(raw).hexdigest()


def verify_role_access(observed, roles, expected_targets, read_receipt):
    """Require denial on each protected target, independently of public probes.

    All inputs still require the external authenticated observer binding checked
    by consume_external_release. This helper creates no observation or approval.
    """
    operations={'OPEN_READ_WITHOUT_READING','PROC_MEM_OPEN','PROC_FD_ACCESS','PROC_ROOT_ACCESS',
                'SIBLING_STATE_OPEN','UNAUTHORIZED_CHANNEL_PEER'}
    declared=observed['actual_private_target_sha256']
    need(type(declared) is list and declared and all(type(v) is str and len(v)==64
         and all(c in '0123456789abcdef' for c in v) for v in declared)
         and len(declared)==len(set(declared)), 'exact unique protected target digests required')
    protected=set(declared)
    need(expected_targets<=protected,'probe targets are not actual custody bindings')
    for role in ('DECISION_RUNNER','MODEL_SERVICE'):
        rows=[r for r in observed['access_probes'] if r['role']==role]
        denied_operations=set();denied_targets=set();public_read=False
        for row in rows:
            denied=(row['expected']=='DENY' and row['actual']=='DENY'
                    and type(row['errno']) is int and row['errno'] in (1,13))
            need(row['pid']==roles[role]['pid'] and row['start_ticks']==roles[role]['start_ticks']
                 and row['target_exists'] is True and row['expected'] in ('DENY','ALLOW')
                 and row['actual']==row['expected']
                 and (row['expected']!='DENY' or denied),'actual role denial unavailable')
            # An ALLOW cannot be hidden by an additional DENY for the same target
            # or by unrelated denied operations. Missing files are never denial.
            if row['target_sha256'] in protected:
                need(denied,'successful or unproven protected-target access')
            if denied:
                denied_operations.add(row['operation'])
                if row['operation']=='OPEN_READ_WITHOUT_READING':
                    denied_targets.add(row['target_sha256'])
            if (row['operation']=='OPEN_READ_WITHOUT_READING' and row['target_sha256'] not in protected
                    and row['expected']=='ALLOW' and row['actual']=='ALLOW'):
                public_read=True
            read_receipt(row['raw_receipt'])
        need(operations<=denied_operations,'required deny probes missing')
        need(protected<=denied_targets,'actual protected targets lack observed denied reads')
        need(public_read,'intended allowed public-read observation missing')
    return True


def consume_external_release(*,cfg,out,window,roles,setup,clock,journal,scope):
    from cas_forex_revamp.contracts import content_digest
    from cas_forex_revamp.composition.custody_protocol import validate_release,ReleaseLedger,contract
    from role_boundary import identity
    selected=cfg['isolation'];base=Path(cfg['source_directory']).parent
    need(set(selected)=={'channel_id','issuer_binding_sha256','observer_binding_sha256',
        'authority_path','release_path','probe_paths','boot_id'},'exact external role/issuer configuration required')
    private_paths={cfg['evidence'][k]['path'] for k in ('suite','keys','schedules','counterparts','predicates')}
    need(type(selected['probe_paths']) is list and private_paths<=set(selected['probe_paths'])
         and len(selected['probe_paths'])==len(set(selected['probe_paths']))<=32,
         'probe configuration must include every actual sealed target')
    # Actual external observation follows role setup. This bounded wait shares
    # the original model window; it does not manufacture a ready flag or clock.
    wait_until=min(time.monotonic()+180,time.monotonic()+(window.end-clock()).total_seconds())
    while not (Path(selected['authority_path']).is_file() and Path(selected['release_path']).is_file()):
        window.require_remaining(0)
        need(time.monotonic()<wait_until,'external role observation/release unavailable')
        time.sleep(.1)
    authority,authority_hash=selected_record(selected['authority_path'],base)
    need(authority.get('format')=='forex.external-custody-authority/1'
         and authority['config_sha256']==cfg['_verified_config_sha256']
         and authority['issuer_binding_sha256']==selected['issuer_binding_sha256']
         and authority['observer_binding_sha256']==selected['observer_binding_sha256']
         and authority['run_id']==cfg['run_id'],'external authority/config binding differs')
    references=authority['references']
    expected=authority['expected_release_bindings']
    required={name for name,kind in contract('release')['required_receipt_fields'].items() if kind=='sha256'}
    need(set(references)==required and set(expected)==required|{'run_id','epoch','scope_sha256'},'complete independently selected release references required')
    resolved={}
    for name,row in references.items():
        need(row['sha256']==expected[name],'external reference pin differs')
        resolved[name]=read_record(row,base)
    need(expected['separate_execution_authorization_sha256']==cfg['evidence']['authorization']['sha256']
         and expected['accepted_private_mapping_sha256']==cfg['evidence']['case_review']['sha256']
         and expected['independent_review_attestation_sha256']==cfg['evidence']['source_review']['sha256'],
         'release refers to another execution or review')
    proof_bindings=resolved['stop_egress_deadline_proofs_sha256']
    need(proof_bindings['stop_proof_sha256']==cfg['evidence']['stop_proof']['sha256']
         and proof_bindings['egress_sha256']==cfg['evidence']['egress']['sha256']
         and proof_bindings['work_deadline_utc']==cfg['work_deadline_utc'],'release stop/egress/deadline proof differs')
    clocks=resolved['original_clock_and_budget_binding_sha256']
    need(clocks['model_window']==window.record() and clocks['model_calls']==32 and clocks['retry_calls']==0
         and clocks['bootstrap_started_utc']==cfg['bootstrap_started_utc']
         and clocks['test_deadline_utc']==cfg['test_deadline_utc'],'release resets original clock/budget')
    # Every reference is actual protected-root bytes, not an unbound label.
    need(expected['run_id']==cfg['run_id'] and expected['issuer_binding_sha256']==selected['issuer_binding_sha256']
         and expected['trusted_observer_binding_sha256']==selected['observer_binding_sha256'],'issuer/observer substituted')
    freeze=resolved['complete_freeze_manifest_sha256']
    need(freeze['config_sha256']==cfg['_verified_config_sha256']
         and freeze['source_manifest_sha256']==cfg['source_manifest_sha256']
         and freeze['asset_manifest_sha256']==cfg['asset_manifest_sha256']
         and set(freeze['bound_components'])==set(contract('release')['complete_freeze_manifest_must_bind'])
         and all(type(v) is str and len(v)==64 for v in freeze['bound_components'].values()),'complete tuning freeze unavailable')
    for component,row in freeze['component_records'].items():
        need(component in freeze['bound_components'] and row['sha256']==freeze['bound_components'][component], 'freeze component differs')
        read_record(row,base)
    need(set(freeze['component_records'])==set(freeze['bound_components']),'freeze component unresolved')
    observed=resolved['role_read_isolation_receipt_sha256']
    need(observed['format']=='forex.observed-role-read-isolation/1'
         and observed['observer_binding_sha256']==selected['observer_binding_sha256']
         and observed['run_id']==cfg['run_id'] and observed['roles']==roles
         and observed['source_manifest_sha256']==cfg['source_manifest_sha256']
         and observed['config_sha256']==cfg['_verified_config_sha256']
         and observed['role_setup_sha256']==content_digest(setup)
         and observed['channel_id']==selected['channel_id'],'actual independently observed roles differ')
    need(observed['boot_id']==selected['boot_id'] and all(r['boot_id']==observed['boot_id'] for r in roles.values()),
         'external boot identity differs')
    now=clock()
    need(datetime.fromisoformat(observed['observed_at_utc'].replace('Z','+00:00'))<=now
         <datetime.fromisoformat(observed['expires_at_utc'].replace('Z','+00:00'))<=window.end,'observer receipt expired')
    private_inventory=read_record(observed['private_target_inventory'],base)
    need(private_paths<={r['path'] for r in private_inventory['targets'] if r['exists'] is True},
         'independent probe inventory omits actual sealed inputs')
    expected_targets={content_digest({'path':cfg['evidence'][k]['path'],'sha256':cfg['evidence'][k]['sha256']})
                      for k in ('suite','keys','schedules','counterparts','predicates')}
    verify_role_access(observed,roles,expected_targets,lambda row:read_record(row,base))
    need(observed['actual_private_target_sha256'] and observed['sentinel_inventory_verified'] is True
         and observed['descriptor_inventory_verified'] is True and observed['mount_inventory_verified'] is True,
         'sentinels/descriptors/mount evidence missing')
    for name in ('mount_inventory','descriptor_inventory','channel_peer_inventory','private_target_inventory'):
        read_record(observed[name],base)
    for role,record in roles.items():
        need(identity(record['pid'])['start_ticks']==record['start_ticks'],'observed process changed before release')
    receipt,raw_hash=selected_record(selected['release_path'],base)
    validate_release(receipt,expected=expected,now=clock(),deadline=window.end)
    ledger=ReleaseLedger(Path(out)/'release.custody.sqlite3');ledger.initialize();ledger.consume(receipt)
    journal.append('custody-release-consumed','CUSTODY_RELEASE_CONSUMED',scope,
        {'release_raw_sha256':raw_hash,'release_canonical_sha256':content_digest(receipt),
         'authority_sha256':authority_hash,'role_observer_sha256':expected['role_read_isolation_receipt_sha256']},now=clock())
    binding={k:receipt[k] for k in ('run_id','epoch','scope_sha256','expires_at_utc')}
    binding.update(channel_id=selected['channel_id'],release_receipt_sha256=raw_hash)
    return binding,receipt
