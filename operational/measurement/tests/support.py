"""PUBLIC_SYNTHETIC_UNIT_PREMISES. No signature or observation authority."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from cas_forex_operational_contracts.common import canonical_bytes,digest


def stamp(seconds=1):
    date=datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(seconds=seconds)
    return {'utc':date.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),'boottime_ns':1_000_000_000+seconds*1_000_000_000}


def reference(raw=b'public premise',kind='AUTHENTICATED_INTERVAL'):
    return {'object_id':digest(raw),'bytes':len(raw),'sha256':digest(raw),'artifact_kind':kind}


def budget():
    scope={'method_id':'POLICY_INHERITANCE_TRUSTED_ADAPTER_V1','method_spec_sha256':'a'*64,
        'source_manifest_sha256':'b'*64,'config_sha256':'c'*64,'topology_sha256':'d'*64,
        'run_id':'public-unit-run','epoch':1,'original_window_sha256':'e'*64,'setup_identity':'public-unit-setup'}
    return {'format':'forex.policy-inheritance-setup-budget/3','binding':{'scope':scope,'appointment_sha256':'f'*64},
        'budget_id':'public-budget','issuer_id':'public-issuer','clock_domain':{'boot_id':'00000000-0000-4000-8000-000000000001','time_namespace_inode':1,'clock_id':'CLOCK_BOOTTIME'},
        'started':stamp(0),'deadline':stamp(180),'outer_deadline':stamp(220),'maximum_seconds':180,
        'coverage_plan_sha256':'0'*64,'appointment_interval_ref':reference()}


class PublicClock:
    def __init__(self):self.value=stamp();self.clock_domain=budget()['clock_domain'];self.calls=0
    def stamp(self):self.calls+=1;return deepcopy(self.value)
    def domain(self):self.calls+=1;return deepcopy(self.clock_domain)


class PublicMemorySink:
    def __init__(self):self.values={}
    def retain(self,raw,*,artifact_kind):
        ref=reference(raw,artifact_kind);self.values[ref['sha256']]=raw;return ref
    def readback(self,ref):return self.values[ref['sha256']]
