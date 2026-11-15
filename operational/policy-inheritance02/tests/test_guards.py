import copy
import unittest

from policy_inheritance.contract import canonical_bytes, digest
from policy_inheritance.errors import ContractViolation
from policy_inheritance.guards import GuardModel, PublicGuardSample
from support import Fixture, h, stamp


class GuardTests(unittest.TestCase):
    def setUp(self):self.f=Fixture()
    def guard(self):
        return GuardModel(self.f.contract,self.f.appointment,self.f.budget,selected_scope=self.f.scope,
                          plan_sha256=digest(canonical_bytes(self.f.plan)))
    def sample(self,t,*,interval=None,domain=None,now=None):
        return PublicGuardSample(canonical_bytes(stamp(t) if now is None else now),
                                 canonical_bytes(self.f.clock_domain if domain is None else domain),
                                 canonical_bytes(self.f.interval(t) if interval is None else interval))
    def test_full_interval_valid(self):self.guard().check(self.f.sample(10))
    def test_setup_boundary_has_no_grace(self):
        with self.assertRaises(ContractViolation) as c:self.guard().check(self.f.sample(180))
        self.assertEqual(c.exception.code,"SETUP_DEADLINE_EXPIRED")
    def test_utc_and_boot_deadlines_both_apply(self):
        now=stamp(179);now["boottime_ns"]=stamp(180)["boottime_ns"]
        interval=self.f.interval(179);interval["validated_at"]=now
        with self.assertRaises(ContractViolation):self.guard().check(self.sample(179,interval=interval,now=now))
    def test_boot_clock_cannot_go_backwards(self):
        with self.assertRaises(ContractViolation) as c:self.guard().check(self.f.sample(10),previous_ns=stamp(11)["boottime_ns"])
        self.assertEqual(c.exception.code,"CLOCK_DRIFT")
    def test_clock_discrepancy_cannot_add_time(self):
        now=stamp(10);now["boottime_ns"]=stamp(13)["boottime_ns"]
        interval=self.f.interval(10);interval["validated_at"]=now
        with self.assertRaises(ContractViolation) as c:self.guard().check(self.sample(10,interval=interval,now=now))
        self.assertEqual(c.exception.code,"CLOCK_DRIFT")
    def test_time_namespace_mismatch_rejected(self):
        domain=copy.deepcopy(self.f.clock_domain);domain["time_namespace_inode"]+=1
        with self.assertRaises(ContractViolation):self.guard().check(self.sample(10,domain=domain))
    def test_cached_authority_read_is_not_current(self):
        with self.assertRaises(ContractViolation):self.guard().check(self.sample(10,interval=self.f.interval(9)))
    def test_short_authority_does_not_shorten_budget(self):
        interval=self.f.interval(10);interval["expires_at_utc"]=stamp(170)["utc"]
        with self.assertRaises(ContractViolation) as c:self.guard().check(self.sample(10,interval=interval))
        self.assertEqual(c.exception.code,"APPOINTMENT_INTERVAL_INSUFFICIENT")
    def test_expired_dependency_rejected(self):
        with self.assertRaises(ContractViolation) as c:self.guard().check(self.f.sample(10),dependency_expiries=(stamp(10),))
        self.assertEqual(c.exception.code,"AUTHENTICATED_INTERVAL_EXPIRED")
    def test_original_deadline_cannot_be_extended(self):
        self.f.budget["deadline"]=stamp(181)
        with self.assertRaises(ContractViolation) as c:self.guard()
        self.assertEqual(c.exception.code,"BUDGET_RESET_ATTEMPT")
    def test_principal_keys_roles_and_roots_are_distinct(self):
        self.f.appointment["principals"][1]["signer_public_sha256"]=self.f.appointment["principals"][0]["signer_public_sha256"]
        self.f.binding["appointment_sha256"]=digest(canonical_bytes(self.f.appointment))
        with self.assertRaises(ContractViolation):self.guard()
    def test_unselected_signer_and_wrong_purpose_rejected(self):
        g=self.guard();body=self.f.budget
        envelope=self.f.envelope(body,"consumer","policy-inheritance-setup-budget-v2",2,"shape-budget",is_budget=True)
        envelope["signer_sha256"]=h("unselected")
        with self.assertRaises(ContractViolation):g.envelope_shape(canonical_bytes(body),envelope,purpose="policy-inheritance-setup-budget-v2",
            producer_id="consumer",sample=self.f.sample(2),recorded=stamp(0),is_budget=True)
    def test_envelope_hash_binds_exact_bytes(self):
        g=self.guard();envelope=self.f.envelope(self.f.budget,"consumer","policy-inheritance-setup-budget-v2",2,"shape-budget",is_budget=True)
        envelope["body"]["record_sha256"]=h("other")
        with self.assertRaises(ContractViolation):g.envelope_shape(canonical_bytes(self.f.budget),envelope,purpose="policy-inheritance-setup-budget-v2",
            producer_id="consumer",sample=self.f.sample(2),recorded=stamp(0),is_budget=True)
    def test_future_issued_attestation_rejected(self):
        g=self.guard();env=self.f.envelope(self.f.budget,"consumer","policy-inheritance-setup-budget-v2",3,"future",is_budget=True)
        with self.assertRaises(ContractViolation):g.envelope_shape(canonical_bytes(self.f.budget),env,purpose="policy-inheritance-setup-budget-v2",
            producer_id="consumer",sample=self.f.sample(2),recorded=stamp(0),is_budget=True)
    def test_invalid_signature_is_not_authenticated_by_shape_check(self):
        # A shape check is intentionally not proof. The actual verifier rejects.
        from policy_inheritance.operational import OperationalAdapters
        from policy_inheritance.errors import UnsupportedAuthority
        env=self.f.envelope(self.f.budget,"consumer","policy-inheritance-setup-budget-v2",2,"shape-only",is_budget=True)
        with self.assertRaises(UnsupportedAuthority):OperationalAdapters().verify_ed25519(env)
