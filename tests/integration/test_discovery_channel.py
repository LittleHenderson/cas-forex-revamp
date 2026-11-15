"""Future public protocol regressions; NOT_RUN during source authoring."""
import hashlib
import unittest
from discovery_channel import canonical, discovery_body, parse, validate_release


class DiscoveryChannelTests(unittest.TestCase):
    def body(self):return discovery_body('integration','a'*64,['module.Class.test_one'])
    def ack(self, raw):return canonical({'format':'forex.test-driver-start/1','group_id':'integration',
        'discovery_sha256':hashlib.sha256(raw).hexdigest()})

    def test_exact_ack_binds_exact_collected_bytes(self):
        raw=self.body();validate_release(self.ack(raw),group_id='integration',discovery_raw=raw)

    def test_changed_inventory_cannot_use_previous_ack(self):
        raw=self.body();other=discovery_body('integration','b'*64,['module.Class.test_one'])
        with self.assertRaises(RuntimeError):validate_release(self.ack(raw),group_id='integration',discovery_raw=other)

    def test_group_substitution_cannot_release_tests(self):
        raw=self.body()
        with self.assertRaises(RuntimeError):validate_release(self.ack(raw),group_id='core',discovery_raw=raw)

    def test_duplicate_ids_cannot_hide_missing_test(self):
        with self.assertRaises(RuntimeError):discovery_body('integration','a'*64,['x','x'])

    def test_version_group_requires_empty_inventory(self):
        self.assertEqual(parse(discovery_body('node-version','a'*64,[]))['test_ids'],[])
        with self.assertRaises(RuntimeError):discovery_body('node-version','a'*64,['x'])
        with self.assertRaises(RuntimeError):discovery_body('integration','a'*64,[])

    def test_duplicate_or_noncanonical_json_rejects(self):
        for raw in (b'{"a":1,"a":2}',b'{ "a":1}',b'{"b":1,"a":2}'):
            with self.assertRaises(RuntimeError):parse(raw)

    def test_additional_ack_field_cannot_be_ignored(self):
        raw=self.body();ack=parse(self.ack(raw));ack['pass']=True
        with self.assertRaises(RuntimeError):validate_release(canonical(ack),group_id='integration',discovery_raw=raw)
