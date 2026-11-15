"""Public byte controls only. No sockets, forks, secrets or real evidence."""
import hashlib
import hmac
import struct
import unittest
from cas_forex_operational_contracts.common import canonical_bytes,decode_canonical,ContractError
from cas_forex_measurement.calibration import public_fixture_key,public_packet,KINDS
from cas_forex_measurement.inventory import parse_stat


class PublicCalibrationTests(unittest.TestCase):
    def packet(self,kind):
        fixture=canonical_bytes({'case_kind':kind,'public_only':True});key=public_fixture_key(fixture,'public-case-key')
        app,frame=public_packet(key=key,channel_id='public-channel',value={'public':True},kind=kind)
        return key,app,frame
    def test_private_fixture_marker_is_rejected(self):
        with self.assertRaises(ContractError):public_fixture_key(canonical_bytes({'case_kind':'BAD_MAC','public_only':False}),'public-key')
    def test_public_fixture_unknown_fields_rejected(self):
        with self.assertRaises(ContractError):public_fixture_key(canonical_bytes({'case_kind':'BAD_MAC','public_only':True,'success':True}),'public-key')
    def test_bad_mac_changes_only_mac_check(self):
        key,app,frame=self.packet('BAD_MAC');packet=decode_canonical(app)
        self.assertNotEqual(packet['mac'],hmac.new(key,canonical_bytes(packet['body']),hashlib.sha256).hexdigest())
        self.assertEqual(struct.unpack('!II',frame[:8]),(len(app),0))
        self.assertEqual(packet['body']['channel_id'],'public-channel')
    def test_bad_frame_keeps_valid_packet_mac(self):
        key,app,frame=self.packet('BAD_FRAME');packet=decode_canonical(app)
        self.assertEqual(packet['mac'],hmac.new(key,canonical_bytes(packet['body']),hashlib.sha256).hexdigest())
        self.assertEqual(struct.unpack('!II',frame[:8]),(len(app),1))
    def test_bad_channel_keeps_valid_mac(self):
        key,app,_=self.packet('BAD_CHANNEL_ID');packet=decode_canonical(app)
        self.assertEqual(packet['mac'],hmac.new(key,canonical_bytes(packet['body']),hashlib.sha256).hexdigest())
        self.assertNotEqual(packet['body']['channel_id'],'public-channel')
    def test_replay_fixture_is_exactly_repeatable(self):
        self.assertEqual(self.packet('BAD_SEQUENCE'),self.packet('BAD_SEQUENCE'))
    def test_stat_parser_handles_parentheses_in_name(self):
        fields=['S','1']+['0']*17+['99']+['0']*3
        self.assertEqual(parse_stat(('2 (public ) name) '+' '.join(fields)).encode())['start_ticks'],99)
    def test_truncated_stat_rejected(self):
        with self.assertRaises(ContractError):parse_stat(b'2 (x) S 1')
