"""Source-authored public regressions. NOT_RUN during preparation."""
import os
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'source_runtime'))
import launch_common as c
import source_runtime_common as s

class Deadline:
    def remaining(self,*args):return 1

@unittest.skipUnless(sys.platform=='linux','Approved Linux runtime required')
class NativePipeTests(unittest.TestCase):
    def fixture(self,raw):
        read,write=os.pipe()
        os.write(write,raw);os.close(write)
        self.addCleanup(os.close,read)
        return read
    def test_complete_frame_is_consumed_once(self):
        body=c.canonical({'message':'fixture'})
        fd=self.fixture(len(body).to_bytes(4,'big')+body)
        self.assertEqual(s.read_frame(fd,Deadline()),{'message':'fixture'})
        with self.assertRaises(RuntimeError):s.read_frame(fd,Deadline())
    def test_second_frame_not_consumed_by_first(self):
        a=c.canonical({'a':1});b=c.canonical({'b':2})
        fd=self.fixture(len(a).to_bytes(4,'big')+a+len(b).to_bytes(4,'big')+b)
        self.assertEqual(s.read_frame(fd,Deadline()),{'a':1})
        self.assertEqual(s.read_frame(fd,Deadline()),{'b':2})
    def test_empty_length_rejected(self):
        with self.assertRaises(RuntimeError):s.read_frame(self.fixture(b'\0'*4),Deadline())
    def test_oversize_header_rejected_before_body(self):
        with self.assertRaises(RuntimeError):s.read_frame(self.fixture((4097).to_bytes(4,'big')),Deadline(),4096)
    def test_truncated_header_rejected(self):
        with self.assertRaises(RuntimeError):s.read_frame(self.fixture(b'\0\0'),Deadline())
    def test_truncated_body_rejected(self):
        with self.assertRaises(RuntimeError):s.read_frame(self.fixture((10).to_bytes(4,'big')+b'{}'),Deadline())
    def test_duplicate_keys_rejected(self):
        body=b'{"x":1,"x":2}'
        with self.assertRaises(RuntimeError):s.read_frame(self.fixture(len(body).to_bytes(4,'big')+body),Deadline())
    def test_noncanonical_body_rejected(self):
        body=b'{ "x":1}'
        with self.assertRaises(RuntimeError):s.read_frame(self.fixture(len(body).to_bytes(4,'big')+body),Deadline())
    def test_frame_writer_has_exact_length_and_bytes(self):
        read,write=os.pipe()
        self.addCleanup(os.close,read);self.addCleanup(os.close,write)
        body={'phase':'prepared'}
        s.write_frame(write,body,Deadline())
        raw=c.canonical(body)
        self.assertEqual(os.read(read,4096),len(raw).to_bytes(4,'big')+raw)
    def test_writer_bound_is_checked_before_send(self):
        with patch.object(os,'write') as write:
            with self.assertRaises(RuntimeError):s.write_frame(1,{'x':'y'*20},Deadline(),4)
            write.assert_not_called()
    @unittest.skipUnless(hasattr(os,'splice'),'Linux splice required')
    def test_signer_payload_opaque_to_controller(self):
        source,writer=os.pipe();target,output=os.pipe()
        self.addCleanup(os.close,target);self.addCleanup(os.close,output)
        body=b'PUBLIC-NEGATIVE-FIXTURE-NOT-A-KEY'
        raw=len(body).to_bytes(4,'big')+body
        os.write(writer,raw);os.close(writer)
        with patch.object(c,'decode',side_effect=AssertionError('Controller decoded signer')):
            s.relay_signer_frame(source,output,Deadline())
        self.assertEqual(os.read(target,4096),raw)
        with self.assertRaises(OSError):os.fstat(source)
    @unittest.skipUnless(hasattr(os,'splice'),'Linux splice required')
    def test_truncated_opaque_signer_rejected(self):
        source,writer=os.pipe();target,output=os.pipe()
        self.addCleanup(os.close,target);self.addCleanup(os.close,output)
        os.write(writer,(12).to_bytes(4,'big')+b'partial');os.close(writer)
        with self.assertRaises(RuntimeError):s.relay_signer_frame(source,output,Deadline())

