"""Authored Linux ancillary/framing checks with public fakes. NOT_RUN."""
import array
import socket
import struct
from unittest import TestCase,skipUnless
from unittest.mock import patch
from types import SimpleNamespace
from cas_forex_operational_contracts import checkpoint as ck
from cas_forex_authority.authentication import AuthorityError
from cas_forex_authority.checkpoint_service import CredentialFramer
from support import process


@skipUnless(hasattr(socket,"SCM_CREDENTIALS"),"Linux ancillary ABI required")
class AncillaryTests(TestCase):
    def setUp(self):self.peer=process("SETUP_CONSUMER",20,1001)
    def creds(self,pid=20):return (socket.SOL_SOCKET,socket.SCM_CREDENTIALS,struct.pack("3i",pid,1001,1001))

    def test_exact_one_credential_is_required(self):
        CredentialFramer._ancillary([self.creds()],0,self.peer)
        for rows in ([],[self.creds(),self.creds()],[self.creds(21)]):
            with self.assertRaises(AuthorityError):CredentialFramer._ancillary(rows,0,self.peer)

    def test_delivered_rights_closed_before_rejection(self):
        rights=(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[40,41]).tobytes())
        with patch("cas_forex_authority.checkpoint_service.os.close") as close:
            with self.assertRaises(AuthorityError):CredentialFramer._ancillary([self.creds(),rights],0,self.peer)
            self.assertEqual([x.args[0] for x in close.call_args_list],[40,41])

    def test_truncation_still_closes_each_delivered_fd_once(self):
        rights=(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[40,40,41]).tobytes())
        with patch("cas_forex_authority.checkpoint_service.os.close") as close:
            with self.assertRaises(AuthorityError):CredentialFramer._ancillary([rights],socket.MSG_CTRUNC,self.peer)
            self.assertEqual([x.args[0] for x in close.call_args_list],[40,41])

    def test_uncertain_close_is_not_retried_and_other_fd_still_closed(self):
        rights=(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[40,41]).tobytes())
        with patch("cas_forex_authority.checkpoint_service.os.close",side_effect=[OSError("public fake failure"),None]) as close:
            with self.assertRaises(AuthorityError):CredentialFramer._ancillary([rights],0,self.peer)
            self.assertEqual(close.call_count,2)

    def test_unknown_ancillary_rejects(self):
        with self.assertRaises(AuthorityError):CredentialFramer._ancillary([self.creds(),(99,99,b"x")],0,self.peer)

    def test_truncated_frame_rejects_even_with_matching_credentials(self):
        with self.assertRaises(AuthorityError):CredentialFramer._ancillary([self.creds()],socket.MSG_TRUNC,self.peer)

    def test_partial_frame_checks_credentials_on_each_fragment(self):
        guard=SimpleNamespace(check=lambda:None,remaining=lambda *_:1)
        peers=SimpleNamespace(observe=lambda selected:selected)
        framer=CredentialFramer(guard=guard,peers=peers)
        class Connection:
            def __init__(self):self.parts=[(b"\0\0",[self_creds],0,None),(b"\0\1",[],0,None)]
            def getsockopt(self,*args):return struct.pack("3i",20,1001,1001)
            def settimeout(self,value):pass
            def recvmsg(self,*args):return self.parts.pop(0)
        self_creds=self.creds()
        with self.assertRaises(AuthorityError):framer.receive(Connection(),expected=self.peer,deadline={})
