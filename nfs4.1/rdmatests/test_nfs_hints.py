"""What NFS4Client tells an RDMA transport about a call (needs no server)."""
import types
import unittest
from unittest import mock

from .common import (op, nfs4client, AuthSys, rdma, COMPOUND4args,
                     ANY_STATEID, FILE_SYNC4, FATTR4_SIZE)
import nfs4lib

KB = 1024


def hints_and_call(ops, rdma_pipe=True, tag=b"tag"):
    """The hints and the packed COMPOUND of one call, sent through a stand-in
    for the client and its pipe."""
    sent = {}

    def send_call(pipe, procedure, data, credinfo, **hints):
        sent["data"], sent["hints"] = data, hints
    me = types.SimpleNamespace(
        tag=tag, minorversion=2, send_call=send_call,
        default_cred=AuthSys().init_cred(uid=0, gid=0, name=b"unit"))
    pipe = types.SimpleNamespace(supports_write_chunks=rdma_pipe)
    nfs4client.NFS4Client.compound_async(me, ops, pipe=pipe,
                                         max_response_size=1000000)
    return sent["hints"], sent["data"]


def packed_whole(ops, tag=b"tag"):
    """The COMPOUND as it is packed with all the data in it."""
    packer = nfs4lib.FancyNFS4Packer()
    packer.pack_COMPOUND4args(COMPOUND4args(tag, 2, ops))
    return packer.get_buffer()


class WriteHints(unittest.TestCase):
    BIG = bytes(range(256)) * 200 + b"abc"               # 51203 bytes
    SMALL = b"s" * 3001

    def write(self, data, stateid=ANY_STATEID):
        return op.write(stateid, 0, FILE_SYNC4, data)

    AFTER = ([], [op.getattr(1 << FATTR4_SIZE)],
             [op.getattr(1 << FATTR4_SIZE), op.getfh(), op.getfh()])

    def test_big_data_is_left_out_of_the_call(self):
        for after in self.AFTER:
            ops = [op.putfh(b"fh"), self.write(self.BIG)] + after
            hints, packed = hints_and_call(ops)
            position, data = hints["write_detached"]
            self.assertIs(data, self.BIG)
            self.assertLess(len(packed), 1000)           # not in the call
            # put back with its pad it is what would have been packed
            self.assertEqual(rdma._put_back(packed, position, data),
                             packed_whole(ops))

    def test_the_position_is_in_the_message_not_just_the_args(self):
        """The RPC header is in front of what NFS4Client packs."""
        sent = {}
        pipe = types.SimpleNamespace(
            supports_write_chunks=True,
            send_call=lambda *a, **k: sent.update(k))
        header = b"H" * 44
        recorded = {}
        pipe.push_record = lambda record, **k: recorded.update(
            record=record, **k)
        from rpc.rpc import RpcPipe
        msg = types.SimpleNamespace()
        with mock.patch("rpc.rpc.FancyRPCPacker") as packer:
            packer.return_value.get_buffer.return_value = header
            RpcPipe.rpc_send(pipe, msg, b"DATA", write_detached=(8, b"x" * 9))
        self.assertEqual(recorded["write_detached"], (8 + len(header),
                                                       b"x" * 9))
        self.assertEqual(recorded["record"], header + b"DATA")

    def test_small_data_is_left_in_the_call(self):
        """Below DETACH_WRITE_MIN registering memory costs more than copying."""
        for after in self.AFTER:
            ops = [op.putfh(b"fh"), self.write(self.SMALL)] + after
            hints, packed = hints_and_call(ops)
            self.assertNotIn("write_detached", hints)
            self.assertEqual(packed, packed_whole(ops))

    def test_the_size_that_is_left_out_is_the_limit(self):
        limit = nfs4client.DETACH_WRITE_MIN
        for size, left_out in ((limit - 1, False), (limit, True),
                               (limit + 1, True)):
            hints, _ = hints_and_call([op.putfh(b"fh"),
                                       self.write(b"d" * size)])
            self.assertEqual("write_detached" in hints, left_out, size)

    def test_ops_before_the_write_do_not_matter(self):
        ops = [op.putfh(b"f" * 20), op.putfh(b"fh"), self.write(self.BIG)]
        hints, packed = hints_and_call(ops)
        position, data = hints["write_detached"]
        self.assertEqual(rdma._put_back(packed, position, data),
                         packed_whole(ops))

    def test_no_data_hint_for_two_writes(self):
        hints, packed = hints_and_call([op.putfh(b"fh"), self.write(self.BIG),
                                        self.write(self.BIG)])
        self.assertNotIn("write_detached", hints)
        self.assertGreater(len(packed), 2 * len(self.BIG))   # all in the call

    def test_no_hints_for_a_transport_that_does_not_take_them(self):
        hints, packed = hints_and_call([op.putfh(b"fh"), self.write(self.BIG)],
                                       rdma_pipe=False)
        self.assertEqual(hints, {})
        self.assertGreater(len(packed), len(self.BIG))       # in the call

    def test_a_packer_chosen_by_the_caller_is_used_as_it_is(self):
        sent = {}
        me = types.SimpleNamespace(
            tag=b"t", minorversion=2, send_call=lambda p, n, d, c, **h:
            sent.update(data=d, hints=h),
            default_cred=AuthSys().init_cred(uid=0, gid=0, name=b"unit"))
        pipe = types.SimpleNamespace(supports_write_chunks=True)

        class Mine(nfs4lib.FancyNFS4Packer):            # not the default
            pass
        nfs4client.NFS4Client.compound_async(
            me, [op.putfh(b"fh"), self.write(self.BIG)], pipe=pipe,
            packer=Mine)
        self.assertNotIn("write_detached", sent["hints"])
        self.assertGreater(len(sent["data"]), len(self.BIG))  # all in the call

    def test_the_session_limit_is_passed_on(self):
        hints, _ = hints_and_call([op.putfh(b"fh")])
        self.assertEqual(hints["max_reply"], 1000000)


if __name__ == "__main__":
    unittest.main()
