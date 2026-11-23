"""What NFS4Client tells an RDMA transport about a call (needs no server)."""
import types
import unittest

from .common import (op, nfs4client, AuthSys, rdma,
                     ANY_STATEID, FILE_SYNC4, FATTR4_SIZE)

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


class WriteHints(unittest.TestCase):
    DATA = bytes(range(256)) * 200 + b"abc"               # 51203 bytes

    def write(self, data=None, stateid=ANY_STATEID):
        return op.write(stateid, 0, FILE_SYNC4, self.DATA if data is None
                        else data)

    def test_a_single_write_gives_its_data_and_what_follows(self):
        for after in ([], [op.getattr(1 << FATTR4_SIZE)],
                      [op.getattr(1 << FATTR4_SIZE), op.getfh(), op.getfh()]):
            hints, packed = hints_and_call([op.putfh(b"fh"), self.write()] +
                                           after)
            self.assertIs(hints["write_data"], self.DATA)
            record = b"RPC HEADER " + packed
            position, reduced, chunk = rdma._split_write(
                record, self.DATA, hints["write_tail"])
            # what is cut out is the data and its pad, and it fits back
            self.assertEqual(record[position:position + len(self.DATA)],
                             self.DATA)
            self.assertEqual(reduced[:position] + record[position:position +
                                                         chunk] +
                             reduced[position:], record)
            self.assertEqual(rdma._split_write(record, self.DATA),
                             (position, reduced, chunk))   # as a search finds

    def test_the_tail_is_exactly_the_ops_after_the_write(self):
        none, _ = hints_and_call([op.putfh(b"fh"), self.write()])
        some, _ = hints_and_call([op.putfh(b"fh"), self.write(),
                                  op.getattr(1 << FATTR4_SIZE)])
        self.assertEqual(none["write_tail"], 0)
        self.assertGreater(some["write_tail"], 0)

    def test_ops_before_the_write_do_not_matter(self):
        """The position comes from what follows the data, not from what
        precedes it."""
        hints, packed = hints_and_call([op.putfh(self.DATA[:20]),
                                        self.write()])
        record = b"RPC HEADER " + packed
        position, reduced, chunk = rdma._split_write(
            record, self.DATA, hints["write_tail"])
        self.assertEqual(record[position:position + len(self.DATA)],
                         self.DATA)

    def test_no_data_hint_for_two_writes(self):
        hints, _ = hints_and_call([op.putfh(b"fh"), self.write(),
                                   self.write()])
        self.assertNotIn("write_data", hints)
        self.assertNotIn("write_tail", hints)

    def test_no_hints_for_a_transport_that_does_not_take_them(self):
        hints, _ = hints_and_call([op.putfh(b"fh"), self.write()],
                                  rdma_pipe=False)
        self.assertEqual(hints, {})

    def test_the_session_limit_is_passed_on(self):
        hints, _ = hints_and_call([op.putfh(b"fh")])
        self.assertEqual(hints["max_reply"], 1000000)


if __name__ == "__main__":
    unittest.main()
