"""The transport's helpers (needs no server and no RDMA device)."""
import struct
import types
import unittest
from unittest import mock

from .common import rdma


class SizeClasses(unittest.TestCase):
    def test_classes(self):
        cls = rdma.RdmaPipe._size_class
        self.assertEqual(cls(1), 4096)
        self.assertEqual(cls(4096), 4096)
        self.assertEqual(cls(4097), 8192)
        self.assertEqual(cls(64 * 1024), 64 * 1024)
        self.assertEqual(cls(64 * 1024 + 1), 128 * 1024)
        self.assertEqual(cls(1000000), 1048576)
        self.assertEqual(cls(1052672), 1114112)     # multiples of 64 KB

    def test_a_class_always_holds_the_size(self):
        for size in range(1, 300000, 997):
            self.assertGreaterEqual(rdma.RdmaPipe._size_class(size), size)

    def test_reply_sizes_are_clamped(self):
        clamp = rdma.RdmaPipe._clamp_reply_size
        self.assertEqual(clamp(1), rdma.REPLY_CHUNK_SIZE)
        self.assertEqual(clamp(10 ** 9), rdma.MAX_REPLY_CHUNK_SIZE)
        self.assertEqual(clamp(300000), 300000)


class PrivateData(unittest.TestCase):
    """The RFC 8797 connection private data."""
    def test_what_we_offer(self):
        magic, version, flags, send, recv = struct.unpack(
            ">IBBBB", rdma._encode_private(4096))
        self.assertEqual((magic, version, flags), (0xf6ab0e18, 1, 0))
        self.assertEqual((send, recv), (3, 3))          # 4096, in KB minus 1

    def test_the_servers_answer_sets_the_sizes(self):
        server = struct.pack(">IBBBB", rdma.CMP_MAGIC, 1, 0, 3, 3)
        self.assertEqual(rdma._negotiated_inline(server, 4096), (4096, 4096))
        small = struct.pack(">IBBBB", rdma.CMP_MAGIC, 1, 0, 0, 1)
        self.assertEqual(rdma._negotiated_inline(small, 4096), (2048, 1024))

    def test_we_never_exceed_what_we_offered(self):
        big = struct.pack(">IBBBB", rdma.CMP_MAGIC, 1, 0, 255, 255)
        self.assertEqual(rdma._negotiated_inline(big, 4096), (4096, 4096))

    def test_no_or_wrong_answer_means_1024(self):
        self.assertEqual(rdma._negotiated_inline(None, 4096), (1024, 1024))
        self.assertEqual(rdma._negotiated_inline(b"", 4096), (1024, 1024))
        wrong = struct.pack(">IBBBB", 0x12345678, 1, 0, 3, 3)
        self.assertEqual(rdma._negotiated_inline(wrong, 4096), (1024, 1024))
        future = struct.pack(">IBBBB", rdma.CMP_MAGIC, 2, 0, 3, 3)
        self.assertEqual(rdma._negotiated_inline(future, 4096), (1024, 1024))


def seg(length):
    return struct.pack(">IIQ", 0x1234, length, 0x7000)


class ChunkLists(unittest.TestCase):
    HDR = b"H" * 16

    def parse(self, lists):
        return rdma._parse_chunk_lists(self.HDR + lists, 16)

    def test_no_chunks(self):
        self.assertEqual(self.parse(b"\0" * 12), (28, None, []))

    def test_a_reply_chunk(self):
        lists = (struct.pack(">I", 0) + struct.pack(">I", 0) +
                 struct.pack(">II", 1, 2) + seg(100) + seg(50))
        self.assertEqual(self.parse(lists), (16 + 8 + 8 + 32, 150, []))

    def test_write_chunks_and_their_lengths(self):
        lists = (struct.pack(">I", 0) +
                 struct.pack(">II", 1, 2) + seg(100) + seg(200) +   # chunk 1
                 struct.pack(">II", 1, 1) + seg(7) +                # chunk 2
                 struct.pack(">I", 0) + struct.pack(">I", 0))
        pos, reply_len, writes = self.parse(lists)
        self.assertEqual((reply_len, writes), (None, [300, 7]))
        self.assertEqual(pos, len(self.HDR + lists))

    def test_a_read_list_is_skipped(self):
        lists = (struct.pack(">II", 1, 0) + seg(10) + struct.pack(">I", 0) +
                 struct.pack(">I", 0) + struct.pack(">I", 0))
        pos, reply_len, writes = self.parse(lists)
        self.assertEqual((reply_len, writes), (None, []))
        self.assertEqual(pos, len(self.HDR + lists))

    def test_truncated_lists_are_an_error(self):
        with self.assertRaises(rdma.RdmaError):
            self.parse(b"\0" * 8)
        with self.assertRaises(rdma.RdmaError):
            self.parse(struct.pack(">I", 0) + struct.pack(">II", 1, 5) +
                       seg(1))


class FakeRegion(object):
    """Stands in for memory registered with the device."""
    closed = False

    def __init__(self, pd, data, offset, length, access):
        self.rkey, self.addr, self.size = 0x1234, 0x7000 + offset, length

    def close(self):
        self.closed = True


class DetachedMessage(unittest.TestCase):
    """The message for a WRITE whose data is sent from the caller's memory."""
    PREFIX, SUFFIX = b"P" * 60, b"S" * 20
    TAIL = struct.pack(">I", 0) + struct.pack(">I", 0)

    def stub(self, inline_send=4096):
        return types.SimpleNamespace(
            _conn=types.SimpleNamespace(pd=None), _inline_send=inline_send,
            _fwd_slots=12, in_place_write_bytes=0, _reclaim_idle=lambda: False)

    def build(self, data, record=None, **kw):
        record = record or self.PREFIX[:56] + b"abcd" + self.SUFFIX
        pipe, call = self.stub(**kw), types.SimpleNamespace(call_mr=None)
        with mock.patch.object(rdma.verbs, "PinnedBytes", FakeRegion):
            msg = rdma.RdmaPipe._detached_in_place(pipe, call, 0xabcd, record,
                                                   56, data, self.TAIL)
        return msg, record, pipe, call

    def test_the_data_is_the_chunk_exactly_and_the_message_is_the_rest(self):
        for length in (5000, 5001, 5002, 5003):
            data = b"d" * length
            msg, record, pipe, call = self.build(data)
            xid, vers, credits, proc = struct.unpack_from(">IIII", msg)
            self.assertEqual((xid, vers, credits, proc),
                             (0xabcd, 1, 12, rdma.RDMA_MSG))
            more, position, handle, seg_length, offset = \
                struct.unpack_from(">IIIIQ", msg, 16)
            self.assertEqual((more, position, handle), (1, 56, 0x1234))
            # no pad: the receiver rounds up, and a pad in the message as
            # well would put what follows one byte off
            self.assertEqual(seg_length, length)
            self.assertEqual(offset, 0x7000)           # the data, from its start
            self.assertEqual(msg[40:44], struct.pack(">I", 0))   # end of list
            self.assertEqual(msg[44:44 + len(self.TAIL)], self.TAIL)
            self.assertEqual(msg[44 + len(self.TAIL):], record)  # unchanged
            self.assertEqual(call.call_mr.size, length)
            self.assertEqual(pipe.in_place_write_bytes, length)

    def test_it_must_fit_inline_or_there_is_no_message(self):
        msg, _, pipe, _ = self.build(b"d" * 5000, record=b"P" * 5000)
        self.assertIsNone(msg)
        self.assertEqual(pipe.in_place_write_bytes, 0)

    def test_no_memory_means_no_message(self):
        def refuse(*args):
            raise rdma.verbs.VerbsError("no memory")
        pipe, call = self.stub(), types.SimpleNamespace(call_mr=None)
        with mock.patch.object(rdma.verbs, "PinnedBytes", refuse):
            msg = rdma.RdmaPipe._detached_in_place(
                pipe, call, 1, b"P" * 60, 56, b"d" * 5000, self.TAIL)
        self.assertIsNone(msg)
        self.assertIsNone(call.call_mr)


class PutBack(unittest.TestCase):
    def test_the_data_and_its_pad_go_back_where_they_were(self):
        for length in (0, 1, 2, 3, 4, 5, 1000):
            data = b"x" * length
            pad = b"\0" * ((-length) % 4)
            self.assertEqual(rdma._put_back(b"HEAD" + b"TAIL", 4, data),
                             b"HEAD" + data + pad + b"TAIL")


class RecordWithPayload(unittest.TestCase):
    def test_the_payload_survives_cutting_off_the_header(self):
        rec = rdma.RecordWithPayload(b"0123456789", b"DATA")
        tail = rec[4:]                       # what the RPC layer does
        self.assertEqual(tail, b"456789")
        self.assertIsInstance(tail, rdma.RecordWithPayload)
        self.assertEqual(tail.payload, b"DATA")

    def test_other_slices_are_plain_bytes(self):
        rec = rdma.RecordWithPayload(b"0123456789", b"DATA")
        self.assertIs(type(rec[2:5]), bytes)
        self.assertIs(type(rec[3]), int)
        self.assertEqual(rec, b"0123456789")


if __name__ == "__main__":
    unittest.main()
