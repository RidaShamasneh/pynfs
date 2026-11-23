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


class SplitWrite(unittest.TestCase):
    """Finding the data of a WRITE in the packed call, to send it in place."""
    PREFIX = b"P" * 40            # stands in for the RPC header and the ops
    SUFFIX = b"S" * 12            # and for what follows the WRITE

    def packed(self, data, prefix=None, suffix=None):
        pad = b"\0" * ((-len(data)) % 4)
        return ((self.PREFIX if prefix is None else prefix) +
                struct.pack(">I", len(data)) + data + pad +
                (self.SUFFIX if suffix is None else suffix))

    def test_the_data_is_cut_out_and_can_be_put_back(self):
        for length in (4096, 4097, 4098, 4099, 100000):
            data = bytes(range(256)) * (length // 256) + b"x" * (length % 256)
            record = self.packed(data)
            position, reduced, chunk = rdma._split_write(record, data)
            self.assertEqual(position, len(self.PREFIX) + 4)
            self.assertEqual(chunk, length + (-length) % 4)       # with its pad
            self.assertEqual(reduced, self.PREFIX + struct.pack(">I", length)
                             + self.SUFFIX)
            self.assertEqual(
                reduced[:position] + record[position:position + chunk] +
                reduced[position:], record)
            self.assertEqual(position % 4, 0)

    def test_the_pad_travels_with_the_data(self):
        data = b"abcde"                                  # 3 bytes of pad
        record = self.packed(data)
        position, _, chunk = rdma._split_write(record, data)
        self.assertEqual(record[position:position + chunk], b"abcde\0\0\0")

    def test_not_found_means_none(self):
        self.assertIsNone(rdma._split_write(self.packed(b"abcdefgh"),
                                            b"zzzzzzzz"))

    def test_data_that_appears_twice_is_not_certain(self):
        data = b"twice!!!"
        record = self.packed(data, suffix=struct.pack(">I", 8) + data)
        self.assertIsNone(rdma._split_write(record, data))

    def test_a_cut_off_call_means_none(self):
        data = b"abcde"
        record = self.packed(data, suffix=b"")[:-1]      # the pad is not all there
        self.assertIsNone(rdma._split_write(record, data))

    def test_a_pad_that_is_not_zeros_means_none(self):
        data = b"abcde"
        record = self.packed(data)
        at = record.find(data) + len(data)
        record = record[:at] + b"\1" + record[at + 1:]
        self.assertIsNone(rdma._split_write(record, data))


class SplitWriteWithTail(unittest.TestCase):
    """With the length of what follows the WRITE, no search is needed."""
    PREFIX = b"P" * 40

    def packed(self, data, tail):
        return (self.PREFIX + struct.pack(">I", len(data)) + data +
                b"\0" * ((-len(data)) % 4) + tail)

    def test_same_answer_as_searching(self):
        for length in (4096, 4097, 4098, 4099, 100001):
            data = bytes(range(256)) * (length // 256) + b"x" * (length % 256)
            for tail in (b"", b"T" * 28, b"T" * 4000):
                record = self.packed(data, tail)
                self.assertEqual(rdma._split_write(record, data, len(tail)),
                                 rdma._split_write(record, data))

    def test_data_that_appears_twice_is_no_problem_when_the_tail_is_known(self):
        data = b"twice!!!"
        tail = struct.pack(">I", 8) + data           # the same opaque again
        record = self.packed(data, tail)
        self.assertIsNone(rdma._split_write(record, data))        # searching
        position, reduced, chunk = rdma._split_write(record, data, len(tail))
        self.assertEqual(position, len(self.PREFIX) + 4)
        self.assertEqual(reduced, self.PREFIX + struct.pack(">I", 8) + tail)

    def test_a_wrong_tail_length_means_none(self):
        data = b"d" * 4001
        record = self.packed(data, b"T" * 20)
        for wrong in (0, 4, 16, 19, 21, 24, 10 ** 6, -4):
            self.assertIsNone(rdma._split_write(record, data, wrong), wrong)

    def test_the_ends_of_the_data_are_checked(self):
        data = b"a" * 100 + b"b" * 100
        record = self.packed(data, b"T" * 8)
        start = len(self.PREFIX) + 4
        for at in (start, start + len(data) - 1):           # first, last byte
            broken = record[:at] + b"!" + record[at + 1:]
            self.assertIsNone(rdma._split_write(broken, data, 8), at)

    def test_short_data(self):
        for data in (b"x", b"xy", b"xyz", b"wxyz", b"vwxyz"):
            record = self.packed(data, b"T" * 12)
            self.assertEqual(rdma._split_write(record, data, 12)[0],
                             len(self.PREFIX) + 4)


class FakeRegion(object):
    """Stands in for memory registered with the device."""
    closed = False

    def __init__(self, pd, data, offset, length, access):
        self.rkey, self.addr, self.size = 0x1234, 0x7000 + offset, length

    def close(self):
        self.closed = True


class WriteInPlaceMessage(unittest.TestCase):
    """The message for a WRITE sent in place, built without a device."""
    PREFIX, SUFFIX = b"P" * 60, b"S" * 20
    TAIL = struct.pack(">I", 0) + struct.pack(">I", 0)    # no Write/Reply chunk

    def build(self, data, inline_send=4096, prefix=None):
        pad = b"\0" * ((-len(data)) % 4)
        record = ((prefix or self.PREFIX) + struct.pack(">I", len(data)) +
                  data + pad + self.SUFFIX)
        pipe = types.SimpleNamespace(
            _conn=types.SimpleNamespace(pd=None), _inline_send=inline_send,
            _fwd_slots=12, in_place_write_bytes=0, _reclaim_idle=lambda: False)
        call = types.SimpleNamespace(call_mr=None)
        with mock.patch.object(rdma.verbs, "PinnedBytes", FakeRegion):
            msg = rdma.RdmaPipe._write_in_place(pipe, call, 0xabcd, record,
                                                data, self.TAIL)
        return msg, record, pipe, call

    def test_the_header_the_read_chunk_and_the_rest(self):
        for length in (5000, 5001, 5002, 5003):
            data = b"d" * length
            msg, record, pipe, call = self.build(data)
            xid, vers, credits, proc = struct.unpack_from(">IIII", msg)
            self.assertEqual((xid, vers, credits, proc),
                             (0xabcd, 1, 12, rdma.RDMA_MSG))
            more, position, handle, seg_length, offset = \
                struct.unpack_from(">IIIIQ", msg, 16)
            at = len(self.PREFIX) + 4
            self.assertEqual((more, position), (1, at))
            self.assertEqual(handle, 0x1234)
            # the pad is in the chunk, so its length is a multiple of 4
            self.assertEqual(seg_length, length + (-length) % 4)
            self.assertEqual(offset, 0x7000 + at)
            self.assertEqual(msg[40:44], struct.pack(">I", 0))   # end of list
            self.assertEqual(msg[44:44 + len(self.TAIL)], self.TAIL)
            reduced = msg[44 + len(self.TAIL):]
            self.assertEqual(reduced, self.PREFIX + struct.pack(">I", length)
                             + self.SUFFIX)
            self.assertIs(type(call.call_mr), FakeRegion)
            self.assertEqual(call.call_mr.size, seg_length)
            self.assertEqual(pipe.in_place_write_bytes, length)

    def test_it_must_fit_inline_or_there_is_no_message(self):
        msg, _, pipe, call = self.build(b"d" * 5000, prefix=b"P" * 5000)
        self.assertIsNone(msg)
        self.assertEqual(pipe.in_place_write_bytes, 0)

    def test_data_that_is_not_there_means_no_message(self):
        data = b"d" * 5000
        pipe = types.SimpleNamespace(
            _conn=types.SimpleNamespace(pd=None), _inline_send=4096,
            _fwd_slots=12, in_place_write_bytes=0, _reclaim_idle=lambda: False)
        with mock.patch.object(rdma.verbs, "PinnedBytes", FakeRegion):
            msg = rdma.RdmaPipe._write_in_place(
                pipe, types.SimpleNamespace(call_mr=None), 1, b"x" * 9000, data,
                self.TAIL)
        self.assertIsNone(msg)

    def test_no_memory_means_no_message(self):
        def refuse(*args):
            raise rdma.verbs.VerbsError("no memory")
        pipe = types.SimpleNamespace(
            _conn=types.SimpleNamespace(pd=None), _inline_send=4096,
            _fwd_slots=12, in_place_write_bytes=0, _reclaim_idle=lambda: False)
        data = b"d" * 5000
        record = (self.PREFIX + struct.pack(">I", 5000) + data + self.SUFFIX)
        with mock.patch.object(rdma.verbs, "PinnedBytes", refuse):
            msg = rdma.RdmaPipe._write_in_place(
                pipe, types.SimpleNamespace(call_mr=None), 1, record, data,
                self.TAIL)
        self.assertIsNone(msg)


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
