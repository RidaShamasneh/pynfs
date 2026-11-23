"""Data survives the trip: inline, in Read chunks, Reply chunks and Write
chunks (needs a server)."""
import os
from unittest import mock

from .common import (RdmaServerTest, op, rdma, ANY_STATEID, FATTR4_SIZE,
                     OP_READ, FILE_SYNC4, check)


class WriteRead(RdmaServerTest):
    def test_sizes_from_inline_to_long_calls_and_replies(self):
        """What is written, in calls of every size, reads back the same."""
        sess = self.new_session()
        for size in (1, 100, 2000, 3500, 5000, 200000, 1500000):
            data = os.urandom(size)
            fh = self.create_file(sess, data)
            self.assertEqual(self.read_all(sess, fh), data, size)


class WriteChunks(RdmaServerTest):
    """READ data placed by the server in a Write chunk.

    These assert that the chunk is used, which a Linux nfsd does.
    """
    SIZE = 1000003

    def setUp(self):
        super(WriteChunks, self).setUp()
        self.sess = self.new_session()
        self.pipe = self.sess.c.c1
        self.data = os.urandom(self.SIZE)
        self.fh = self.create_file(self.sess, self.data)

    def read_placed(self, offset, count, extra=()):
        before = self.pipe.write_chunk_bytes
        data, eof, res = self.read(self.sess, self.fh, offset, count, extra)
        return data, eof, self.pipe.write_chunk_bytes - before, res

    def test_large_reads_are_placed_in_a_write_chunk(self):
        # sizes that are not multiples of 4 matter: the XDR pad
        for offset, count in ((0, 2049), (0, 2050), (1, 3001), (0, 4096),
                              (7, 4999), (0, 100001), (3, 500003),
                              (0, self.SIZE)):
            data, eof, placed, _ = self.read_placed(offset, count)
            self.assertEqual(data, self.data[offset:offset + count],
                             (offset, count))
            self.assertEqual(placed, len(data), (offset, count))

    def test_reads_shorter_than_asked_and_at_the_end(self):
        data, eof, placed, _ = self.read_placed(999000, 100000)
        self.assertEqual((data, eof), (self.data[999000:], True))
        self.assertEqual(placed, 1003)
        data, eof, placed, _ = self.read_placed(self.SIZE, 5000)   # at EOF
        self.assertEqual((data, eof, placed), (b"", True, 0))
        data, eof, placed, _ = self.read_placed(self.SIZE - 1, 100000)
        self.assertEqual((data, eof, placed), (self.data[-1:], True, 1))

    def test_small_reads_come_inline(self):
        data, eof, placed, _ = self.read_placed(0, 5)
        self.assertEqual((data, placed), (self.data[:5], 0))

    def test_a_result_after_the_read_still_lines_up(self):
        """The reply keeps no pad for the data: GETATTR must still decode."""
        for count in (4999, 5000, 5001, 5002):
            data, _, placed, res = self.read_placed(
                0, count, [op.getattr(1 << FATTR4_SIZE)])
            self.assertEqual(data, self.data[:count], count)
            self.assertEqual(placed, count)
            self.assertEqual(res.resarray[-1].obj_attributes[FATTR4_SIZE],
                             self.SIZE)

    def test_a_big_read_with_other_results_after_it(self):
        """The rest of the reply no longer fits inline, so there is a Reply
        chunk next to the Write chunk, and nfsd drops the connection unless
        that covers the READ data as well."""
        for count in (100001, 300000, self.SIZE):
            data, _, placed, res = self.read_placed(
                0, count, [op.getattr(1 << FATTR4_SIZE)])
            self.assertEqual(data, self.data[:count], count)
            self.assertEqual(placed, count)
            self.assertEqual(res.resarray[-1].obj_attributes[FATTR4_SIZE],
                             self.SIZE)

    def test_two_reads_in_one_compound_use_no_write_chunk(self):
        before = self.pipe.write_chunk_bytes
        res = self.sess.compound([op.putfh(self.fh),
                                  op.read(ANY_STATEID, 0, 9000),
                                  op.read(ANY_STATEID, 9000, 9001)])
        check(res, msg="two reads")
        got = [r.switch.switch.data for r in res.resarray
               if r.resop == OP_READ]
        self.assertEqual(got, [self.data[:9000], self.data[9000:18001]])
        self.assertEqual(self.pipe.write_chunk_bytes, before)


class WriteInPlace(RdmaServerTest):
    """A WRITE too big to go inline is sent with a Read chunk at the position
    of its data, registered where it is in the call, not copied.

    These assert that the data went that way, which a Linux nfsd accepts.
    """
    def setUp(self):
        super(WriteInPlace, self).setUp()
        self.sess = self.new_session(max_request=1048576 + 8192)
        self.pipe = self.sess.c.c1
        self.fh = self.create_file(self.sess)           # empty
        self.maxwrite = self.sess.fore_channel.maxrequestsize - 4096

    def write(self, offset, data, extra=()):
        res = self.sess.compound([op.putfh(self.fh), op.write(
            self.sess_stateid(), offset, FILE_SYNC4, data)] + list(extra))
        check(res, msg="write")
        return res

    def sess_stateid(self):
        return ANY_STATEID

    def test_big_writes_are_sent_in_place(self):
        # not multiples of 4 too: the pad goes with the data
        for size in (5000, 5001, 5002, 5003, 60000, 100001, 500003):
            if size > self.maxwrite:
                continue
            data = os.urandom(size)
            before = self.pipe.in_place_write_bytes
            self.write(0, data)
            self.assertEqual(self.pipe.in_place_write_bytes - before, size)
            self.assertEqual(self.read_all(self.sess, self.fh), data, size)

    def test_a_write_that_fits_inline_is_not(self):
        before = self.pipe.in_place_write_bytes
        self.write(0, b"small")
        self.assertEqual(self.pipe.in_place_write_bytes, before)
        self.assertEqual(self.read_all(self.sess, self.fh), b"small")

    def test_the_largest_write_the_session_allows(self):
        size = min(self.maxwrite, 1000000)
        if size < 200000:
            self.skipTest("the server allows writes of only %d bytes" % size)
        data = os.urandom(size)
        self.write(0, data)
        self.assertEqual(self.pipe.in_place_write_bytes, size)
        self.assertEqual(self.read_all(self.sess, self.fh), data)

    def test_a_result_after_the_write_still_lines_up(self):
        data = os.urandom(70003)
        before = self.pipe.in_place_write_bytes
        res = self.write(0, data, [op.getattr(1 << FATTR4_SIZE)])
        self.assertEqual(self.pipe.in_place_write_bytes - before, 70003)
        self.assertEqual(res.resarray[-1].obj_attributes[FATTR4_SIZE], 70003)
        self.assertEqual(self.read_all(self.sess, self.fh), data)

    def test_data_that_repeats_itself(self):
        for data in (b"abcd" * 25000, b"\0" * 100000, b"ab" * 50001):
            self.write(0, data)
            self.assertEqual(self.read_all(self.sess, self.fh)[:len(data)],
                             data)

    def test_two_writes_in_one_compound_are_not(self):
        """Which data would go in place is not clear, so the call goes as a
        long call, copied.  (Only the first write's data is checked: a Linux
        nfsd stores the second of two big WRITEs in one COMPOUND wrongly even
        over TCP.)"""
        a, b = os.urandom(50000), os.urandom(50000)
        before = self.pipe.in_place_write_bytes
        check(self.sess.compound([
            op.putfh(self.fh), op.write(ANY_STATEID, 0, FILE_SYNC4, a),
            op.write(ANY_STATEID, 50000, FILE_SYNC4, b)]), msg="two writes")
        self.assertEqual(self.pipe.in_place_write_bytes, before)
        self.assertEqual(self.read_all(self.sess, self.fh)[:50000], a)

    def test_when_the_data_cannot_be_placed_the_call_is_a_long_call(self):
        """If the transport is not sure where the data is (see SplitWrite in
        test_transport_units), the call goes as a long call instead."""
        data = os.urandom(70000)
        before = self.pipe.in_place_write_bytes
        with mock.patch.object(rdma, "_split_write", lambda r, d, tail=None: None):
            self.write(0, data)
        self.assertEqual(self.pipe.in_place_write_bytes, before)
        self.assertEqual(self.read_all(self.sess, self.fh), data)


class LargeReply(RdmaServerTest):
    def test_one_read_of_a_megabyte(self):
        """A reply that needs a Reply or Write chunk as big as the session
        allows."""
        sess = self.new_session(max_response=2097152)
        if sess.fore_channel.maxresponsesize < 1000000 + 8192:
            self.skipTest("the server allows replies of only %d bytes" %
                          sess.fore_channel.maxresponsesize)
        data = os.urandom(1000000)
        fh = self.create_file(sess, data)
        self.assertEqual(self.read(sess, fh, 0, 1000000)[0], data)
