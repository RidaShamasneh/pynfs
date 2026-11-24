"""Data survives the trip: inline, in Read chunks, Reply chunks and Write
chunks (needs a server)."""
import os
import tracemalloc
from unittest import mock

from .common import (RdmaServerTest, op, rdma, nfs4client, ANY_STATEID,
                     FATTR4_SIZE, OP_READ, FILE_SYNC4, check)


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
        for size in (40000, 40001, 40002, 40003, 100001, 500003):
            if size > self.maxwrite:
                continue
            data = os.urandom(size)
            before = self.pipe.in_place_write_bytes
            self.write(0, data)
            self.assertEqual(self.pipe.in_place_write_bytes - before, size)
            self.assertEqual(self.read_all(self.sess, self.fh), data, size)

    def test_small_writes_are_copied_as_they_always_were(self):
        """Inline, or a long call, which costs less than registering memory
        for so little data."""
        before = self.pipe.in_place_write_bytes
        for size in (5, 3000, 5000, 20000, nfs4client.DETACH_WRITE_MIN - 1):
            data = os.urandom(size)
            self.write(0, data)
            self.assertEqual(self.read_all(self.sess, self.fh), data, size)
        self.assertEqual(self.pipe.in_place_write_bytes, before)

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

    def test_when_the_data_cannot_be_registered_the_call_is_a_long_call(self):
        """If it cannot be sent from where it is (no lockable memory for it),
        the data is put back into the call, which goes as a long call."""
        def refuse(*args):
            raise rdma.verbs.VerbsError("no memory")
        data = os.urandom(70000)
        before = self.pipe.in_place_write_bytes
        with mock.patch.object(rdma.verbs, "PinnedBytes", refuse):
            self.write(0, data)
        self.assertEqual(self.pipe.in_place_write_bytes, before)
        self.assertEqual(self.read_all(self.sess, self.fh), data)

    def test_sizes_around_where_the_paths_change(self):
        """Around what fits inline, and what is left out of the call."""
        limit = nfs4client.DETACH_WRITE_MIN
        for size in (3000, 3800, 4000, 4090, 4095, 4096, 4097, 4099, 8191,
                     limit - 1, limit, limit + 1, limit + 2, limit + 3):
            data = os.urandom(size)
            res = self.write(0, data, [op.getattr(1 << FATTR4_SIZE)])
            self.assertEqual(res.resarray[-1].obj_attributes[FATTR4_SIZE],
                             size, size)
            self.assertEqual(self.read_all(self.sess, self.fh), data, size)

    def test_the_data_is_not_copied_on_its_way(self):
        """Nothing of the data is allocated in Python on the way out: it is
        registered where the application has it.  With the data left in the
        call, as before, there are several copies of it."""
        size = min(self.maxwrite, 900000)
        if size < 300000:
            self.skipTest("the server allows writes of only %d bytes" % size)
        data = os.urandom(size)
        self.write(0, data)                             # warm up
        self.assertEqual(self.pipe.in_place_write_bytes, size)

        def peak():
            tracemalloc.start()
            try:
                self.write(0, data)
                return tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
        direct = peak()
        self.assertLess(direct, size // 8, direct)
        with mock.patch.object(nfs4client, "DETACH_WRITE_MIN", 10 ** 9):
            copied = peak()
        self.assertGreater(copied, size, copied)        # the measure works


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
