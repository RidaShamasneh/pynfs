"""Data survives the trip: inline, in Read chunks, Reply chunks and Write
chunks (needs a server)."""
import os

from .common import RdmaServerTest, op, ANY_STATEID, FATTR4_SIZE, OP_READ, check


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
