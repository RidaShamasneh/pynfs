"""How big a Reply or Write chunk each kind of call registers (needs a
server)."""
import os

from .common import (RdmaServerTest, Spy, op, rdma, kb, use_obj, EXPORT,
                     ANY_STATEID, FATTR4_SIZE, FATTR4_ACL, check)

KB = 1024


class ChunkSizes(RdmaServerTest):
    def setUp(self):
        super(ChunkSizes, self).setUp()
        self.sess = self.new_session()
        self.pipe = self.sess.c.c1
        self.cap = rdma.RdmaPipe._size_class(self.pipe._reply_size)
        self.data = os.urandom(1000000)
        self.fh = self.create_file(self.sess, self.data)

    def sizes(self, ops):
        with Spy() as spy:
            check(self.sess.compound(ops), msg="compound")
        return spy.sizes

    def test_small_calls_get_the_smallest_chunk(self):
        self.assertEqual(self.sizes([op.putfh(self.fh),
                                     op.getattr(1 << FATTR4_SIZE)]),
                         [rdma.REPLY_CHUNK_SIZE])
        self.assertEqual(self.sizes([op.putfh(self.fh),
                                     op.write(ANY_STATEID, 0, 2, b"x" * 60000)]),
                         [rdma.REPLY_CHUNK_SIZE])

    def test_a_read_with_a_write_chunk_needs_no_reply_chunk(self):
        """nfsd wants a Reply chunk to cover the READ data too, unless the
        rest of the reply fits inline and there is none."""
        if self.cap < 1000000 or self.pipe._inline_reply < 4096:
            self.skipTest("needs a 1 MB session and a 4 KB inline size")
        got = self.sizes([op.putfh(self.fh), op.read(ANY_STATEID, 0, 1000000)])
        self.assertEqual(got, [rdma.RdmaPipe._size_class(1000000)])
        got = self.sizes([op.putfh(self.fh), op.read(ANY_STATEID, 0, 100000)])
        self.assertEqual(got, [rdma.RdmaPipe._size_class(100000)])

    def test_reads_without_a_write_chunk_get_a_reply_chunk_for_the_data(self):
        got = self.sizes([op.putfh(self.fh),
                          op.read(ANY_STATEID, 0, 300000),
                          op.read(ANY_STATEID, 300000, 300000)])
        self.assertEqual(len(got), 1)
        self.assertGreaterEqual(got[0], 600000)
        self.assertLess(got[0], self.cap)

    def test_readdir_is_sized_by_its_maxcount(self):
        got = self.sizes(use_obj(EXPORT) + [
            op.readdir(0, b"\0" * 8, 4000, 100000, 1 << FATTR4_SIZE)])
        self.assertEqual(len(got), 1)
        self.assertGreaterEqual(got[0], 100000)
        self.assertLess(got[0], self.cap)

    def test_a_reply_without_a_bound_gets_what_the_session_allows(self):
        got = self.sizes([op.putfh(self.fh),
                          op.getattr(1 << FATTR4_ACL | 1 << FATTR4_SIZE)])
        self.assertEqual(got, [self.cap])

    def test_ops_with_a_bound_do_not_need_the_session_maximum(self):
        stateids = [ANY_STATEID] * 1000
        res = self.sess.compound([op.test_stateid(stateids)])
        self.assertEqual(res.status, 0, res.status)
        self.assertEqual(self.sizes([op.test_stateid(stateids)]),
                         [rdma.REPLY_CHUNK_SIZE])

    def test_idle_buffers_stay_within_the_pool_limit(self):
        for count in (1000000, 100000, 300000):
            self.read(self.sess, self.fh, 0, count)
        idle = sum(size * len(mrs)
                   for size, mrs in self.pipe._free_mrs.items())
        self.assertLessEqual(idle, rdma.POOL_BYTES)
