"""Little lockable memory (RLIMIT_MEMLOCK): calls must wait for each other's
buffers or fail cleanly, never hang or corrupt data (needs a server)."""
import os
import resource
import threading

from .common import RdmaServerTest, op, rdma, FATTR4_SIZE, check


class MemoryLimits(RdmaServerTest):
    def lower_memlock(self, megabytes):
        soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
        limit = int(megabytes * 1024 * 1024)
        if hard != resource.RLIM_INFINITY and limit > hard:
            self.skipTest("the hard memlock limit is below %s MB" % megabytes)
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (limit, hard))
        self.addCleanup(resource.setrlimit, resource.RLIMIT_MEMLOCK,
                        (soft, hard))

    def concurrent_reads(self, sess, fh, count, threads=8):
        results = []

        def reader():
            try:
                results.append(self.read(sess, fh, 0, count)[0])
            except Exception as e:                   # noqa: B902
                results.append(e)
        workers = [threading.Thread(target=reader) for _ in range(threads)]
        for w in workers:
            w.start()
        for w in workers:
            w.join(120)
            self.assertFalse(w.is_alive(), "a read hung")
        return results

    def prepare(self, megabytes):
        self.lower_memlock(megabytes)
        sess = self.new_session(max_response=1048576)
        data = os.urandom(500000)
        return sess, self.create_file(sess, data), data

    def test_calls_wait_for_each_others_buffers(self):
        """With room for only one or two big buffers, the reads run turn by
        turn and all succeed."""
        for megabytes in (2.5, 1.2):
            with self.subTest(megabytes=megabytes):
                sess, fh, data = self.prepare(megabytes)
                for result in self.concurrent_reads(sess, fh, 500000):
                    self.assertEqual(result, data)
                self._cleanup()
                self._files, self._clients = [], []

    def test_far_too_little_memory_fails_cleanly(self):
        """If not even one big buffer fits, a read fails with an error (or
        works, where memory is not accounted); the connection stays usable."""
        sess, fh, data = self.prepare(0.3)
        for result in self.concurrent_reads(sess, fh, 500000):
            if isinstance(result, Exception):
                self.assertIsInstance(result, rdma.RdmaError, result)
            else:
                self.assertEqual(result, data)
        # The connection still works.  (A call that raised leaves its slot of
        # the old session in use, so ask over a new session on the same one.)
        again = self.new_session(sess.c)
        res = again.compound([op.putfh(fh), op.getattr(1 << FATTR4_SIZE)])
        check(res, msg="getattr")
        self.assertEqual(res.resarray[-1].obj_attributes[FATTR4_SIZE], 500000)
