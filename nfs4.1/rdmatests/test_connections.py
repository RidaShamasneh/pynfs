"""More than one connection or session; leaks (needs a server)."""
import collections
import os
import time

from .common import RdmaServerTest, op, nfs4client, check, ANY_STATEID, \
    AuthSys, UID, GID, RDMA_SERVER, pipes_of


class ExtraConnections(RdmaServerTest):
    """The reply limit is the session's, whatever connection carries a call."""

    def setUp(self):
        super(ExtraConnections, self).setUp()
        self.client = self.new_client()
        self.big = self.new_session(self.client, max_response=2097152)
        if self.big.fore_channel.maxresponsesize < 1000000 + 8192:
            self.skipTest("the server allows replies of only %d bytes" %
                          self.big.fore_channel.maxresponsesize)
        self.data = os.urandom(1000000)
        self.fh = self.create_file(self.big, self.data)

    def test_an_extra_connection_knows_the_session_limit(self):
        main = self.client.c1
        extra = self.client.connect(self.client.server_address)
        self.assertEqual(extra._reply_size, main._reply_size)
        self.assertGreaterEqual(extra._reply_size,
                                self.big.fore_channel.maxresponsesize)

    def test_a_megabyte_on_an_extra_connection_through_the_client(self):
        """As st_sequence does: the client, with a SEQUENCE of its own."""
        extra = self.client.connect(self.client.server_address)
        res = self.client.compound(
            [self.big.seq_op(), op.putfh(self.fh),
             op.read(ANY_STATEID, 0, 1000000)], pipe=extra)
        check(res, msg="read")
        self.assertEqual(res.resarray[-1].switch.switch.data, self.data)

    def test_a_megabyte_on_an_extra_connection_through_the_session(self):
        extra = self.client.connect(self.client.server_address)
        data, _, _ = self.read(self.big, self.fh, 0, 1000000, pipe=extra)
        self.assertEqual(data, self.data)

    def test_a_newer_small_session_does_not_shrink_an_older_one(self):
        small = self.new_session(self.client, max_request=8192,
                                 max_response=8192)
        self.assertLessEqual(small.fore_channel.maxresponsesize, 8192)
        self.assertGreaterEqual(self.client.c1._reply_size,
                                self.big.fore_channel.maxresponsesize)
        data, _, _ = self.read(self.big, self.fh, 0, 1000000)
        self.assertEqual(data, self.data)


def descriptors():
    count = collections.Counter()
    for fd in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink("/proc/self/fd/" + fd)
        except OSError:
            continue
        if "infiniband" in target or "rdma" in target or "uverbs" in target:
            count["rdma"] += 1
        elif target.startswith("pipe:"):
            count["pipe"] += 1
    return count


class Leaks(RdmaServerTest):
    def test_closed_pipes_leave_no_descriptors_behind(self):
        host, port = RDMA_SERVER
        for _ in range(2):                  # open the shared device once
            self._cycle(host, port)
        time.sleep(0.5)
        before = descriptors()
        for _ in range(15):
            self._cycle(host, port)
        time.sleep(0.5)                     # the event threads finish closing
        after = descriptors()
        self.assertLessEqual(after["pipe"], before["pipe"] + 2)
        self.assertLessEqual(after["rdma"], before["rdma"] + 2)

    @staticmethod
    def _cycle(host, port):
        client = nfs4client.NFS4Client(host.encode(), port, minorversion=1,
                                       rdma=True)
        client.set_cred(AuthSys().init_cred(uid=UID, gid=GID, name=b"leak"))
        client.null()
        for pipe in pipes_of(client):
            pipe.close()
