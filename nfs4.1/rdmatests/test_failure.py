"""Connection loss and credits, against a fake server (needs pyverbs and a
local RDMA address in PYNFS_FAKE_ADDR)."""
import os
import random
import subprocess
import sys
import threading
import time
import unittest

from .common import FAKE_ADDR, nfs4client, rdma, AuthSys, UID, GID, pipes_of

try:
    import pyverbs                                  # noqa: F401
    HAVE_PYVERBS = True
except ImportError:
    HAVE_PYVERBS = False

FAKE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "fakeserver.py")


@unittest.skipUnless(FAKE_ADDR and HAVE_PYVERBS,
                     "needs pyverbs and PYNFS_FAKE_ADDR=<local RDMA address>")
class FakeServerTest(unittest.TestCase):
    def fake(self, mode):
        """Start a fake server; returns (its process, the port)."""
        port = random.randint(21000, 29999)
        proc = subprocess.Popen([sys.executable, FAKE, FAKE_ADDR, str(port),
                                 mode], stdout=subprocess.PIPE,
                                universal_newlines=True)
        self.addCleanup(proc.kill)
        timer = threading.Timer(30, proc.kill)      # never hang the tests
        timer.daemon = True
        timer.start()
        self.addCleanup(timer.cancel)
        self.assertEqual(proc.stdout.readline().strip(), "ready")
        return proc, port

    def client(self, port):
        client = nfs4client.NFS4Client(FAKE_ADDR.encode(), port,
                                       minorversion=1, rdma=True)
        client.set_cred(AuthSys().init_cred(uid=UID, gid=GID, name=b"fake"))
        self.addCleanup(lambda: [p.close() for p in pipes_of(client)])
        return client

    def timed(self, fn):
        start = time.time()
        with self.assertRaises(rdma.RdmaError) as caught:
            fn()
        return time.time() - start, str(caught.exception)


class ConnectionLoss(FakeServerTest):
    def test_a_call_waiting_when_the_peer_disconnects_fails_at_once(self):
        _, port = self.fake("disconnect")
        client = self.client(port)
        took, message = self.timed(client.null)
        self.assertLess(took, 10, "should not wait for the 300 s timeout")
        self.assertIn("connection lost", message)
        self.assertFalse(client.c1.is_active())

    def test_a_call_after_the_loss_fails_immediately(self):
        _, port = self.fake("disconnect")
        client = self.client(port)
        self.timed(client.null)
        took, _ = self.timed(client.null)
        self.assertLess(took, 1)

    def test_close_fails_a_call_that_is_waiting(self):
        _, port = self.fake("hang")
        client = self.client(port)
        timer = threading.Timer(0.5, client.c1.close)
        timer.start()
        self.addCleanup(timer.cancel)
        took, message = self.timed(client.null)
        self.assertLess(took, 10)
        self.assertIn("closed", message)


class Credits(FakeServerTest):
    def test_the_forward_window_is_the_servers_grant_capped_by_our_buffers(
            self):
        proc, port = self.fake("credit")
        pipe = self.client(port).c1
        self.assertEqual(pipe._credits, 1)              # until the server says
        pipe._handler.null()
        self.assertEqual(pipe._credits, pipe._fwd_slots)    # 1000 granted
        self.assertLess(pipe._fwd_slots, pipe._recv_slots)

        # the fake now calls us with 77 in the credit field of its Call;
        # that is not a grant for our calls
        request, callback = proc.stdout.readline(), proc.stdout.readline()
        self.assertIn("credit field %d" % pipe._fwd_slots, request)
        self.assertIn("credit grant %d" % pipe._back_slots, callback)
        self.assertEqual(pipe._credits, pipe._fwd_slots)
