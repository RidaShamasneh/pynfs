"""Shared setup for the RPC-over-RDMA tests.

The tests that talk to a real server read their configuration from the
environment:

  PYNFS_RDMA_SERVER  host[:port] of an NFS server listening for RDMA
                     (default port 20049)
  PYNFS_EXPORT       path of a writable directory on it, e.g. /srv/nfs/share
  PYNFS_UID/GID      AUTH_SYS credentials to use (default: ours)
  PYNFS_FAKE_ADDR    address of a local RDMA interface, for the tests that run
                     a fake server (these also need pyverbs)

Without them those tests are skipped.  The tests that need no server (the
reply bounds, the transport's helpers) always run.
"""
import itertools
import os
import sys
import threading
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_NFS41 = os.path.dirname(_HERE)
_ROOT = os.path.dirname(_NFS41)
for _path in (_ROOT, _NFS41):        # as testserver.py's use_local does
    if _path not in sys.path:
        sys.path.insert(0, _path)

import nfs4client                                   # noqa: E402
import nfs_ops                                      # noqa: E402
from nfs4lib import check, use_obj                  # noqa: E402
from xdrdef.nfs4_const import *                     # noqa: E402,F401,F403
from xdrdef.nfs4_type import *                      # noqa: E402,F401,F403
from rpc.security import AuthSys                    # noqa: E402
import rpc.rdma as rdma                             # noqa: E402

op = nfs_ops.NFS4ops()
ANY_STATEID = stateid4(0, b"\0" * 12)               # noqa: F405


def _host_port(value, default_port):
    host, sep, port = value.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        return host, int(port)
    return value, default_port


_server = os.environ.get("PYNFS_RDMA_SERVER")
RDMA_SERVER = _host_port(_server, 20049) if _server else None
_export = os.environ.get("PYNFS_EXPORT")
EXPORT = [c.encode() for c in (_export or "").split("/") if c]
FAKE_ADDR = os.environ.get("PYNFS_FAKE_ADDR")
UID = int(os.environ.get("PYNFS_UID", os.getuid()))
GID = int(os.environ.get("PYNFS_GID", os.getgid()))

_counter = itertools.count()


def kb(size):
    return "%dK" % (size // 1024)


def pipes_of(client):
    """The RDMA pipes of an NFS4Client (just the main one in older versions)."""
    return list(getattr(client, "_rdma_pipes", None) or [client.c1])


@unittest.skipUnless(RDMA_SERVER and _export,
                     "set PYNFS_RDMA_SERVER=host[:port] and "
                     "PYNFS_EXPORT=/writable/path")
class RdmaServerTest(unittest.TestCase):
    """A test against a real server, over RDMA, in a directory of its export.

    Clients are closed and the files the test made are removed afterwards.
    """
    minorversion = 2

    def setUp(self):
        self._clients = []
        self._files = []
        self.addCleanup(self._cleanup)

    def unique(self, what=b"x"):
        return b"rdmatest-%d-%d-%s" % (os.getpid(), next(_counter), what)

    def new_client(self):
        host, port = RDMA_SERVER
        client = nfs4client.NFS4Client(host.encode(), port,
                                       minorversion=self.minorversion,
                                       rdma=True)
        client.set_cred(AuthSys().init_cred(uid=UID, gid=GID,
                                            name=b"pynfs-rdma-tests"))
        self._clients.append(client)
        return client

    def new_session(self, client=None, max_request=131072,
                    max_response=2097152):
        client = client or self.new_client()
        record = client.new_client(self.unique(b"client"))
        sess = record.create_session(fore_attrs=channel_attrs4(  # noqa: F405
            0, max_request, max_response, 8192, 128, 8, []))
        sess.compound([op.reclaim_complete(FALSE)])           # noqa: F405
        return sess

    def create_file(self, sess, data=b"", name=None):
        """Create a file with the given contents, return its filehandle."""
        name = name or self.unique(b"file")
        res = sess.compound(use_obj(EXPORT) + [
            op.open(0, OPEN4_SHARE_ACCESS_BOTH |                  # noqa: F405
                    OPEN4_SHARE_ACCESS_WANT_NO_DELEG,             # noqa: F405
                    OPEN4_SHARE_DENY_NONE,                        # noqa: F405
                    open_owner4(0, self.unique(b"owner")),        # noqa: F405
                    openflag4(OPEN4_CREATE, createhow4(           # noqa: F405
                        UNCHECKED4, {FATTR4_MODE: 0o644})),       # noqa: F405
                    open_claim4(CLAIM_NULL, name)),               # noqa: F405
            op.getfh()])
        check(res, msg="open")
        stateid = res.resarray[-2].stateid
        fh = res.resarray[-1].object
        self._files.append((sess, name))
        step = min(100000, sess.fore_channel.maxrequestsize - 4096)
        for off in range(0, len(data), step):
            check(sess.compound([op.putfh(fh), op.write(
                stateid, off, FILE_SYNC4, data[off:off + step])]),  # noqa: F405
                msg="write")
        check(sess.compound([op.putfh(fh), op.close(0, stateid)]),
              msg="close")
        return fh

    def read(self, sess, fh, offset, count, extra=(), **kwargs):
        """One READ compound; returns (data, eof, the whole result)."""
        res = sess.compound([op.putfh(fh), op.read(ANY_STATEID, offset, count)]
                            + list(extra), **kwargs)
        check(res, msg="read")
        result = [r for r in res.resarray if r.resop == OP_READ][0]  # noqa: F405
        return result.switch.switch.data, result.switch.switch.eof, res

    def read_all(self, sess, fh, count=100000):
        data, offset = b"", 0
        while True:
            piece, eof, _ = self.read(sess, fh, offset, count)
            data += piece
            offset += len(piece)
            if eof:
                return data

    def _cleanup(self):
        fresh = {}
        for sess, name in self._files:
            try:
                sess.compound(use_obj(EXPORT) + [op.remove(name)])
            except Exception:
                # e.g. the session's slots are stuck after calls that raised:
                # try over a new session on the same client
                try:
                    if sess.c not in fresh:
                        fresh[sess.c] = self.new_session(sess.c)
                    fresh[sess.c].compound(use_obj(EXPORT) + [op.remove(name)])
                except Exception:
                    pass
        for client in self._clients:
            for pipe in pipes_of(client):
                try:
                    pipe.close()
                except Exception:
                    pass


class Spy(object):
    """Record the size of every Reply/Write chunk buffer RdmaPipe asks for."""
    def __init__(self):
        self.sizes = []
        self._orig = rdma.RdmaPipe._get_mr

    def __enter__(self):
        spy = self

        def get_mr(pipe, size, shrink=False):
            mr = spy._orig(pipe, size, shrink)
            spy.sizes.append(mr.size if mr else None)
            return mr
        rdma.RdmaPipe._get_mr = get_mr
        return self

    def __exit__(self, *exc):
        rdma.RdmaPipe._get_mr = self._orig
