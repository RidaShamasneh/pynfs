"""
RPC-over-RDMA version 1 (RFC 8166) client transport.

RdmaPipe is a drop-in replacement for RpcPipe: the layers above it keep
calling send_call()/listen() and deal in whole RPC records, only the bytes on
the wire differ.

This first version only does what fits in a single inline RDMA_MSG:
  * no read/write/reply chunks, so every call and every reply must fit in
    the inline size (1024 bytes, the RFC 8166 default; the pyverbs shipped
    with rdma-core 28 can not send the RFC 8797 CM private data that would
    negotiate a larger value),
  * no RFC 8797 private data,
  * AUTH_NONE/AUTH_SYS are fine, GSS is untested.

Requires the pyverbs python bindings (python3-pyverbs on Debian/Ubuntu).
Usage:
    pipe = handler.connect_rdma((host, 20049))
"""
from __future__ import absolute_import

import struct
import threading
import time
from collections import deque

from .rpc import RpcPipe, log_t

RPCRDMA_VERSION = 1
DEFAULT_PORT = 20049
INLINE_SIZE = 1024      # RFC 8166 section 3.3.2: default inline threshold
RECV_SLOTS = 16         # receive buffers posted == credits we request
RDMA_HDR = struct.Struct(">IIII")      # xid, vers, credits, proc

# rpcrdma1_proc
RDMA_MSG, RDMA_NOMSG, RDMA_MSGP, RDMA_DONE, RDMA_ERROR = range(5)


class RdmaError(Exception):
    pass


class RdmaPipe(RpcPipe):
    """An RpcPipe that moves records over an RPC-over-RDMA connection."""

    def __init__(self, handler, address, recv_slots=RECV_SLOTS):
        # Deliberately not calling Pipe.__init__: there is no socket, no
        # write queue and no polling thread involved.
        try:
            from pyverbs.cmid import CMID, AddrInfo, ConnParam
            from pyverbs.qp import QPInitAttr, QPCap
            from pyverbs.cq import CQ
            import pyverbs.cm_enums as ce
        except ImportError as e:
            raise RdmaError("RDMA needs the pyverbs python bindings "
                            "(python3-pyverbs): %s" % e)
        self._s = None
        self._handler = handler
        self._closed = False
        self._pending = {}
        self._lock = threading.Lock()
        import random
        self._xid = random.randint(0, 0x7fffffff)
        self.set_active()

        host, port = address
        if isinstance(host, bytes):
            host = host.decode()
        addr = AddrInfo(src=None, dst=host, service=str(port),
                        port_space=ce.RDMA_PS_TCP, flags=0)
        cap = QPCap(max_send_wr=4, max_recv_wr=recv_slots + 2,
                    max_send_sge=1, max_recv_sge=1)
        self._cmid = CMID(creator=addr)
        # pyverbs' CMID.get_*_comp() block in C without dropping the GIL, which
        # would freeze every other thread, so use our own CQs and poll them.
        ctx = self._cmid.context
        self._scq = CQ(ctx, 16, None, None, 0)
        self._rcq = CQ(ctx, recv_slots + 4, None, None, 0)
        self._cmid.create_qp(QPInitAttr(qp_type=2,  # IBV_QPT_RC
                                        qp_context=None, cap=cap,
                                        scq=self._scq, rcq=self._rcq))
        # Receives complete in the order they were posted, and this pyverbs
        # gives no wr_id, so keep the buffers in a queue to find the right one.
        self._recv_q = deque()
        for _ in range(recv_slots):
            mr = self._cmid.reg_msgs(INLINE_SIZE)
            self._recv_q.append(mr)
            self._cmid.post_recv(mr)
        self._send_mr = self._cmid.reg_msgs(INLINE_SIZE)
        self._send_lock = threading.Lock()
        self._credits = 1               # until the server tells us more
        self._outstanding = 0
        self._credit_cv = threading.Condition()
        self._recv_slots = recv_slots

        self._cmid.connect(ConnParam(resources=1, depth=1))
        log_t.info("RDMA connected to %s:%s" % (host, port))
        self._thread = threading.Thread(target=self._recv_loop,
                                        name="RdmaRecv")
        self._thread.daemon = True
        self._thread.start()

    def __getattr__(self, attr):
        # Pipe.__getattr__ would forward to the (absent) socket
        raise AttributeError(attr)

    def __str__(self):
        return "rdma-pipe"

    def fileno(self):
        return -1

    # ---- sending -------------------------------------------------------
    def push_record(self, record):
        """Send one RPC call/reply as an inline RDMA_MSG."""
        hlen = RDMA_HDR.size + 12
        if hlen + len(record) > INLINE_SIZE:
            raise RdmaError("message of %d bytes does not fit the %d byte "
                            "inline size and chunks are not implemented yet"
                            % (len(record), INLINE_SIZE))
        xid = struct.unpack(">I", record[:4])[0]
        with self._credit_cv:
            while self._outstanding >= self._credits and not self._closed:
                self._credit_cv.wait(1.0)
            if self._closed:
                raise RdmaError("connection closed")
            self._outstanding += 1
        # no read list, no write list, no reply chunk
        msg = (RDMA_HDR.pack(xid, RPCRDMA_VERSION, self._recv_slots, RDMA_MSG)
               + struct.pack(">III", 0, 0, 0) + record)
        with self._send_lock:
            self._send_mr.write(msg, len(msg))
            self._cmid.post_send(self._send_mr)
            self._wait_send()

    def _wait_send(self):
        while True:
            n, wcs = self._scq.poll(1)
            if n == 0:
                time.sleep(0.0002)
                continue
            wc = wcs[0]
            if wc.status != 0:
                raise RdmaError("send failed, wc status %d" % wc.status)
            return

    # ---- receiving -----------------------------------------------------
    def _recv_loop(self):
        while not self._closed:
            try:
                n, wcs = self._rcq.poll(1)
            except Exception as e:
                if not self._closed:
                    log_t.warn("RDMA receive failed: %s" % e)
                break
            if n == 0:
                time.sleep(0.0002)
                continue
            wc = wcs[0]
            mr = self._recv_q.popleft()
            if wc.status != 0:
                if not self._closed:
                    log_t.warn("RDMA receive completed with status %d"
                               % wc.status)
                break
            data = mr.read(wc.byte_len, 0)
            self._cmid.post_recv(mr)         # recycle the buffer
            self._recv_q.append(mr)
            try:
                self._handle_message(data)
            except Exception:
                log_t.warn("bad RPC-over-RDMA message, dropped",
                           exc_info=True)
        self.clear_active()

    def _handle_message(self, data):
        if len(data) < RDMA_HDR.size:
            raise RdmaError("short RDMA header")
        xid, vers, credits, proc = RDMA_HDR.unpack_from(data)
        if vers != RPCRDMA_VERSION:
            raise RdmaError("unsupported RPC-RDMA version %d" % vers)
        with self._credit_cv:
            self._credits = max(1, credits)
            if self._outstanding > 0:
                self._outstanding -= 1
            self._credit_cv.notify_all()
        if proc == RDMA_ERROR:
            err = struct.unpack_from(">I", data, RDMA_HDR.size)[0]
            raise RdmaError("server sent RDMA_ERROR %d for xid %#x"
                            % (err, xid))
        if proc != RDMA_MSG:
            raise RdmaError("unexpected RPC-RDMA proc %d" % proc)
        # An empty read list, write list and reply chunk
        if data[RDMA_HDR.size:RDMA_HDR.size + 12] != b"\0" * 12:
            raise RdmaError("reply carries chunks, not supported yet")
        record = data[RDMA_HDR.size + 12:]
        # Same path an incoming TCP record takes, on its own thread
        t = threading.Thread(target=self._handler._event_rpc_record,
                             args=(record, self))
        t.daemon = True
        t.start()

    def close(self):
        if self._closed:
            return
        self._closed = True
        with self._credit_cv:
            self._credit_cv.notify_all()
        try:
            self._cmid.disconnect()
        except Exception:
            pass
        self.clear_active()
