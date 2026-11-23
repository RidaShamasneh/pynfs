"""
RPC-over-RDMA version 1 (RFC 8166) client transport.

RdmaPipe is a drop-in replacement for RpcPipe: the layers above it keep
calling send_call()/listen() and deal in whole RPC records, only the bytes on
the wire differ.

How messages travel:
  * A call that fits the inline size goes in a single RDMA_MSG.
  * A larger call goes as RDMA_NOMSG with the whole RPC call in a Position
    Zero Read chunk: the call is copied to a registered buffer and the server
    RDMA Reads it (RFC 8166 section 4.3, a "long call").
  * Every call carries a Reply chunk, a registered buffer the server RDMA
    Writes a reply into if it does not fit inline (a "long reply").  The
    reply then arrives as RDMA_NOMSG and the data is taken from that buffer.
  * No Write chunks (large READ data comes back in the Reply chunk, copied)
    and no RFC 8797 CM private data (the pyverbs shipped with rdma-core 28
    can not send it), so the inline size stays at the 1024 byte default.
  * The backchannel works over the same connection: calls from the server
    arrive as inline RDMA_MSG and are answered with an inline RDMA_MSG.
  * AUTH_NONE/AUTH_SYS are fine, GSS is untested.

Requires the pyverbs python bindings (python3-pyverbs on Debian/Ubuntu).
Usage:
    pipe = handler.connect_rdma((host, 20049))
"""
from __future__ import absolute_import

import random
import struct
import threading
import time
from collections import deque

from .rpc import RpcPipe, log_t

RPCRDMA_VERSION = 1
DEFAULT_PORT = 20049
INLINE_SIZE = 1024      # RFC 8166 section 3.3.2: default inline threshold
RECV_SLOTS = 16         # receive buffers posted == credits we request
REPLY_CHUNK_SIZE = 256 * 1024   # largest reply that can come back
RDMA_HDR = struct.Struct(">IIII")      # xid, vers, credits, proc

# rpcrdma1_proc
RDMA_MSG, RDMA_NOMSG, RDMA_MSGP, RDMA_DONE, RDMA_ERROR = range(5)


class RdmaError(Exception):
    pass


def _seg(handle, length, offset):
    """An RPC-over-RDMA segment: rkey, length, 64 bit remote address."""
    return struct.pack(">IIQ", handle, length, offset)


class _Call(object):
    """Registered memory belonging to one call that is waiting for its reply."""
    def __init__(self, reply_mr, call_mr=None):
        self.reply_mr = reply_mr    # the Reply chunk
        self.call_mr = call_mr      # the Position Zero Read chunk, if any


def _parse_chunk_lists(data, pos):
    """Walk the read list, write list and reply chunk starting at pos.

    Returns (position after them, total length of the reply chunk or None).
    """
    def word(p):
        if p + 4 > len(data):
            raise RdmaError("truncated chunk lists")
        return struct.unpack_from(">I", data, p)[0]
    while word(pos) != 0:                  # read list: one entry per item
        pos += 4 + 4 + 16                  # discriminant, position, segment
    pos += 4
    while word(pos) != 0:                  # write list: one chunk per item
        nsegs = word(pos + 4)
        pos += 8 + 16 * nsegs
    pos += 4
    reply_len = None
    if word(pos) != 0:                     # reply chunk
        nsegs = word(pos + 4)
        reply_len = 0
        for i in range(nsegs):
            reply_len += word(pos + 8 + 16 * i + 4)
        pos += 8 + 16 * nsegs
    else:
        pos += 4
    return pos, reply_len


class RdmaPipe(RpcPipe):
    """An RpcPipe that moves records over an RPC-over-RDMA connection."""

    def __init__(self, handler, address, recv_slots=RECV_SLOTS,
                 reply_size=REPLY_CHUNK_SIZE):
        # Deliberately not calling Pipe.__init__: there is no socket, no
        # write queue and no polling thread involved.
        try:
            from pyverbs.cmid import CMID, AddrInfo, ConnParam
            from pyverbs.qp import QPInitAttr, QPCap
            from pyverbs.cq import CQ
            from pyverbs.pd import PD
            from pyverbs.mr import MR
            import pyverbs.cm_enums as ce
            import pyverbs.enums as en
        except ImportError as e:
            raise RdmaError("RDMA needs the pyverbs python bindings "
                            "(python3-pyverbs): %s" % e)
        self._MR = MR
        self._en = en
        self._s = None
        self._handler = handler
        self._closed = False
        self._pending = {}              # xid -> DeferredData (see RpcPipe)
        self._pending_calls = {}        # xid -> _Call, chunks in use
        self._lock = threading.Lock()
        self._xid = random.randint(0, 0x7fffffff)
        self.set_active()

        host, port = address
        if isinstance(host, bytes):
            host = host.decode()

        def addrinfo():
            return AddrInfo(src=None, dst=host, service=str(port),
                            port_space=ce.RDMA_PS_TCP, flags=0)
        # The chunks are registered by us, so they need to be in the same
        # protection domain as the QP: allocate our own PD on the device and
        # give it to the CMID.  The first CMID is only used to find the device.
        self._probe = CMID(creator=addrinfo())
        ctx = self._probe.context
        self._pd = PD(ctx)
        self._cmid = CMID(creator=addrinfo(), pd=self._pd)
        # pyverbs' CMID.get_*_comp() block in C without dropping the GIL, which
        # would freeze every other thread, so use our own CQs and poll them.
        self._scq = CQ(ctx, 16, None, None, 0)
        self._rcq = CQ(ctx, recv_slots + 4, None, None, 0)
        cap = QPCap(max_send_wr=4, max_recv_wr=recv_slots + 2,
                    max_send_sge=1, max_recv_sge=1)
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
        # post_send() sends the whole MR, so keep one MR per message length
        self._send_mrs = {}
        self._send_lock = threading.Lock()
        self._reply_size = reply_size
        self._free_reply_mrs = []
        self._credits = 1               # until the server tells us more
        self._credit_cv = threading.Condition()
        self._recv_slots = recv_slots

        # Responder resources are how many RDMA Reads the server may have
        # outstanding against our call chunks.
        self._cmid.connect(ConnParam(resources=16, depth=1))
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

    # ---- memory registration -------------------------------------------
    def _chunk_mr(self, size, access):
        en = self._en
        return self._MR(self._pd, size, en.IBV_ACCESS_LOCAL_WRITE | access)

    def _get_reply_mr(self):
        with self._lock:
            if self._free_reply_mrs:
                return self._free_reply_mrs.pop()
        return self._chunk_mr(self._reply_size, self._en.IBV_ACCESS_REMOTE_WRITE)

    def _put_reply_mr(self, mr):
        with self._lock:
            self._free_reply_mrs.append(mr)

    # ---- sending -------------------------------------------------------
    def push_record(self, record):
        """Send one RPC call/reply, inline or as a long call."""
        xid, mtype = struct.unpack(">II", record[:8])
        if mtype == 1:      # REPLY, to a call the server made (backchannel)
            msg = (RDMA_HDR.pack(xid, RPCRDMA_VERSION, self._recv_slots,
                                 RDMA_MSG) + struct.pack(">III", 0, 0, 0) +
                   record)
            if len(msg) > INLINE_SIZE:
                raise RdmaError("callback reply does not fit inline")
            self._send(msg)
            return
        with self._credit_cv:
            while len(self._pending_calls) >= self._credits and \
                    not self._closed:
                self._credit_cv.wait(1.0)
            if self._closed:
                raise RdmaError("connection closed")
            reply_mr = self._get_reply_mr()
            call = _Call(reply_mr)
            self._pending_calls[xid] = call
        try:
            # no write list, and a Reply chunk the size of our buffer
            reply_chunk = (struct.pack(">II", 1, 1) +
                           _seg(reply_mr.rkey, self._reply_size, reply_mr.buf))
            hdr = RDMA_HDR.pack(xid, RPCRDMA_VERSION, self._recv_slots,
                                RDMA_MSG)
            tail = struct.pack(">I", 0) + reply_chunk  # write list, reply chunk
            inline = hdr + struct.pack(">I", 0) + tail  # read list is empty
            if len(inline) + len(record) <= INLINE_SIZE:
                msg = inline + record
            else:
                call.call_mr = self._chunk_mr(len(record),
                                              self._en.IBV_ACCESS_REMOTE_READ)
                call.call_mr.write(record, len(record))
                # one Read chunk (position 0 == the whole call) and nothing
                # else inline
                read_list = (struct.pack(">II", 1, 0) +
                             _seg(call.call_mr.rkey, len(record),
                                  call.call_mr.buf) + struct.pack(">I", 0))
                hdr = RDMA_HDR.pack(xid, RPCRDMA_VERSION, self._recv_slots,
                                    RDMA_NOMSG)
                msg = hdr + read_list + tail
                if len(msg) > INLINE_SIZE:
                    raise RdmaError("transport header too large")
            self._send(msg)
        except Exception:
            self._release(xid)
            raise

    def _send(self, msg):
        with self._send_lock:
            mr = self._send_mrs.get(len(msg))
            if mr is None:
                mr = self._send_mrs[len(msg)] = self._cmid.reg_msgs(len(msg))
            mr.write(msg, len(msg))
            self._cmid.post_send(mr)
            while True:
                n, wcs = self._scq.poll(1)
                if n:
                    break
                time.sleep(0.0002)
            if wcs[0].status != 0:
                raise RdmaError("send failed, wc status %d" % wcs[0].status)

    def _release(self, xid):
        """Forget a call: free its chunks and its credit."""
        with self._credit_cv:
            call = self._pending_calls.pop(xid, None)
            self._credit_cv.notify_all()
        if call is None:
            return None
        if call.call_mr is not None:
            call.call_mr.close()
            call.call_mr = None
        return call

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

    def _fail(self, xid, error):
        deferred = self._pending.get(xid)
        if deferred is not None:
            deferred.fill(None, error)

    def _handle_message(self, data):
        if len(data) < RDMA_HDR.size:
            raise RdmaError("short RDMA header")
        xid, vers, credits, proc = RDMA_HDR.unpack_from(data)
        if vers != RPCRDMA_VERSION:
            raise RdmaError("unsupported RPC-RDMA version %d" % vers)
        with self._credit_cv:
            self._credits = max(1, credits)
        if proc == RDMA_MSG and self._is_call(data):
            # The server is calling us on the backchannel: same path as a
            # call arriving over TCP, which sends its reply with push_record
            pos, _ = _parse_chunk_lists(data, RDMA_HDR.size)
            self._dispatch(data[pos:])
            return
        call = self._release(xid)
        if call is None:
            raise RdmaError("reply with unknown xid %#x" % xid)
        try:
            if proc == RDMA_ERROR:
                err = struct.unpack_from(">I", data, RDMA_HDR.size)[0]
                error = RdmaError("server sent RDMA_ERROR %d for xid %#x"
                                  % (err, xid))
                self._fail(xid, error)
                raise error
            pos, reply_len = _parse_chunk_lists(data, RDMA_HDR.size)
            if proc == RDMA_MSG:
                record = data[pos:]
            elif proc == RDMA_NOMSG:
                if reply_len is None or reply_len > self._reply_size:
                    raise RdmaError("RDMA_NOMSG without a usable Reply chunk")
                record = call.reply_mr.read(reply_len, 0)
            else:
                raise RdmaError("unexpected RPC-RDMA proc %d" % proc)
        finally:
            self._put_reply_mr(call.reply_mr)
        self._dispatch(record)

    @staticmethod
    def _is_call(data):
        """Is the RPC message after the transport header a CALL?"""
        try:
            pos, _ = _parse_chunk_lists(data, RDMA_HDR.size)
        except RdmaError:
            return False
        return len(data) >= pos + 8 and \
            struct.unpack_from(">I", data, pos + 4)[0] == 0

    def _dispatch(self, record):
        """Same path an incoming TCP record takes, on its own thread"""
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
