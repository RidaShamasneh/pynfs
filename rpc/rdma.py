"""
RPC-over-RDMA version 1 (RFC 8166) client transport.

RdmaPipe is a drop-in replacement for RpcPipe: the layers above it keep
calling send_call()/listen() and deal in whole RPC records, only the bytes on
the wire differ.  It talks to librdmacm/libibverbs through the small ctypes
layer in rdma_verbs.py, so there is nothing to install except rdma-core.

How messages travel:
  * Connection setup sends the RFC 8797 private data, offering 4096 byte
    inline buffers, and takes the server's answer to size what we may send
    inline (1024 when the server sends none).
  * A call that fits the inline size goes in a single RDMA_MSG.
  * A larger call goes as RDMA_NOMSG with the whole RPC call in a Position
    Zero Read chunk: the call is copied to a registered buffer and the server
    RDMA Reads it (RFC 8166 section 4.3, a "long call").
  * Every call carries a Reply chunk, a registered buffer the server RDMA
    Writes a reply into if it does not fit inline (a "long reply").  The
    reply then arrives as RDMA_NOMSG and the data is taken from that buffer.
  * No Write chunks: large READ data comes back in the Reply chunk, copied.
  * The backchannel works over the same connection: calls from the server
    arrive as inline RDMA_MSG and are answered with an inline RDMA_MSG.
    Credits are kept apart (RFC 8167): the forward window is the server's
    grant from Replies, capped to the receive buffers not reserved for
    callbacks, and our backward Replies grant the reserved ones.
  * Connection loss: when the peer disconnects or the QP breaks (a CM event
    or a flushed completion), every call still waiting for a reply fails at
    once with RdmaError, later calls fail immediately, is_active() turns
    False and the verbs resources are freed.  There is no reconnect.  A peer
    that vanishes without any disconnect is only noticed by the next send
    failing; a call that merely times out leaves the connection alone.
  * AUTH_NONE/AUTH_SYS are fine, GSS is untested.

Usage:
    pipe = handler.connect_rdma((host, 20049))
"""
from __future__ import absolute_import

import os
import random
import select
import struct
import threading

from . import rdma_verbs as verbs
from .rpc import RpcPipe, log_t

RPCRDMA_VERSION = 1
DEFAULT_PORT = 20049
MIN_INLINE_SIZE = 1024  # RFC 8166 section 3.3.2: used if nothing is negotiated
INLINE_SIZE = 4096      # what we offer in the connection private data
RECV_SLOTS = 16         # receive buffers posted, shared by replies and
                        # calls from the server
BACK_SLOTS = 4          # of those, kept for calls from the server (RFC 8167):
                        # this is the backward credit grant we give
REPLY_CHUNK_SIZE = 256 * 1024   # largest reply that can come back
RESPONDER_RESOURCES = 16        # RDMA Reads the server may have outstanding
RDMA_HDR = struct.Struct(">IIII")      # xid, vers, credits, proc

# RFC 8797 connection private data: magic, version, flags, send size, recv
# size (the sizes in kilobytes minus one)
CMP_MAGIC = 0xf6ab0e18
CMP_VERSION = 1
CMP = struct.Struct(">IBBBB")

# rpcrdma1_proc
RDMA_MSG, RDMA_NOMSG, RDMA_MSGP, RDMA_DONE, RDMA_ERROR = range(5)

SEND_WRID = 1 << 32     # work request id of sends; receives use their index


class RdmaError(Exception):
    pass


def _seg(handle, length, offset):
    """An RPC-over-RDMA segment: rkey, length, 64 bit remote address."""
    return struct.pack(">IIQ", handle, length, offset)


def _encode_private(size):
    n = (size >> 10) - 1
    return CMP.pack(CMP_MAGIC, CMP_VERSION, 0, n, n)


def _negotiated_inline(private_data, ours):
    """The largest message we may send inline, from the server's private data."""
    if private_data and len(private_data) >= CMP.size:
        magic, version, _flags, _send, recv = CMP.unpack_from(private_data)
        if magic == CMP_MAGIC and version == CMP_VERSION:
            return min(ours, (recv + 1) << 10)
    return MIN_INLINE_SIZE


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
                 reply_size=REPLY_CHUNK_SIZE, back_slots=BACK_SLOTS,
                 inline_size=INLINE_SIZE):
        # Deliberately not calling Pipe.__init__: there is no socket, no
        # write queue and no polling thread involved.
        try:
            verbs.load()
        except verbs.VerbsError as e:
            raise RdmaError(str(e))
        if inline_size % 1024 or inline_size < MIN_INLINE_SIZE:
            raise RdmaError("inline_size must be a multiple of 1024")
        self._s = None
        self._handler = handler
        self._closed = False            # close() was called
        self._lost = None               # why the connection is unusable
        self._pending = {}              # xid -> DeferredData (see RpcPipe)
        self._pending_calls = {}        # xid -> _Call, chunks in use
        self._lock = threading.Lock()
        self._xid = random.randint(0, 0x7fffffff)
        self.set_active()

        # Credits.  Every reply and every callback from the server lands in
        # one of our receive buffers, so the calls we may have outstanding
        # (the forward window) are capped to the buffers not kept for
        # callbacks, whatever the server is willing to grant.
        self._recv_slots = recv_slots
        self._back_slots = back_slots
        self._fwd_slots = recv_slots - back_slots
        if self._fwd_slots < 1:
            raise RdmaError("recv_slots must be larger than back_slots")
        self._credits = 1               # until the server tells us more
        self._credit_cv = threading.Condition()

        self._reply_size = reply_size
        self._free_reply_mrs = []
        self._send_lock = threading.Lock()
        self._send_event = threading.Event()
        self._send_status = 0
        self._conn_lock = threading.Lock()   # connection setup vs teardown
        self._freed = False
        self._recv_mrs = []
        self._send_mr = None
        self._thread = None
        self._wake_r, self._wake_w = os.pipe()
        for fd in (self._wake_r, self._wake_w):
            verbs._set_nonblocking(fd)

        host, port = address
        if isinstance(host, bytes):
            host = host.decode()
        self._conn = verbs.Connection()
        try:
            self._connect(host, port, inline_size)
        except Exception as e:
            self._free()
            if isinstance(e, verbs.VerbsError):
                raise RdmaError(str(e))
            raise
        log_t.info("RDMA connected to %s:%s, inline size %d"
                   % (host, port, self._inline_send))
        self._thread = threading.Thread(target=self._event_loop,
                                        name="RdmaEvents")
        self._thread.daemon = True
        self._thread.start()

    def _connect(self, host, port, inline_size):
        conn = self._conn
        conn.resolve(verbs.sockaddr(host, port), 5000)
        conn.setup_queues(2, self._recv_slots + 2)
        # Receive buffers are as large as the inline size we offered
        for i in range(self._recv_slots):
            mr = verbs.MR(conn.pd, inline_size, verbs.IBV_ACCESS_LOCAL_WRITE)
            self._recv_mrs.append(mr)
            conn.post_recv(mr, i)
        self._send_mr = verbs.MR(conn.pd, inline_size, 0)
        private = _encode_private(inline_size) \
            if inline_size > MIN_INLINE_SIZE else None
        ev = conn.connect(private, RESPONDER_RESOURCES)
        self._inline_send = _negotiated_inline(ev.private_data, inline_size)

    def __getattr__(self, attr):
        # Pipe.__getattr__ would forward to the (absent) socket
        raise AttributeError(attr)

    def __str__(self):
        return "rdma-pipe"

    def fileno(self):
        return -1

    # ---- memory registration -------------------------------------------
    def _chunk_mr(self, size, access):
        return verbs.MR(self._conn.pd, size,
                        verbs.IBV_ACCESS_LOCAL_WRITE | access)

    def _get_reply_mr(self):
        with self._lock:
            if self._free_reply_mrs:
                return self._free_reply_mrs.pop()
        return self._chunk_mr(self._reply_size, verbs.IBV_ACCESS_REMOTE_WRITE)

    def _put_reply_mr(self, mr):
        with self._lock:
            self._free_reply_mrs.append(mr)

    # ---- sending -------------------------------------------------------
    def push_record(self, record):
        """Send one RPC call/reply, inline or as a long call."""
        self._check_alive()
        xid, mtype = struct.unpack(">II", record[:8])
        if mtype == 1:      # REPLY, to a call the server made (backchannel)
            # the credit field of a backward Reply is our backward grant
            msg = (RDMA_HDR.pack(xid, RPCRDMA_VERSION, self._back_slots,
                                 RDMA_MSG) + struct.pack(">III", 0, 0, 0) +
                   record)
            if len(msg) > self._inline_send:
                raise RdmaError("callback reply does not fit inline")
            self._send(msg)
            return
        with self._credit_cv:
            while len(self._pending_calls) >= self._credits and \
                    self._lost is None:
                self._credit_cv.wait(1.0)
            self._check_alive()
            reply_mr = self._get_reply_mr()
            call = _Call(reply_mr)
            self._pending_calls[xid] = call
        try:
            # no write list, and a Reply chunk the size of our buffer
            reply_chunk = (struct.pack(">II", 1, 1) +
                           _seg(reply_mr.rkey, self._reply_size,
                                reply_mr.addr))
            hdr = RDMA_HDR.pack(xid, RPCRDMA_VERSION, self._fwd_slots,
                                RDMA_MSG)
            tail = struct.pack(">I", 0) + reply_chunk  # write list, reply chunk
            inline = hdr + struct.pack(">I", 0) + tail  # read list is empty
            if len(inline) + len(record) <= self._inline_send:
                msg = inline + record
            else:
                call.call_mr = self._chunk_mr(len(record),
                                              verbs.IBV_ACCESS_REMOTE_READ)
                call.call_mr.write(record)
                # one Read chunk (position 0 == the whole call) and nothing
                # else inline
                read_list = (struct.pack(">II", 1, 0) +
                             _seg(call.call_mr.rkey, len(record),
                                  call.call_mr.addr) + struct.pack(">I", 0))
                hdr = RDMA_HDR.pack(xid, RPCRDMA_VERSION, self._fwd_slots,
                                    RDMA_NOMSG)
                msg = hdr + read_list + tail
                if len(msg) > self._inline_send:
                    raise RdmaError("transport header too large")
            self._send(msg)
        except Exception:
            self._release(xid)
            raise

    def _check_alive(self):
        if self._lost is not None:
            raise RdmaError("RDMA connection lost: %s" % self._lost)

    def _send(self, msg):
        with self._send_lock:
            self._check_alive()
            if len(msg) > self._inline_send:
                raise RdmaError("message does not fit the inline size")
            self._send_mr.write(msg)
            self._send_event.clear()
            try:
                self._conn.post_send(self._send_mr, len(msg), SEND_WRID)
            except verbs.VerbsError as e:
                self._connection_lost("send failed: %s" % e)
                self._check_alive()
            # the event thread sets this on the send completion, or when the
            # connection is lost
            while not self._send_event.wait(1.0):
                self._check_alive()
            self._check_alive()
            if self._send_status != 0:
                self._connection_lost("send failed, wc status %d"
                                      % self._send_status)
                self._check_alive()

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

    # ---- events --------------------------------------------------------
    def _wake(self):
        # under the lock so the fd can not be closed (and its number reused)
        # while we write to it
        with self._conn_lock:
            if not self._freed:
                try:
                    os.write(self._wake_w, b"x")
                except OSError:
                    pass

    def _event_loop(self):
        """Handle completions and CM events until the connection is gone."""
        conn = self._conn
        poller = select.poll()
        for fd in (conn.cc_fd, conn.cm_fd, self._wake_r):
            poller.register(fd, select.POLLIN)
        try:
            while self._lost is None:
                for fd, _ in poller.poll():
                    if fd == self._wake_r:
                        try:
                            os.read(self._wake_r, 64)
                        except OSError:
                            pass
                    elif fd == conn.cm_fd:
                        self._cm_events()
                    elif fd == conn.cc_fd:
                        self._completions()
        except Exception as e:
            log_t.warn("RDMA event loop failed", exc_info=True)
            self._connection_lost("event loop failed: %s" % e)
        self._teardown()

    def _cm_events(self):
        while True:
            ev = self._conn.get_event()
            if ev is None:
                return
            log_t.debug("RDMA CM event %s" % ev)
            if ev.type in (verbs.CM_DISCONNECTED, verbs.CM_DEVICE_REMOVAL,
                           verbs.CM_ADDR_CHANGE, verbs.CM_CONNECT_ERROR,
                           verbs.CM_UNREACHABLE, verbs.CM_REJECTED):
                self._connection_lost("CM event %s" % ev)

    def _completions(self):
        for wr_id, status, length in self._conn.completions():
            if wr_id == SEND_WRID:
                self._send_status = status
                self._send_event.set()
                continue
            if status != 0:
                # Normally a flush error: the peer disconnected or the QP broke
                self._connection_lost("receive completed with wc status %d"
                                      % status)
                continue
            mr = self._recv_mrs[wr_id]
            data = mr.read(length)
            self._conn.post_recv(mr, wr_id)         # recycle the buffer
            try:
                self._handle_message(data)
            except Exception:
                log_t.warn("bad RPC-over-RDMA message, dropped",
                           exc_info=True)

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
        if proc == RDMA_MSG and self._is_call(data):
            # The server is calling us on the backchannel: same path as a
            # call arriving over TCP, which sends its reply with push_record
            pos, _ = _parse_chunk_lists(data, RDMA_HDR.size)
            self._dispatch(data[pos:])
            return
        # Only a Reply to one of our calls carries the forward credit grant.
        # In a backward Call the field is the server's own request and says
        # nothing about how many calls we may send.
        with self._credit_cv:
            self._credits = min(max(1, credits), self._fwd_slots)
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
                record = call.reply_mr.read(reply_len)
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

    # ---- loss and teardown ---------------------------------------------
    def _connection_lost(self, reason):
        """The connection is gone: refuse new calls, fail the waiting ones.

        Safe to call more than once and from any thread.
        """
        with self._credit_cv:
            if self._lost is not None:
                return
            self._lost = reason
            unanswered = list(self._pending_calls)
            self._credit_cv.notify_all()      # wake senders waiting for credit
        if not self._closed:
            log_t.warn("RDMA connection lost: %s" % reason)
        self.clear_active()
        error = RdmaError("RDMA connection lost: %s" % reason)
        # Only calls whose reply has not arrived; answered ones have already
        # left _pending_calls and must keep the reply they were given.
        for xid in unanswered:
            self._fail(xid, error)
        self._send_event.set()                # wake a sender waiting for its
        self._wake()                          # completion, and the event loop

    def _teardown(self):
        """Free the verbs resources.  Runs once, on the event thread, after
        the connection is lost, so nothing is polling the CQ any more."""
        # Senders check _lost under this lock, so none is using the send MR
        with self._send_lock:
            send_mr, self._send_mr = self._send_mr, None
        with self._credit_cv:
            calls = list(self._pending_calls.values())
            self._pending_calls.clear()
        with self._lock:
            reply_mrs, self._free_reply_mrs = self._free_reply_mrs, []
        mrs = self._recv_mrs + [send_mr] + reply_mrs
        for call in calls:
            mrs.append(call.reply_mr)
            if call.call_mr is not None:
                mrs.append(call.call_mr)
        self._free(mrs)

    def _free(self, mrs=None):
        """MRs first, then the QP, the CQ, the PD and the CM id."""
        if mrs is None:
            mrs = self._recv_mrs + [self._send_mr] + self._free_reply_mrs
        with self._conn_lock:
            if self._freed:
                return
            self._freed = True
            self._conn.disconnect()             # tell the server first
            for mr in mrs:
                try:
                    if mr is not None:
                        mr.close()
                except Exception:
                    log_t.debug("closing a memory region failed",
                                exc_info=True)
            self._recv_mrs = []
            try:
                self._conn.close()
            except Exception:
                log_t.debug("closing the RDMA connection failed",
                            exc_info=True)
            for fd in (self._wake_r, self._wake_w):
                try:
                    os.close(fd)
                except OSError:
                    pass

    def close(self):
        """Close the connection and free everything.  Calls still waiting for
        a reply fail with RdmaError."""
        if self._closed:
            return
        self._closed = True
        # the event thread sends the disconnect and frees everything
        self._connection_lost("closed")
        if self._thread is not None and \
                threading.current_thread() is not self._thread:
            self._thread.join(5.0)      # it frees the resources on its way out
