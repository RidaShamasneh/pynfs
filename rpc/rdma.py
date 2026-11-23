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
    An NFSv4.1 server never sends more than the session's maximum response
    size, so set_reply_size() sets that as the largest chunk (64 KB to 4 MB).
    A call that says how big its reply can be (the reply_size hint) gets a
    chunk of just that size, 64 KB at least, so ordinary calls pin little.
    nfsd wants the Reply chunk to hold the whole reply, READ data included,
    even when the data goes in a Write chunk (a smaller one makes it drop the
    connection), so the READ count is part of the size.  When the reply
    without the READ data is known to fit inline, as for a READ with only a
    few small ops around it, there is no Reply chunk at all.
  * A READ can have its data placed by the server straight into a Write
    chunk (RFC 8166 section 4.4, RFC 8267), instead of coming back through
    the Reply chunk.  The caller says so with the read_size hint of
    push_record(); see RecordWithPayload for how the data gets to the
    NFS layer.  Other large replies still use the Reply chunk, copied.
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
REPLY_CHUNK_SIZE = 64 * 1024    # smallest Reply chunk (see set_reply_size)
MAX_REPLY_CHUNK_SIZE = 4 * 1024 * 1024   # and the largest
REPLY_SLACK = 4096      # room above the session's maximum response size
WRITE_CHUNK_MIN = 2048  # READs larger than this get a Write chunk
INLINE_HDR_ALLOWANCE = 128      # for the transport header of an inline reply
POOL_BYTES = 4 * 1024 * 1024    # most memory idle pooled buffers pin
SIZE_CLASS_STEP = 64 * 1024     # pooled buffers: powers of two up to this,
                                # then multiples of it
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
    """(the largest message we may send inline, the largest the server will
    send us inline), from the server's private data."""
    if private_data and len(private_data) >= CMP.size:
        magic, version, _flags, send, recv = CMP.unpack_from(private_data)
        if magic == CMP_MAGIC and version == CMP_VERSION:
            return (min(ours, (recv + 1) << 10), min(ours, (send + 1) << 10))
    return MIN_INLINE_SIZE, MIN_INLINE_SIZE


class RecordWithPayload(bytes):
    """An RPC record whose READ data arrived in a Write chunk.

    The bytes are the reduced reply, which has the data length but not the
    data; payload is the data, to be spliced in by whoever decodes the reply
    (nfs4lib.FancyNFS4Unpacker).  Slicing to the end keeps the payload, so it
    survives the RPC layer taking the header off.
    """
    def __new__(cls, record, payload):
        obj = bytes.__new__(cls, record)
        obj.payload = payload
        return obj

    def __getitem__(self, key):
        item = bytes.__getitem__(self, key)
        if isinstance(key, slice) and key.stop is None:
            return RecordWithPayload(item, self.payload)
        return item


class _Call(object):
    """Registered memory belonging to one call that is waiting for its reply."""
    def __init__(self, reply_mr, call_mr=None):
        self.reply_mr = reply_mr    # the Reply chunk, None if there is none
        self.call_mr = call_mr      # the Position Zero Read chunk, if any
        self.write_mr = None        # the Write chunk for a READ, if any


def _parse_chunk_lists(data, pos):
    """Walk the read list, write list and reply chunk starting at pos.

    Returns (position after them, total length of the reply chunk or None,
    the total length of each Write chunk).
    """
    def word(p):
        if p + 4 > len(data):
            raise RdmaError("truncated chunk lists")
        return struct.unpack_from(">I", data, p)[0]
    while word(pos) != 0:                  # read list: one entry per item
        pos += 4 + 4 + 16                  # discriminant, position, segment
    pos += 4
    write_lens = []
    while word(pos) != 0:                  # write list: one chunk per item
        nsegs = word(pos + 4)
        write_lens.append(sum(word(pos + 8 + 16 * i + 4)
                              for i in range(nsegs)))
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
    return pos, reply_len, write_lens


class RdmaPipe(RpcPipe):
    """An RpcPipe that moves records over an RPC-over-RDMA connection."""

    # callers (NFS4Client) may pass read_size to send_call()
    supports_write_chunks = True

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

        self._reply_size = self._clamp_reply_size(reply_size)
        self._free_mrs = {}             # size -> idle Reply/Write chunk buffers
        self.write_chunk_bytes = 0      # READ data received in Write chunks
        self._shrink_warned = False
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
        self._inline_send, self._inline_reply = \
            _negotiated_inline(ev.private_data, inline_size)

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
                        verbs.IBV_ACCESS_LOCAL_WRITE | access)  # VerbsError

    @staticmethod
    def _clamp_reply_size(size):
        return max(REPLY_CHUNK_SIZE, min(size, MAX_REPLY_CHUNK_SIZE))

    @staticmethod
    def _size_class(size):
        """Pooled buffers come in a few sizes so idle ones can be reused."""
        if size <= SIZE_CLASS_STEP:
            return 1 << max(12, (size - 1).bit_length())
        return (size + SIZE_CLASS_STEP - 1) & ~(SIZE_CLASS_STEP - 1)

    def set_reply_size(self, max_response_size):
        """Set the largest Reply chunk, and the size of those of calls that do
        not say how big their reply can be, for calls that do not say which
        session's maximum response size (ca_maxresponsesize) applies."""
        size = self._clamp_reply_size(max_response_size + REPLY_SLACK)
        with self._lock:
            if size == self._reply_size:
                return
            self._reply_size = size
        log_t.info("RDMA Reply chunk size is now %d" % size)

    def _reclaim_idle(self):
        """Unpin the idle pooled buffers, to make room.  True if any."""
        with self._lock:
            mrs = [mr for idle in self._free_mrs.values() for mr in idle]
            self._free_mrs = {}
        for mr in mrs:
            mr.close()
        return bool(mrs)

    def _get_mr(self, size, shrink=False):
        """A remote-writable buffer, for a Reply or a Write chunk, of at
        least size bytes; None if the memory can not be registered right now
        (RLIMIT_MEMLOCK).  With shrink, a smaller one (down to
        REPLY_CHUNK_SIZE) is accepted: a big reply may then fail, but
        ordinary calls keep working."""
        wanted = size = self._size_class(size)
        reclaimed = False
        while True:
            with self._lock:
                idle = self._free_mrs.get(size)
                if idle:
                    return idle.pop()
            try:
                mr = self._chunk_mr(size, verbs.IBV_ACCESS_REMOTE_WRITE)
                if size < wanted and not self._shrink_warned:
                    self._shrink_warned = True
                    log_t.warn("RDMA chunk limited to %d bytes, not %d: "
                               "RLIMIT_MEMLOCK is too low" % (size, wanted))
                return mr
            except verbs.VerbsError as e:
                log_t.debug("chunk registration failed: %s" % e)
                if not reclaimed and self._reclaim_idle():
                    reclaimed = True        # idle buffers were in the way
                    continue
                if not shrink or size <= REPLY_CHUNK_SIZE:
                    return None
                size = self._size_class(max(REPLY_CHUNK_SIZE, size // 2))

    def _put_mr(self, mr):
        """Give a buffer back to the pool, if there is room for it."""
        with self._lock:
            pinned = sum(m.size for idle in self._free_mrs.values()
                         for m in idle)
            if pinned + mr.size <= POOL_BYTES and not self._freed:
                self._free_mrs.setdefault(mr.size, []).append(mr)
                return
        mr.close()

    # ---- sending -------------------------------------------------------
    def push_record(self, record, read_size=None, reply_size=None,
                    max_reply=None):
        """Send one RPC call/reply, inline or as a long call.

        read_size says the call has one READ of that many bytes: a big enough
        one gets a Write chunk, so the server places the data directly in
        our memory.  Only for a reply the server could ever send.

        reply_size is an upper bound for the reply, READ data not counted if
        there is a read_size: the Reply chunk is sized for it.  Without it
        the Reply chunk can take anything the session allows.

        max_reply is the most the call's session allows as a reply; it is
        what the Reply chunk may grow to.  Without it, whatever
        set_reply_size() last said, for the whole pipe.
        """
        self._check_alive()
        cap = self._reply_size if max_reply is None else \
            self._clamp_reply_size(max_reply + REPLY_SLACK)
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
            while True:
                # A Write chunk for the READ data, if it is worth it
                write_mr = None
                if read_size and WRITE_CHUNK_MIN < read_size <= cap:
                    write_mr = self._get_mr(read_size)
                reply_mr = None
                if write_mr is not None and reply_size is not None and \
                        reply_size <= self._inline_reply - INLINE_HDR_ALLOWANCE:
                    # The reply without the READ data fits inline: no Reply
                    # chunk, so nothing more to pin.
                    break
                # A Reply chunk for the whole reply, READ data included
                want = cap
                if reply_size is not None:
                    want = max(REPLY_CHUNK_SIZE, min(
                        reply_size + (read_size or 0) + REPLY_SLACK, cap))
                # Out of lockable memory: wait for a call in flight to
                # finish and give its buffers back.  If there is none, make do
                # with a smaller chunk
                reply_mr = self._get_mr(want, shrink=not self._pending_calls)
                if reply_mr is not None:
                    break
                if write_mr is not None:
                    self._put_mr(write_mr)
                if not self._pending_calls:
                    raise RdmaError("cannot register a %d byte Reply chunk "
                                    "(RLIMIT_MEMLOCK too low?)"
                                    % REPLY_CHUNK_SIZE)
                self._credit_cv.wait(1.0)
                self._check_alive()
            call = _Call(reply_mr)
            call.write_mr = write_mr
            self._pending_calls[xid] = call
        try:
            # a Reply chunk the size of our buffer, and a Write chunk for READ
            # data if there is one (XDR rounds the data up to a multiple of 4)
            reply_chunk = struct.pack(">I", 0)
            if reply_mr is not None:
                reply_chunk = (struct.pack(">II", 1, 1) +
                               _seg(reply_mr.rkey, reply_mr.size,
                                    reply_mr.addr))
            write_list = struct.pack(">I", 0)
            if call.write_mr is not None:
                write_list = (struct.pack(">II", 1, 1) +
                              _seg(call.write_mr.rkey, (read_size + 3) & ~3,
                                   call.write_mr.addr) +
                              struct.pack(">I", 0))
            hdr = RDMA_HDR.pack(xid, RPCRDMA_VERSION, self._fwd_slots,
                                RDMA_MSG)
            tail = write_list + reply_chunk
            inline = hdr + struct.pack(">I", 0) + tail  # read list is empty
            if len(inline) + len(record) <= self._inline_send:
                msg = inline + record
            else:
                try:
                    try:
                        call.call_mr = self._chunk_mr(
                            len(record), verbs.IBV_ACCESS_REMOTE_READ)
                    except verbs.VerbsError:
                        # idle pooled buffers may be what is using the memory
                        if not self._reclaim_idle():
                            raise
                        call.call_mr = self._chunk_mr(
                            len(record), verbs.IBV_ACCESS_REMOTE_READ)
                except verbs.VerbsError as e:
                    raise RdmaError("cannot register a %d byte call: %s"
                                    % (len(record), e))
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
            call = self._release(xid)
            if call is not None:
                for mr in (call.reply_mr, call.write_mr):
                    if mr is not None:
                        self._put_mr(mr)
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
            pos = _parse_chunk_lists(data, RDMA_HDR.size)[0]
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
        payload = None
        try:
            if proc == RDMA_ERROR:
                err = struct.unpack_from(">I", data, RDMA_HDR.size)[0]
                # the caller gets the error; this is not a bad message
                log_t.warn("server sent RDMA_ERROR %d for xid %#x"
                           % (err, xid))
                self._fail(xid, RdmaError("server sent RDMA_ERROR %d" % err))
                return
            pos, reply_len, write_lens = _parse_chunk_lists(data,
                                                            RDMA_HDR.size)
            if call.write_mr is not None and write_lens and write_lens[0]:
                # The server placed READ data in our Write chunk.  Copy it out
                # now: the buffer goes back to the pool below.
                placed = min(write_lens[0], call.write_mr.size)
                payload = call.write_mr.read(placed)
                self.write_chunk_bytes += placed
            if proc == RDMA_MSG:
                record = data[pos:]
            elif proc == RDMA_NOMSG:
                if call.reply_mr is None or reply_len is None or \
                        reply_len > call.reply_mr.size:
                    raise RdmaError("RDMA_NOMSG without a usable Reply chunk")
                record = call.reply_mr.read(reply_len)
            else:
                raise RdmaError("unexpected RPC-RDMA proc %d" % proc)
        finally:
            for mr in (call.reply_mr, call.write_mr):
                if mr is not None:
                    self._put_mr(mr)
        if payload:
            record = RecordWithPayload(record, payload)
        self._dispatch(record)

    @staticmethod
    def _is_call(data):
        """Is the RPC message after the transport header a CALL?"""
        try:
            pos = _parse_chunk_lists(data, RDMA_HDR.size)[0]
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
            idle_mrs = [mr for idle in self._free_mrs.values() for mr in idle]
            self._free_mrs = {}
        mrs = self._recv_mrs + [send_mr] + idle_mrs
        for call in calls:
            for mr in (call.reply_mr, call.call_mr, call.write_mr):
                if mr is not None:
                    mrs.append(mr)
        self._free(mrs)

    def _free(self, mrs=None):
        """MRs first, then the QP, the CQ, the PD and the CM id."""
        if mrs is None:
            mrs = self._recv_mrs + [self._send_mr]
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
