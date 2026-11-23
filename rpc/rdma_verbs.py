"""
Minimal ctypes bindings for librdmacm and libibverbs.

Just what the RPC-over-RDMA transport in rdma.py needs, loaded at run time so
that nothing else depends on them.  The python bindings shipped with rdma-core
(pyverbs) were not used because they can not send connection private data,
hide the connection events, and block in C without releasing the GIL.

struct offsets below come from the installed rdma-core headers (offsetof) and
are part of the stable libibverbs/librdmacm ABI.  The data path functions that
verbs.h defines as inline (ibv_post_send, ibv_post_recv, ibv_poll_cq,
ibv_req_notify_cq) are called through the provider function table in
struct ibv_context, exactly as the inline versions do.
"""
from __future__ import absolute_import

import ctypes
import errno
import fcntl
import os
import socket
import struct
from ctypes import byref, c_char, c_int, c_size_t, c_uint, c_void_p

# enum values
RDMA_PS_TCP = 0x0106
IBV_QPT_RC = 2
IBV_WR_SEND = 2
IBV_SEND_SIGNALED = 2
IBV_ACCESS_LOCAL_WRITE = 1
IBV_ACCESS_REMOTE_WRITE = 2
IBV_ACCESS_REMOTE_READ = 4
IBV_WC_SUCCESS = 0
IBV_WC_WR_FLUSH_ERR = 5

(CM_ADDR_RESOLVED, CM_ADDR_ERROR, CM_ROUTE_RESOLVED, CM_ROUTE_ERROR,
 CM_CONNECT_REQUEST, CM_CONNECT_RESPONSE, CM_CONNECT_ERROR, CM_UNREACHABLE,
 CM_REJECTED, CM_ESTABLISHED, CM_DISCONNECTED, CM_DEVICE_REMOVAL,
 CM_MULTICAST_JOIN, CM_MULTICAST_ERROR, CM_ADDR_CHANGE,
 CM_TIMEWAIT_EXIT) = range(16)

# struct offsets
_CTX_POLL_CQ = 96
_CTX_REQ_NOTIFY_CQ = 104
_CTX_POST_SEND = 208
_CTX_POST_RECV = 216
_CMID_VERBS = 0
_CMID_QP = 24
_COMP_CHANNEL_FD = 8
_CM_CHANNEL_FD = 0
_EV_EVENT = 16
_EV_STATUS = 20
_EV_PRIVATE_DATA = 24
_EV_PRIVATE_DATA_LEN = 32
_MR_ADDR = 16
_MR_LKEY = 36
_MR_RKEY = 40
WC_SIZE = 48
SEND_WR_SIZE = 128
RECV_WR_SIZE = 32
SGE_SIZE = 16
CONN_PARAM_SIZE = 24
QP_INIT_ATTR_SIZE = 64


class VerbsError(Exception):
    pass


_cm = None
_ib = None


def load():
    """Load librdmacm and libibverbs (once); raises VerbsError if absent."""
    global _cm, _ib
    if _cm is not None:
        return
    try:
        cm = ctypes.CDLL("librdmacm.so.1", use_errno=True)
        ib = ctypes.CDLL("libibverbs.so.1", use_errno=True)
    except OSError as e:
        raise VerbsError("RDMA needs librdmacm and libibverbs: %s" % e)
    p = c_void_p
    sigs = [
        (cm, "rdma_create_event_channel", p, []),
        (cm, "rdma_destroy_event_channel", None, [p]),
        (cm, "rdma_create_id", c_int, [p, p, p, c_int]),
        (cm, "rdma_destroy_id", c_int, [p]),
        (cm, "rdma_resolve_addr", c_int, [p, p, p, c_int]),
        (cm, "rdma_resolve_route", c_int, [p, c_int]),
        (cm, "rdma_create_qp", c_int, [p, p, p]),
        (cm, "rdma_destroy_qp", None, [p]),
        (cm, "rdma_connect", c_int, [p, p]),
        (cm, "rdma_disconnect", c_int, [p]),
        (cm, "rdma_get_cm_event", c_int, [p, p]),
        (cm, "rdma_ack_cm_event", c_int, [p]),
        (cm, "rdma_event_str", ctypes.c_char_p, [c_int]),
        (ib, "ibv_alloc_pd", p, [p]),
        (ib, "ibv_dealloc_pd", c_int, [p]),
        (ib, "ibv_create_comp_channel", p, [p]),
        (ib, "ibv_destroy_comp_channel", c_int, [p]),
        (ib, "ibv_create_cq", p, [p, c_int, p, p, c_int]),
        (ib, "ibv_destroy_cq", c_int, [p]),
        (ib, "ibv_reg_mr", p, [p, p, c_size_t, c_int]),
        (ib, "ibv_dereg_mr", c_int, [p]),
        (ib, "ibv_get_cq_event", c_int, [p, p, p]),
        (ib, "ibv_ack_cq_events", None, [p, c_uint]),
    ]
    try:
        for lib, name, res, args in sigs:
            fn = getattr(lib, name)
            fn.restype = res
            fn.argtypes = args
    except AttributeError as e:
        raise VerbsError("unsupported rdma-core: %s" % e)
    _cm, _ib = cm, ib


def _err(what):
    e = ctypes.get_errno()
    return VerbsError("%s failed: %s" % (what, os.strerror(e) if e else "?"))


def _ptr(addr):
    return c_void_p.from_address(addr).value


def _set_nonblocking(fd):
    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)


def sockaddr(host, port):
    """A ctypes buffer holding a struct sockaddr_in/in6 for host:port."""
    for af, _, _, _, sa in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        if af == socket.AF_INET:
            raw = struct.pack("=H", af) + struct.pack(">H", sa[1]) + \
                socket.inet_pton(af, sa[0]) + b"\0" * 8
            return ctypes.create_string_buffer(raw, len(raw))
        if af == socket.AF_INET6:
            raw = struct.pack("=H", af) + struct.pack(">H", sa[1]) + \
                struct.pack(">I", sa[2]) + socket.inet_pton(af, sa[0]) + \
                struct.pack("=I", sa[3])
            return ctypes.create_string_buffer(raw, len(raw))
    raise VerbsError("cannot resolve %s" % host)


class MR(object):
    """A registered memory region that owns its buffer."""

    def __init__(self, pd, size, access):
        self.size = size
        # Page aligned, so that only the pages the region needs are pinned
        # (RLIMIT_MEMLOCK counts every page it touches)
        self._buf = (c_char * (size + 4095))()
        self.addr = (ctypes.addressof(self._buf) + 4095) & ~4095
        self._mr = _ib.ibv_reg_mr(pd, self.addr, size, access)
        if not self._mr:
            raise _err("ibv_reg_mr(%d bytes)" % size)
        self.lkey = ctypes.c_uint32.from_address(self._mr + _MR_LKEY).value
        self.rkey = ctypes.c_uint32.from_address(self._mr + _MR_RKEY).value

    def write(self, data, offset=0):
        if offset + len(data) > self.size:
            raise VerbsError("write past the end of the region")
        ctypes.memmove(self.addr + offset, data, len(data))

    def read(self, length, offset=0):
        if offset + length > self.size:
            raise VerbsError("read past the end of the region")
        return ctypes.string_at(self.addr + offset, length)

    def close(self):
        if self._mr:
            mr, self._mr = self._mr, None
            _ib.ibv_dereg_mr(mr)


def bytes_address(data):
    """Where the bytes of a bytes object are in memory (CPython keeps them
    where they are for the life of the object)."""
    return ctypes.cast(ctypes.c_char_p(data), c_void_p).value


class PinnedBytes(MR):
    """Part of an existing bytes object, registered where it is, not copied.

    The object is kept alive, and must not change, until close()."""

    def __init__(self, pd, data, offset, length, access):
        if not isinstance(data, bytes) or offset < 0 or \
                offset + length > len(data):
            raise VerbsError("not a region of a bytes object")
        self.size = length
        self._keep = data
        self.addr = bytes_address(data) + offset
        probe = min(length, 16)         # be sure the address is the data's
        if ctypes.string_at(self.addr, probe) != data[offset:offset + probe]:
            raise VerbsError("can not find the memory of a bytes object")
        self._mr = _ib.ibv_reg_mr(pd, self.addr, length, access)
        if not self._mr:
            raise _err("ibv_reg_mr(%d bytes in place)" % length)
        self.lkey = ctypes.c_uint32.from_address(self._mr + _MR_LKEY).value
        self.rkey = ctypes.c_uint32.from_address(self._mr + _MR_RKEY).value

    def close(self):
        MR.close(self)
        self._keep = None


class CmEvent(object):
    """A fetched rdma_cm event; the data is copied out and the event acked."""

    def __init__(self, type, status, private_data):
        self.type = type
        self.status = status
        self.private_data = private_data

    def __str__(self):
        return "%s (status %d)" % (_cm.rdma_event_str(self.type).decode(),
                                   self.status)


class Connection(object):
    """One RDMA connection: CM id, PD, one CQ for both queues, and the QP."""

    def __init__(self):
        load()
        self.ch = self.id = self.pd = self.cc = self.cq = self.qp = None
        self.ctx = None
        self._cq_events = 0
        self.ch = _cm.rdma_create_event_channel()
        if not self.ch:
            raise _err("rdma_create_event_channel")
        idp = c_void_p()
        if _cm.rdma_create_id(self.ch, byref(idp), None, RDMA_PS_TCP):
            self.close()
            raise _err("rdma_create_id")
        self.id = idp.value
        self.cm_fd = c_int.from_address(self.ch + _CM_CHANNEL_FD).value

    # ---- connection manager ---------------------------------------------
    def get_event(self, timeout=None):
        """Next CM event (None if there is none / on timeout)."""
        import select
        if timeout is not None:
            r, _, _ = select.select([self.cm_fd], [], [], timeout)
            if not r:
                return None
        evp = c_void_p()
        if _cm.rdma_get_cm_event(self.ch, byref(evp)):
            if ctypes.get_errno() in (errno.EAGAIN, errno.EINTR):
                return None
            raise _err("rdma_get_cm_event")
        ev = evp.value
        etype = c_int.from_address(ev + _EV_EVENT).value
        status = c_int.from_address(ev + _EV_STATUS).value
        pdata = None
        ptr = _ptr(ev + _EV_PRIVATE_DATA)
        plen = ctypes.c_uint8.from_address(ev + _EV_PRIVATE_DATA_LEN).value
        if etype == CM_ESTABLISHED and ptr and plen:
            pdata = ctypes.string_at(ptr, plen)
        _cm.rdma_ack_cm_event(ev)
        return CmEvent(etype, status, pdata)

    def expect(self, wanted, timeout):
        """Wait for a CM event of the given type, failing on an error event."""
        ev = self.get_event(timeout)
        if ev is None:
            raise VerbsError("timed out waiting for the RDMA connection")
        if ev.type != wanted:
            raise VerbsError("RDMA connect failed: %s" % ev)
        return ev

    def resolve(self, addr, timeout_ms):
        if _cm.rdma_resolve_addr(self.id, None, ctypes.addressof(addr),
                                 timeout_ms):
            raise _err("rdma_resolve_addr")
        self.expect(CM_ADDR_RESOLVED, timeout_ms / 1000.0 + 1)
        if _cm.rdma_resolve_route(self.id, timeout_ms):
            raise _err("rdma_resolve_route")
        self.expect(CM_ROUTE_RESOLVED, timeout_ms / 1000.0 + 1)
        self.ctx = _ptr(self.id + _CMID_VERBS)

    def connect(self, private_data, responder_resources, retry=6, rnr_retry=7):
        pd = ctypes.create_string_buffer(private_data, len(private_data)) \
            if private_data else None
        param = (c_char * CONN_PARAM_SIZE)()
        struct.pack_into("=QBBBBBBB", param, 0,
                         ctypes.addressof(pd) if pd else 0,
                         len(private_data) if pd else 0,
                         responder_resources, 0, 0, retry, rnr_retry, 0)
        if _cm.rdma_connect(self.id, byref(param)):
            raise _err("rdma_connect")
        return self.expect(CM_ESTABLISHED, 10.0)   # keeps pd alive until here

    def disconnect(self):
        if self.id:
            _cm.rdma_disconnect(self.id)

    # ---- queues -----------------------------------------------------------
    def setup_queues(self, max_send_wr, max_recv_wr):
        """PD, completion channel, one CQ and an RC QP."""
        self.pd = _ib.ibv_alloc_pd(self.ctx)
        if not self.pd:
            raise _err("ibv_alloc_pd")
        self.cc = _ib.ibv_create_comp_channel(self.ctx)
        if not self.cc:
            raise _err("ibv_create_comp_channel")
        self.cc_fd = c_int.from_address(self.cc + _COMP_CHANNEL_FD).value
        _set_nonblocking(self.cc_fd)
        _set_nonblocking(self.cm_fd)
        self.cq = _ib.ibv_create_cq(self.ctx, max_send_wr + max_recv_wr + 2,
                                    None, self.cc, 0)
        if not self.cq:
            raise _err("ibv_create_cq")
        self.arm()
        attr = (c_char * QP_INIT_ATTR_SIZE)()
        struct.pack_into("=QQQQIIIII", attr, 0, 0, self.cq, self.cq, 0,
                         max_send_wr, max_recv_wr, 1, 1, 0)
        struct.pack_into("=ii", attr, 52, IBV_QPT_RC, 0)
        if _cm.rdma_create_qp(self.id, self.pd, byref(attr)):
            raise _err("rdma_create_qp")
        self.qp = _ptr(self.id + _CMID_QP)

    def _fn(self, obj, offset, proto):
        """Provider function from the table in obj->context->ops"""
        table = _ptr(obj)                       # obj->context
        return proto(_ptr(table + offset))

    def arm(self):
        proto = ctypes.CFUNCTYPE(c_int, c_void_p, c_int)
        if self._fn(self.cq, _CTX_REQ_NOTIFY_CQ, proto)(self.cq, 0):
            raise VerbsError("ibv_req_notify_cq failed")

    def post_recv(self, mr, wr_id, length=None):
        sge = (c_char * SGE_SIZE)()
        struct.pack_into("=QII", sge, 0, mr.addr, length or mr.size, mr.lkey)
        wr = (c_char * RECV_WR_SIZE)()
        struct.pack_into("=QQQi", wr, 0, wr_id, 0, ctypes.addressof(sge), 1)
        bad = c_void_p()
        proto = ctypes.CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p)
        rc = self._fn(self.qp, _CTX_POST_RECV, proto)(self.qp, ctypes.addressof(wr),
                                                      ctypes.addressof(bad))
        if rc:
            raise VerbsError("ibv_post_recv failed: %s" % os.strerror(rc))

    def post_send(self, mr, length, wr_id):
        sge = (c_char * SGE_SIZE)()
        struct.pack_into("=QII", sge, 0, mr.addr, length, mr.lkey)
        wr = (c_char * SEND_WR_SIZE)()
        struct.pack_into("=QQQiiI", wr, 0, wr_id, 0, ctypes.addressof(sge), 1,
                         IBV_WR_SEND, IBV_SEND_SIGNALED)
        bad = c_void_p()
        proto = ctypes.CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p)
        rc = self._fn(self.qp, _CTX_POST_SEND, proto)(self.qp, ctypes.addressof(wr),
                                                      ctypes.addressof(bad))
        if rc:
            raise VerbsError("ibv_post_send failed: %s" % os.strerror(rc))

    def poll(self, max_wcs=16):
        """Completions as (wr_id, status, byte_len); drains the CQ."""
        proto = ctypes.CFUNCTYPE(c_int, c_void_p, c_int, c_void_p)
        poll_fn = self._fn(self.cq, _CTX_POLL_CQ, proto)
        buf = (c_char * (WC_SIZE * max_wcs))()
        out = []
        while True:
            n = poll_fn(self.cq, max_wcs, ctypes.addressof(buf))
            if n < 0:
                raise VerbsError("ibv_poll_cq failed")
            for i in range(n):
                wr_id, status, _op, _vendor, byte_len = \
                    struct.unpack_from("=QiiII", buf, i * WC_SIZE)
                out.append((wr_id, status, byte_len))
            if n < max_wcs:
                return out

    def completions(self):
        """Handle a completion-channel wakeup: ack it, re-arm, drain the CQ."""
        cqp, ctxp = c_void_p(), c_void_p()
        while _ib.ibv_get_cq_event(self.cc, byref(cqp), byref(ctxp)) == 0:
            _ib.ibv_ack_cq_events(cqp, 1)
        self.arm()                  # before draining, so none is missed
        return self.poll()

    # ---- teardown ----------------------------------------------------------
    def close(self):
        """Free everything, in the order the libraries need."""
        if self.qp:
            _cm.rdma_destroy_qp(self.id)
            self.qp = None
        for name, fn in (("cq", _ib.ibv_destroy_cq),
                         ("cc", _ib.ibv_destroy_comp_channel),
                         ("pd", _ib.ibv_dealloc_pd)):
            obj = getattr(self, name)
            if obj:
                fn(obj)
                setattr(self, name, None)
        if self.id:
            _cm.rdma_destroy_id(self.id)
            self.id = None
        if self.ch:
            _cm.rdma_destroy_event_channel(self.ch)
            self.ch = None
