#!/usr/bin/env python3
"""A fake RPC-over-RDMA server, to test the client's handling of what a real
server will not do on demand.  Needs pyverbs (python3-pyverbs).

    fakeserver.py ADDR PORT MODE

Accepts one connection, reads the first request, then, by MODE:

  disconnect  waits a little, then disconnects without answering
  hang        never answers
  credit      answers it with a grant of 1000 credits, then sends a callback
              (a backward CB_NULL) whose credit field is 77, and prints what
              the client replies with

It prints "ready" once it listens, and lines for the test to read.
"""
import struct
import sys
import time

from pyverbs.cmid import CMID, AddrInfo, ConnParam
from pyverbs.qp import QPInitAttr, QPCap
import pyverbs.cm_enums as ce

addr, port, mode = sys.argv[1], sys.argv[2], sys.argv[3]
ai = AddrInfo(src=addr, dst=None, service=port, port_space=ce.RDMA_PS_TCP,
              flags=ce.RAI_PASSIVE)
cap = QPCap(max_send_wr=4, max_recv_wr=4, max_send_sge=1, max_recv_sge=1)
listener = CMID(creator=ai, qp_init_attr=QPInitAttr(qp_type=2, qp_context=None,
                                                    cap=cap))
listener.listen()
print("ready", flush=True)
child = listener.get_request()
bufs = [child.reg_msgs(4096) for _ in range(2)]
for buf in bufs:
    child.post_recv(buf)
child.accept(ConnParam(resources=1, depth=1))


def send(msg):
    mr = child.reg_msgs(len(msg))
    mr.write(msg, len(msg))
    child.post_send(mr)
    child.get_send_comp()


wc = child.get_recv_comp()
request = bufs[0].read(wc.byte_len, 0)
xid, _vers, credit, _proc = struct.unpack(">IIII", request[:16])
print("request: credit field %d" % credit, flush=True)

if mode == "disconnect":
    time.sleep(0.3)
    child.disconnect()
elif mode == "hang":
    time.sleep(60)
elif mode == "credit":
    reply = struct.pack(">IIIIII", xid, 1, 0, 0, 0, 0)       # accepted NULL reply
    send(struct.pack(">IIIIIII", xid, 1, 1000, 0, 0, 0, 0) + reply)
    time.sleep(0.5)
    cb_xid = 0x777777            # NFS4_CALLBACK 0x40000000 version 1 proc 0
    call = struct.pack(">IIIIIIIIII", cb_xid, 0, 2, 0x40000000, 1, 0,
                       0, 0, 0, 0)
    send(struct.pack(">IIIIIII", cb_xid, 1, 77, 0, 0, 0, 0) + call)
    wc = child.get_recv_comp()
    answer = bufs[1].read(wc.byte_len, 0)
    rxid, _v, grant, proc = struct.unpack(">IIII", answer[:16])
    print("callback reply: xid %#x credit grant %d proc %d" %
          (rxid, grant, proc), flush=True)
    time.sleep(5)
