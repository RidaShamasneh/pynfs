#!/usr/bin/env python3
"""
Minimal example: read a file from an NFSv4.1 export using the pynfs library.

Usage (from the nfs4.1 directory, after `python3 setup.py build`):
    ./read_example.py <server> <path-inside-export> [port]
    ./read_example.py 127.0.0.1 /hello.txt

<path-inside-export> is relative to the server's pseudo-fs root, i.e. the
same path you would see after mounting the server's root with NFSv4.
"""
import sys
import os

# Make the generated xdr/rpc packages importable when run from the source tree
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
sys.path.insert(0, os.path.join(here, ".."))

import nfs4client
import nfs_ops
from nfs4lib import check
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from rpc.security import AuthSys

op = nfs_ops.NFS4ops()


def main():
    server = sys.argv[1].encode()
    path = [c.encode() for c in sys.argv[2].split("/") if c]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 2049

    # 1. Connect and set credentials (AUTH_SYS as the current user)
    client = nfs4client.NFS4Client(server, port, minorversion=1)
    client.set_cred(AuthSys().init_cred(uid=os.getuid(), gid=os.getgid(),
                                        name=b"pynfs-example"))

    # 2. EXCHANGE_ID + CREATE_SESSION + RECLAIM_COMPLETE
    sess = client.new_client_session(b"read_example")

    # 3. PUTROOTFH, LOOKUP dir..., OPEN(file, read), GETFH
    dirpath, name = path[:-1], path[-1]
    ops = [op.putrootfh()] + [op.lookup(d) for d in dirpath]
    ops += [op.open(0, OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
                    OPEN4_SHARE_DENY_NONE,
                    open_owner4(0, b"read_example_owner"),
                    openflag4(OPEN4_NOCREATE),
                    open_claim4(CLAIM_NULL, name)),
            op.getfh()]
    res = sess.compound(ops)
    check(res, msg="open %s" % sys.argv[2])
    stateid = res.resarray[-2].stateid
    fh = res.resarray[-1].object

    # 4. READ until EOF
    data, offset = b"", 0
    while True:
        res = sess.compound([op.putfh(fh), op.read(stateid, offset, 32768)])
        check(res, msg="read")
        r = res.resarray[-1].switch.switch
        data += r.data
        offset += len(r.data)
        if r.eof:
            break

    # 5. CLOSE
    check(sess.compound([op.putfh(fh), op.close(0, stateid)]), msg="close")

    sys.stdout.buffer.write(data)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    main()
