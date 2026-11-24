"""NFS4Client's bound on the size of a COMPOUND reply (needs no server)."""
import unittest

from .common import (op, nfs4client, ANY_STATEID, FATTR4_SIZE, FATTR4_ACL,
                     FATTR4_FS_LOCATIONS, FATTR4_SEC_LABEL, nfs_argop4)

KB = 1024
FH = b"x"


def bound(ops, tag=b"tag", read_data_elsewhere=False):
    return nfs4client.reply_bound(ops, tag, read_data_elsewhere)


class ReplyBound(unittest.TestCase):
    def test_small_ops_have_a_small_bound(self):
        got = bound([op.putfh(FH), op.getattr(1 << FATTR4_SIZE)])
        self.assertIsNotNone(got)
        self.assertLess(got, 64 * KB)

    def test_the_tag_is_counted(self):
        self.assertGreaterEqual(bound([op.putfh(FH)], tag=b"t" * 10000), 10000)

    def test_read_counts_its_data_unless_it_comes_elsewhere(self):
        read = [op.putfh(FH), op.read(ANY_STATEID, 0, 1000000)]
        self.assertGreaterEqual(bound(read), 1000000)
        self.assertLess(bound(read, read_data_elsewhere=True), 64 * KB)

    def test_readdir_uses_its_maxcount(self):
        ops = [op.putfh(FH), op.readdir(0, b"\0" * 8, 1000, 100000,
                                        1 << FATTR4_SIZE)]
        self.assertGreaterEqual(bound(ops), 100000)
        self.assertLess(bound(ops), 100000 + 64 * KB)

    def test_ops_with_a_size_in_their_arguments(self):
        zero = b"\0" * 8
        self.assertGreaterEqual(bound([op.listxattrs(0, 20000)]), 20000)
        self.assertGreaterEqual(bound([op.getdeviceinfo(b"\0" * 16, 1, 30000,
                                                        0)]), 30000)
        self.assertGreaterEqual(bound([op.layoutget(
            False, 1, 1, 0, 100, 100, ANY_STATEID, 40000)]), 40000)
        self.assertGreaterEqual(bound([op.getdevicelist(1, 5000, 0, zero)]),
                                5000 * 16)
        self.assertGreaterEqual(bound([op.test_stateid([ANY_STATEID] * 5000)]),
                                5000 * 4)

    def test_small_results_of_newer_ops(self):
        for build in (lambda: op.removexattr(b"user.a"),
                      lambda: op.layoutreturn(False, 1, 1, None),):
            try:
                ops = [op.putfh(FH), build()]
            except Exception:
                continue
            self.assertLess(bound(ops) or 0, 64 * KB)

    def test_attributes_that_can_be_large_have_no_bound(self):
        for attr in (FATTR4_ACL, FATTR4_FS_LOCATIONS, FATTR4_SEC_LABEL):
            self.assertIsNone(bound([op.putfh(FH),
                                     op.getattr(1 << attr | 1 << FATTR4_SIZE)]),
                              attr)

    def test_ops_with_unbounded_results_have_no_bound(self):
        self.assertIsNone(bound([op.putfh(FH), op.getxattr(b"user.a")]))
        self.assertIsNone(bound([op.putfh(FH),
                                 op.read_plus(ANY_STATEID, 0, 100)]))

    def test_one_unknown_op_spoils_the_bound(self):
        self.assertIsNone(bound([op.putfh(FH), nfs_argop4(10044)]))   # ILLEGAL

    def test_malformed_ops_have_no_bound(self):
        self.assertIsNone(bound([object()]))


if __name__ == "__main__":
    unittest.main()
