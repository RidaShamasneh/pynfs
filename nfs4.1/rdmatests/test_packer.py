"""Packing a COMPOUND without the data of its WRITE (needs no server)."""
import unittest

from .common import op, ANY_STATEID, FILE_SYNC4, FATTR4_SIZE, COMPOUND4args
import nfs4lib


def whole(ops):
    packer = nfs4lib.FancyNFS4Packer()
    packer.pack_COMPOUND4args(COMPOUND4args(b"tag", 2, ops))
    return packer.get_buffer()


def detaching(ops, detach=True):
    packer = nfs4lib.DetachingNFS4Packer()
    packer.detach_write = detach
    packer.pack_COMPOUND4args(COMPOUND4args(b"tag", 2, ops))
    return packer.get_buffer(), packer.detached


class DetachingPacker(unittest.TestCase):
    def write(self, data):
        return op.write(ANY_STATEID, 7, FILE_SYNC4, data)

    def test_putting_the_data_and_its_pad_back_gives_the_normal_packing(self):
        for length in (0, 1, 2, 3, 4, 5, 4095, 4096, 4097, 100003):
            data = bytes(range(256)) * (length // 256) + b"z" * (length % 256)
            for before, after in (([], []), ([op.putfh(b"fh")], []),
                                  ([op.putfh(b"fh")],
                                   [op.getattr(1 << FATTR4_SIZE), op.getfh()])):
                ops = before + [self.write(data)] + after
                packed, detached = detaching(ops)
                position, got = detached
                self.assertIs(got, data)
                pad = b"\0" * ((-length) % 4)
                self.assertEqual(packed[:position] + data + pad +
                                 packed[position:], whole(ops), (length, after))
                self.assertEqual(position % 4, 0)

    def test_the_length_word_is_kept(self):
        data = b"d" * 4097
        packed, (position, _) = detaching([self.write(data)])
        self.assertEqual(packed[position - 4:position],
                         (4097).to_bytes(4, "big"))

    def test_nothing_is_left_out_unless_asked(self):
        data = b"d" * 5000
        packed, detached = detaching([self.write(data)], detach=False)
        self.assertIsNone(detached)
        self.assertEqual(packed, whole([self.write(data)]))

    def test_only_the_first_write_is_left_out(self):
        a, b = b"a" * 5000, b"b" * 5000
        packed, (position, got) = detaching([self.write(a), self.write(b)])
        self.assertIs(got, a)
        self.assertIn(b, packed)                      # the second is in it
        self.assertEqual(packed[:position] + a + packed[position:],
                         whole([self.write(a), self.write(b)]))

    def test_the_callers_ops_are_not_changed(self):
        data = b"d" * 5000
        write = self.write(data)
        detaching([write])
        self.assertIs(write.opwrite.data, data)

    def test_other_ops_pack_as_usual(self):
        ops = [op.putfh(b"fh"), op.getattr(1 << FATTR4_SIZE)]
        self.assertEqual(detaching(ops), (whole(ops), None))


if __name__ == "__main__":
    unittest.main()
