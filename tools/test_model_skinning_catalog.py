"""Exercise archive extents and serialized skinning records without retail assets."""

import struct
import unittest
import zlib

from orig.model_skinning_catalog import inspect_model, unpack_model


def archive(data, compressed=True):
    auxiliary = 12
    result = bytearray(auxiliary + 0x18)
    if compressed:
        packed = zlib.compress(data)
        # Outer loader reads include padding which is outside the inner stream.
        struct.pack_into('>4I', result, 0, 0xfacefeed, len(data), auxiliary, len(packed) + 32)
        result += struct.pack('>4s3I', b'ZLB\0', 1, len(data), len(packed))
        result += packed + b'\xcd' * 16
    else:
        struct.pack_into('>4I', result, 0, 0xe0e0e0e0, len(data), auxiliary, len(data))
        result += data
    return result


class ModelSkinningCatalogTests(unittest.TestCase):
    def test_padded_compressed_and_raw_records(self):
        data = bytes(range(256)) * 2
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                self.assertEqual(unpack_model(archive(data, compressed)), data)

    def test_truncated_outer_envelope(self):
        with self.assertRaises(ValueError):
            unpack_model(archive(b'payload')[:-1])

    def test_inner_size_and_extent_disagreement(self):
        for offset in (8, 12):
            record = archive(b'payload')
            field = 12 + 0x18 + offset
            value = struct.unpack_from('>I', record, field)[0]
            struct.pack_into('>I', record, field, value + 1)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                unpack_model(record)

    def test_nbt_records_and_padding_evidence(self):
        data = bytearray(0x240)
        data[0x24] = 8
        struct.pack_into('>I', data, 0x2c, 0x200)
        struct.pack_into('>H', data, 0xae, 1)
        data[0xb2] = 0x3e  # Signed six-bit scale -2.
        struct.pack_into('>2I', data, 0xc8, 0x100, 0x180)
        struct.pack_into('>3I', data, 0x160, 0, 0, 0)
        data[0x16c:0x174] = bytes([2, 7, 0, 1, 0, 3, 1, 1])
        data[0x180:0x186] = bytes([32, 96, 64, 64, 205, 205])
        data[0x201:0x213] = bytes(range(1, 19))
        result = inspect_model(data)
        job = result['jobs'][0]
        self.assertTrue(result['normal_triplets'])
        self.assertEqual((job['kind'], job['scale'], job['stride']), ('normal', -2, 9))
        chunk = job['chunks'][0]
        self.assertEqual(chunk['matrix_indices'], [2, 7])
        self.assertEqual(chunk['weight_sums'], {128: 2, 410: 1})
        self.assertEqual(chunk['cd_weight_indices'], [2])
        self.assertTrue(chunk['cd_weights_trailing'])
        self.assertEqual(chunk['cd_weight_zero_records'], 1)
        self.assertEqual((chunk['stream_slack'], chunk['weight_slack']), (4, 26))
        # A declared stream transfer must contain every processed record.
        data[0x172] = 6
        with self.assertRaises(ValueError):
            inspect_model(data)

    def test_unskinned_model(self):
        self.assertEqual(inspect_model(bytes(0xfc))['jobs'], [])


if __name__ == '__main__':
    unittest.main()
