"""Exercise the raw-DOL audit independently of generated retail objects."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import retail_pool_audit as pool
from version_progress import SplitRange


def words(*values):
    return struct.pack(">" + "I" * len(values), *values)


class DecoderTests(unittest.TestCase):
    def test_startup_ori_and_signed_addi(self):
        self.assertEqual(pool.sda2_base(words(0x3C40803E, 0x60426500)), 0x803E6500)
        self.assertEqual(pool.sda2_base(words(0x3C40803F, 0x3842FFFF)), 0x803EFFFF)
        for code in (words(0x3C40803E, 0x60626500),
                     words(0x3C40803E, 0x60426500) * 2):
            with self.assertRaisesRegex(ValueError, "expected one startup"):
                pool.sda2_base(code)

    def test_width_and_negative_displacement(self):
        self.assertEqual(pool.direct_load(0xC022FFFC, 0x1000), (0xFFC, 4))
        self.assertEqual(pool.direct_load(0xC822FFF8, 0x1000), (0xFF8, 8))
        self.assertEqual(pool.direct_load(0x88620000, 0x1000), (0x1000, 1))
        self.assertEqual(pool.direct_load(0xA8620000, 0x1000), (0x1000, 2))
        self.assertIsNone(pool.direct_load(0xC0230000, 0x1000))
        self.assertIsNone(pool.direct_load(0xD0220000, 0x1000))
        with self.assertRaisesRegex(ValueError, "r2-updating"):
            pool.direct_load(0xC4220000, 0x1000)

    def test_whole_load_must_fit_one_claim(self):
        claims = pool.SpanIndex([SplitRange("a.c", "sdata2", 8, 16),
                                SplitRange("b.c", "sdata2", 16, 24)])
        self.assertEqual(claims.owner(8, 8), "a.c")
        self.assertEqual(claims.owner(16, 8), "b.c")
        self.assertIsNone(claims.owner(12, 8))
        self.assertIsNone(claims.owner(7))
        self.assertIsNone(claims.owner(24))
        with self.assertRaisesRegex(ValueError, "overlapping"):
            pool.SpanIndex([SplitRange("a", "sdata2", 8, 17),
                            SplitRange("b", "sdata2", 16, 24)])


class DolAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "config" / "TEST"
        self.config.mkdir(parents=True)
        original = self.root / "orig" / "TEST" / "sys"
        original.mkdir(parents=True)
        self.path = original / "main.dol"
        data = bytearray(0x100)
        for index, address, payload in [
            (0, 0x1000, words(0x3C400000, 0x60428000, 0x4E800020)),
            (1, 0x2000, words(0xC0220000, 0xC8220004, 0xC022000C,
                             0xC0220010, 0xC0220000, 0xC0220000)),
            (14, 0x8000, bytes(range(24))),
        ]:
            struct.pack_into(">I", data, index * 4, len(data))
            struct.pack_into(">I", data, 0x48 + index * 4, address)
            struct.pack_into(">I", data, 0x90 + index * 4, len(payload))
            data.extend(payload)
        self.path.write_bytes(data)
        (self.config / "config.yml").write_text(f"hash: {hashlib.sha1(data).hexdigest()}\n")
        (self.config / "symbols.txt").write_text(
            "__init_registers = .init:0x00001000; // type:function size:0xC\n"
            "first = .text:0x00002000; // type:function size:0x10\n"
            "second = .text:0x00002010; // type:function size:0x4\n")
        (self.config / "splits.txt").write_text(
            "a.c:\n .text start:0x2000 end:0x2010\n .sdata2 start:0x8000 end:0x8008\n"
            "b.c:\n .text start:0x2010 end:0x2018\n .sdata2 start:0x8010 end:0x8018\n")

    def test_unclaimed_foreign_and_incoming_loads(self):
        report = pool.audit("TEST", ["src/a.c"], self.root)
        self.assertEqual(report["sda2_base"], 0x8000)
        self.assertEqual(report["summaries"], [{
            "source": "a.c", "loads": 4, "distinct_loads": 4,
            "outside_claim_loads": 3, "outside_claim_bytes": 12,
        }])
        self.assertEqual([load["pool_owner"] for load in report["loads"]],
                         ["a.c", None, None, "b.c"])
        self.assertEqual(report["loads"][1]["value"], "0405060708090a0b")
        self.assertEqual([load["function"] for load in report["incoming"]], ["second", None])
        self.assertEqual(report["other_consumers"], report["incoming"])
        self.assertEqual(len(json.loads(json.dumps(report))["loads"]), 4)
        self.assertIn("0x0000800C", pool.markdown(report))

    def test_repetitions_survive_and_multiple_sources_are_supported(self):
        report = pool.audit("TEST", ["a.c", "b.c", "a.c"], self.root)
        self.assertEqual(len(report["loads"]), 6)
        self.assertEqual(len(report["summaries"]), 2)
        self.assertEqual(report["incoming"], [])

    def test_other_consumer_of_unclaimed_bytes_is_visible(self):
        data = bytearray(self.path.read_bytes())
        text_offset = struct.unpack_from(">I", data, 4)[0]
        struct.pack_into(">I", data, text_offset + 20, 0xC022000C)
        self.path.write_bytes(data)
        (self.config / "config.yml").write_text(f"hash: {hashlib.sha1(data).hexdigest()}\n")
        report = pool.audit("TEST", ["a.c"], self.root)
        self.assertEqual(len(report["incoming"]), 1)
        self.assertEqual(len(report["other_consumers"]), 2)
        self.assertIsNone(report["other_consumers"][1]["pool_owner"])

    def test_hash_and_source_validation(self):
        with self.assertRaisesRegex(ValueError, "sources absent"):
            pool.audit("TEST", ["absent.c"], self.root)
        self.path.write_bytes(self.path.read_bytes() + b"wrong revision")
        with self.assertRaisesRegex(ValueError, "Retail hash mismatch"):
            pool.audit("TEST", ["a.c"], self.root)


if __name__ == "__main__":
    unittest.main()
