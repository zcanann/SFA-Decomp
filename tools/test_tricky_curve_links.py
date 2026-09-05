import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from orig.tricky_curve_links import Curve, audit_links, collect_curves, parse_curves


def curve(ident, links=(-1, -1, -1, -1), mask=0, romlist="map", kind=0x24):
    return Curve(romlist, ident * 0x34, 0x34, ident, kind, 0, mask, links)


def record(size=0x34, object_id=110):
    data = bytearray(size)
    struct.pack_into(">HB", data, 0, object_id, size // 4)
    struct.pack_into(">I", data, 0x14, 123)
    if size >= 0x2C:
        struct.pack_into(">BBB4i", data, 0x19, 0x24, 3, 0x82, 7, -1, 9, -1)
    return bytes(data)


class TrickyCurveLinkTests(unittest.TestCase):
    def test_variable_record_sizes_and_signed_sentinel(self):
        rows = parse_curves(record() + record(0x44), "map")
        self.assertEqual([row.size for row in rows], [0x34, 0x44])
        self.assertEqual(rows[1].offset, 0x34)
        self.assertEqual(rows[0].links, (7, -1, 9, -1))
        self.assertEqual(rows[0].backward_mask, 0x82)
        self.assertEqual(rows[0].subtype, 3)

    def test_noncurve_records_are_skipped(self):
        self.assertEqual(parse_curves(record(0x18, 5), "map"), [])

    def test_malformed_records_are_rejected(self):
        for data in (b"\0", bytes(24), record()[:-1], record(0x18), record() + b"\0"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_curves(data, "map")

    def test_reciprocal_direction_bits(self):
        report = audit_links([curve(1, (2, -1, -1, -1)), curve(2, (1, -1, -1, -1), 1)])
        self.assertEqual(report["counts"]["opposite_bits"], 2)
        self.assertEqual(report["anomalies"], [])

    def test_same_bits_are_reported_not_repaired(self):
        rows = [curve(1, (2, -1, -1, -1)), curve(2, (1, -1, -1, -1))]
        report = audit_links(rows)
        self.assertEqual(report["counts"]["same_bits"], 2)
        self.assertEqual(rows[0].backward_mask, 0)
        self.assertEqual(len(report["anomalies"]), 2)

    def test_missing_nonreciprocal_and_duplicate_backlinks(self):
        for target, status in ((None, "missing_target"), (curve(2), "nonreciprocal"),
                               (curve(2, (1, 1, -1, -1)), "duplicate_reciprocal")):
            with self.subTest(status=status):
                rows = [curve(1, (2, -1, -1, -1))]
                if target:
                    rows.append(replace(target, kind=0))
                report = audit_links(rows)
                self.assertEqual(report["counts"][status], 1)

    def test_local_target_precedes_cross_map_id_variant(self):
        report = audit_links([curve(1, (2, -1, -1, -1)), curve(2, (1, -1, -1, -1), 1),
                              curve(2, romlist="variant", kind=0)])
        self.assertEqual(report["counts"]["opposite_bits"], 2)

    def test_multiple_external_targets_remain_ambiguous(self):
        report = audit_links([curve(1, (2, -1, -1, -1)), curve(2, romlist="a", kind=0),
                              curve(2, romlist="b", kind=0)])
        self.assertEqual(report["counts"]["ambiguous_target"], 1)

    def test_unique_cross_map_link_is_resolved(self):
        report = audit_links([curve(1, (2, -1, -1, -1)), curve(2, (1, -1, -1, -1), 1, "other")])
        self.assertEqual(report["counts"]["external_target"], 2)
        self.assertEqual(report["counts"]["opposite_bits"], 2)

    def test_empty_asset_directory_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            collect_curves(Path(directory))


if __name__ == "__main__":
    unittest.main()
