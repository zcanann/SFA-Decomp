"""Register correspondence must distinguish renumbering from changed lifetimes."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mwcc_register_compare import load_capture, match_roles
from tricky_backend_ir import COMPILER_SHA256


def capture(registers, colors=None, edges=()):
    graph = [{"prefix": [0] * 9, "neighbors": []} for _ in range(40)]
    for a, b in edges:
        graph[a]["neighbors"].append(b)
        graph[b]["neighbors"].append(a)
    colored = copy.deepcopy(graph)
    for i, node in enumerate(colored):
        node["prefix"][6] = (colors or {}).get(i, i if i < 32 else 7)
    final, records = [], {}
    for index, register in enumerate(registers):
        instruction = {"address": index + 1, "opcode": 0x3F,
                       "operands": [{"kind": 0, "register_class": 4, "number": register}]}
        records[index + 1] = copy.deepcopy(instruction)
        instruction["operands"][0]["number"] = colored[register]["prefix"][6]
        final.append(instruction)
    return {"class": 4, "final": final, "records": records, "graph": graph,
            "colored": colored, "object_sha256": "test"}


class RegisterComparisonTests(unittest.TestCase):
    def test_closed_graph_renumbering_and_changed_colors(self):
        left = capture([32, 33, 32], {32: 8, 33: 9}, [(32, 33), (32, 1)])
        right = capture([35, 34, 35], {35: 9, 34: 8}, [(35, 34), (35, 1)])
        result = match_roles(left, right)
        self.assertEqual(result["register_partition_conflicts"], {"left": {}, "right": {}})
        self.assertEqual(result["mapped_graph_edge_differences"], [])
        self.assertEqual(result["unmapped_graph_neighbors"], [])
        self.assertEqual(result["physical_changes"][0], {
            "left_virtual": 32, "right_virtual": 35, "left_physical": 8,
            "right_physical": 9, "instruction_indices": [0, 2]})

    def test_split_lifetime_is_not_a_renumbering(self):
        result = match_roles(capture([32, 32]), capture([34, 35]))
        self.assertEqual(result["register_partition_conflicts"]["left"], {"32": [34, 35]})

    def test_changed_interference_is_reported(self):
        result = match_roles(capture([32, 33], edges=[(32, 33)]), capture([34, 35]))
        self.assertEqual(len(result["mapped_graph_edge_differences"]), 2)

    def test_unmapped_neighbor_prevents_closed_graph_claim(self):
        result = match_roles(capture([32], edges=[(32, 39)]), capture([34]))
        self.assertEqual(result["unmapped_graph_neighbors"], [("left", 39)])

    def test_different_stream_is_rejected(self):
        right = capture([34])
        right["final"][0]["opcode"] = 0x3C
        with self.assertRaisesRegex(ValueError, "instruction shape"):
            match_roles(capture([32]), right)
        with self.assertRaisesRegex(ValueError, "instruction counts"):
            match_roles(capture([32]), capture([34, 35]))

    def test_fixed_register_cannot_be_renumbered(self):
        with self.assertRaisesRegex(ValueError, "fixed register"):
            match_roles(capture([3]), capture([4]))

    def test_object_hash_is_checked_before_reading_ir(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.json"
            path.write_text(json.dumps({"schema": 1, "compiler_sha256": COMPILER_SHA256,
                                        "object_sha256": hashlib.sha256(b"original").hexdigest()}))
            path.with_name("traced.o").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "object hash mismatch"):
                load_capture(path, "example")

    def test_retry_uses_final_graph_and_preserves_unverified_attempts(self):
        attempts = [{"nodes": 33, "next_nodes": 34}]
        first = {"name": "example", "stage": "BEFORE GPR SIMPLIFICATION",
                 "coloring_graph": ["old"]}
        final = {"name": "example", "stage": "BEFORE GPR SIMPLIFICATION",
                 "coloring_graph": ["final"]}
        rewrite = {"name": "example", "stage": "BEFORE GPR REWRITE",
                   "coloring_graph": ["colored"], "blocks": []}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.json"
            path.with_name("traced.o").write_bytes(b"object")
            path.write_text(json.dumps({
                "schema": 1, "compiler_sha256": COMPILER_SHA256,
                "object_sha256": hashlib.sha256(b"object").hexdigest(),
                "register_class": 4, "unit": "example",
                "snapshots": [first, final, rewrite, {"name": "example", "stage": "FINAL CODE"}],
            }))
            # Validation itself is covered by the backend replay suites. This
            # exercises selection after validation and keeps the strict default.
            def validate(*args, **kwargs):
                if not kwargs["final_allocation_attempt"]:
                    raise ValueError("unpaired initial GPR graph")
                return {"example": {"unreplayed_allocation_attempts": attempts}}

            with patch("mwcc_register_compare.inspect", side_effect=validate), \
                    patch("mwcc_register_compare.emitted_instructions", return_value=[]):
                with self.assertRaisesRegex(ValueError, "unpaired initial"):
                    load_capture(path, "example")
                result = load_capture(path, "example", final_allocation_attempt=True)
            self.assertEqual(result["graph"], ["final"])
            self.assertEqual(result["colored"], ["colored"])
            self.assertEqual(result["unreplayed_allocation_attempts"], attempts)


if __name__ == "__main__":
    unittest.main()
