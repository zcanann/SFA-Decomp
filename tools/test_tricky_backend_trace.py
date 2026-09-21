from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import tricky_backend_trace as trace
from test_tricky_backend_graph import simplification_fixture


class BackendTraceTests(unittest.TestCase):
    def test_temporary_birth_capture_rejects_unsupported_modes_before_compiling(self):
        for platform, graph in [("linux", True), ("win32", True), ("darwin", False)]:
            with self.subTest(platform=platform, graph=graph), patch.object(trace.sys, "platform", platform), \
                    patch.object(trace.subprocess, "run") as run, \
                    self.assertRaisesRegex(ValueError, "requires macOS and --graph"):
                trace.run_capture(Path("unused.c"), Path("unused"), ["unused"], graph=graph,
                                  temporary_names=["@1899"])
            run.assert_not_called()

    def test_inspection_uses_selected_unit(self):
        final = {"name": "headDisplayDraw", "stage": "FINAL CODE"}
        with ExitStack() as stack:
            stack.enter_context(patch.object(trace, "read_object", return_value=SimpleNamespace(functions={"headDisplayDraw": b""})))
            stack.enter_context(patch.object(trace, "validate_snapshot"))
            stack.enter_context(patch.object(trace, "validate_alignment", return_value=[]))
            stack.enter_context(patch.object(trace.strucdiff, "text_lines", return_value=[]))
            analyse = stack.enter_context(patch.object(trace.strucdiff, "analyse", return_value=([], [], [], 0, 0)))
            trace.inspect([final], Path("unused.o"), ["headDisplayDraw"], unit="main/dlls/engine/0/0")
            analyse.assert_called_once_with("main/dlls/engine/0/0", "headDisplayDraw", "unused.o")

    def test_paired_graph_color_policy_is_replayed(self):
        before, after = simplification_fixture([32, 33])
        initial = {"name": "trickyDigTunnel", "stage": "BEFORE GPR SIMPLIFICATION",
                   "graph_colored": False, "coloring_graph": before,
                   "available_gprs": [28, 29], "original_gpr_count": 34,
                   "color_policy": {"initial": [29], "reserve": [28], "reserve_cursor": 0, "blocked": []}}
        colored = {"name": "trickyDigTunnel", "stage": "BEFORE GPR REWRITE",
                   "graph_colored": True, "coloring_graph": after}
        final = {"name": "trickyDigTunnel", "stage": "FINAL CODE"}
        with ExitStack() as stack:
            stack.enter_context(patch.object(trace, "read_object", return_value=SimpleNamespace(functions={"trickyDigTunnel": b""})))
            stack.enter_context(patch.object(trace, "validate_snapshot"))
            stack.enter_context(patch.object(trace, "validate_rewrite"))
            stack.enter_context(patch.object(trace, "validate_alignment", return_value=[]))
            stack.enter_context(patch.object(trace.strucdiff, "text_lines", return_value=[]))
            stack.enter_context(patch.object(trace.strucdiff, "analyse", return_value=([], [], [], 0, 0)))
            result = trace.inspect([initial, colored, final], Path("unused.o"), ["trickyDigTunnel"], require_graph=True)
            self.assertEqual(len(result["trickyDigTunnel"]["color_decisions"]), 2)
            self.assertTrue(result["trickyDigTunnel"]["simplification_replayed"])
            for snapshot in (initial, colored):
                snapshot["register_class"] = 3
            del initial["available_gprs"], initial["original_gpr_count"]
            result = trace.inspect([initial, colored, final], Path("unused.o"), ["trickyDigTunnel"],
                                   require_graph=True, required_register_class=3)
            self.assertEqual(result["trickyDigTunnel"]["register_class"], 3)
            self.assertEqual(result["trickyDigTunnel"]["high_degree_removals"], [])
            self.assertEqual(len(result["trickyDigTunnel"]["color_decisions"]), 2)
            self.assertFalse(result["trickyDigTunnel"]["simplification_replayed"])
            initial["simplification_policy"] = {"available": [28, 29], "temporary_cutoff": 34}
            result = trace.inspect([initial, colored, final], Path("unused.o"), ["trickyDigTunnel"], require_graph=True)
            self.assertTrue(result["trickyDigTunnel"]["simplification_replayed"])
            initial["simplification_policy"]["available"] = [28]
            with self.assertRaisesRegex(ValueError, "replayed simplification disagrees"):
                trace.inspect([initial, colored, final], Path("unused.o"), ["trickyDigTunnel"], require_graph=True)
            initial["simplification_policy"]["available"] = [28, 29]
            with self.assertRaisesRegex(ValueError, "missing requested register class"):
                trace.inspect([initial, colored, final], Path("unused.o"), ["trickyDigTunnel"],
                              require_graph=True, required_register_class=4)
            initial["color_policy"]["initial"] = [28, 29]
            with self.assertRaisesRegex(ValueError, "replayed color disagrees"):
                trace.inspect([initial, colored, final], Path("unused.o"), ["trickyDigTunnel"], require_graph=True)
            del initial["color_policy"]
            with self.assertRaisesRegex(ValueError, "missing FPR coloring policy"):
                trace.inspect([initial, colored, final], Path("unused.o"), ["trickyDigTunnel"], require_graph=True)

    def test_final_attempt_reports_unreplayed_retry_and_checks_final_coloring(self):
        before, after = simplification_fixture([32, 33])
        smaller, _ = simplification_fixture([32])
        smaller.pop()
        smaller[32]["neighbors"] = []
        smaller[32]["prefix"][5] = smaller[32]["prefix"][8] = 0
        initial = {"name": "trickyDigTunnel", "stage": "BEFORE GPR SIMPLIFICATION",
                   "graph_colored": False, "coloring_graph": before,
                   "available_gprs": [28, 29], "original_gpr_count": 34,
                   "color_policy": {"initial": [29], "reserve": [28], "reserve_cursor": 0, "blocked": []}}
        earlier = dict(initial, coloring_graph=smaller)
        colored = {"name": "trickyDigTunnel", "stage": "BEFORE GPR REWRITE",
                   "graph_colored": True, "coloring_graph": after}
        final = {"name": "trickyDigTunnel", "stage": "FINAL CODE"}
        stages = [earlier, initial, colored, final]
        with ExitStack() as stack:
            stack.enter_context(patch.object(trace, "read_object", return_value=SimpleNamespace(functions={"trickyDigTunnel": b""})))
            stack.enter_context(patch.object(trace, "validate_snapshot"))
            rewrite = stack.enter_context(patch.object(trace, "validate_rewrite"))
            stack.enter_context(patch.object(trace, "validate_alignment", return_value=[]))
            stack.enter_context(patch.object(trace.strucdiff, "text_lines", return_value=[]))
            stack.enter_context(patch.object(trace.strucdiff, "analyse", return_value=([], [], [], 0, 0)))
            with self.assertRaisesRegex(ValueError, "unpaired initial"):
                trace.inspect(stages, Path("unused.o"), ["trickyDigTunnel"], require_graph=True)
            result = trace.inspect(stages, Path("unused.o"), ["trickyDigTunnel"],
                                   require_graph=True, final_allocation_attempt=True)["trickyDigTunnel"]
            self.assertEqual(result["unreplayed_allocation_attempts"],
                             [{"stage": earlier["stage"], "nodes": 33, "next_nodes": 34}])
            self.assertTrue(result["simplification_replayed"])
            self.assertEqual(len(result["color_decisions"]), 2)
            rewrite.assert_called_once_with(colored, final)
            with self.assertRaisesRegex(ValueError, "does not grow"):
                trace.inspect([initial, initial, colored, final], Path("unused.o"),
                              ["trickyDigTunnel"], require_graph=True, final_allocation_attempt=True)
            with self.assertRaisesRegex(ValueError, "unpaired initial"):
                trace.inspect([earlier, initial, final], Path("unused.o"),
                              ["trickyDigTunnel"], final_allocation_attempt=True)
            initial["color_policy"]["initial"] = [28, 29]
            with self.assertRaisesRegex(ValueError, "replayed color disagrees"):
                trace.inspect(stages, Path("unused.o"), ["trickyDigTunnel"],
                              require_graph=True, final_allocation_attempt=True)

    def test_reordered_duplicate_and_dangling_graph_pairs_are_rejected(self):
        before, after = simplification_fixture([32, 33])
        initial = {"name": "trickyDigTunnel", "stage": "BEFORE GPR SIMPLIFICATION",
                   "graph_colored": False, "coloring_graph": before,
                   "available_gprs": [28, 29], "original_gpr_count": 34}
        colored = {"name": "trickyDigTunnel", "stage": "BEFORE GPR REWRITE",
                   "graph_colored": True, "coloring_graph": after}
        final = {"name": "trickyDigTunnel", "stage": "FINAL CODE"}
        for stages, message in [([colored, initial], "without a preceding"),
                                ([initial, initial, colored], "unpaired initial"),
                                ([initial, colored, initial], "unpaired initial"),
                                ([initial, colored, colored], "without a preceding")]:
            with self.subTest(stages=[s["stage"] for s in stages]), ExitStack() as stack:
                stack.enter_context(patch.object(trace, "read_object", return_value=SimpleNamespace(functions={})))
                stack.enter_context(patch.object(trace, "validate_snapshot"))
                stack.enter_context(patch.object(trace, "validate_rewrite"))
                with self.assertRaisesRegex(ValueError, message):
                    trace.inspect(stages + [final], Path("unused.o"), ["trickyDigTunnel"], require_graph=True)

    def test_graph_request_cannot_succeed_with_only_ordinary_dumps(self):
        snapshot = {"name": "trickyDigTunnel", "stage": "FINAL CODE", "head": 0,
                    "blocks": [], "labels": {}}
        with patch.object(trace, "read_object", return_value=SimpleNamespace(functions={})), \
                self.assertRaisesRegex(ValueError, "missing GPR graph for trickyDigTunnel"):
            trace.inspect([snapshot], Path("unused.o"), ["trickyDigTunnel"], require_graph=True)


if __name__ == "__main__":
    unittest.main()
