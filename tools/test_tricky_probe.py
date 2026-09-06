import contextlib
import io
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import tricky_probe as probe


class TrickyProbeTests(unittest.TestCase):
    def test_current_residuals_replace_the_old_watchlist(self):
        report = {"functions": [
            {"name": "Tricky_render", "fuzzy_match_percent": 100.0},
            {"name": "trickyUpdateMovementState", "fuzzy_match_percent": 99.9},
            {"name": "newResidual", "fuzzy_match_percent": 96.0},
            {"name": "trickyAdjustStepAroundPoint", "fuzzy_match_percent": 99.25},
        ]}
        self.assertEqual(
            [function["name"] for function in probe.nonexact_functions(report)],
            ["newResidual", "trickyAdjustStepAroundPoint", "trickyUpdateMovementState"],
        )

    def test_missing_scores_are_not_exact(self):
        functions = [{"name": "missing"}, {"name": "null", "fuzzy_match_percent": None}]
        self.assertEqual(probe.nonexact_functions({"functions": functions}), functions)
        self.assertEqual(probe.nonexact_functions({}), [])

    def test_unit_rows_uses_a_fresh_structured_report(self):
        report = {
            "name": probe.REPORT_UNIT,
            "measures": {"fuzzy_match_percent": 99.5},
            "functions": [{"name": "residual", "size": 512, "fuzzy_match_percent": 99.0}],
        }
        output = io.StringIO()
        with (
            patch.object(probe.unitfuzzy, "find_unit", return_value={"unit": "live"}) as find,
            patch.object(probe.unitfuzzy, "measure", return_value=report) as measure,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(probe.unit_rows(), ["residual"])
        find.assert_called_once_with("GSAE01", probe.UNIT)
        measure.assert_called_once_with({"unit": "live"}, "GSAE01")
        self.assertIn("fuzzy=99.50000", output.getvalue())
        self.assertIn("512B  residual", output.getvalue())

    def test_build_has_a_thirty_second_timeout(self):
        completed = subprocess.CompletedProcess(["ninja"], 0, stdout="built")
        with patch.object(probe.subprocess, "run", return_value=completed) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                probe.build()
        self.assertEqual(run.call_args.args[0], ["ninja", probe.OBJ_TARGET])
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def test_build_timeout_is_not_hidden(self):
        with patch.object(probe.subprocess, "run", side_effect=subprocess.TimeoutExpired("ninja", 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                probe.build()

    def test_build_failure_is_not_hidden(self):
        completed = subprocess.CompletedProcess(["ninja"], 1, stdout="compile failed")
        with (
            patch.object(probe.subprocess, "run", return_value=completed),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            probe.build()

    def test_structural_counts_come_from_the_analysis(self):
        differences = [(" ", 0, 0), ("r", 1, 1), ("+", None, 2), ("M", 2, 3), ("-", 3, None)]
        output = io.StringIO()
        with (
            patch.object(probe.structural_diff, "analyse", return_value=(differences, [], [], 4, 4)) as analyse,
            contextlib.redirect_stdout(output),
        ):
            probe.strucdiff(["residual"])
        analyse.assert_called_once_with(probe.REPORT_UNIT, "residual")
        self.assertIn("target 4 / ours 4 ; STRUC 3 ; recolour 1", output.getvalue())

    def test_missing_function_is_not_reported_as_exact(self):
        with patch.object(probe.structural_diff, "analyse", return_value=([], [], [], 0, 0)):
            with self.assertRaisesRegex(RuntimeError, "function absent from both objects"):
                probe.strucdiff(["missing"])

    def test_main_deduplicates_explicit_and_current_residuals(self):
        argv = ["tricky_probe.py", "--no-build", "--all-struc", "--struc", "residual",
                "--all-ndiff", "--ndiff", "residual", "--link"]
        completed = subprocess.CompletedProcess([], 0, stdout="linked")
        with (
            patch.object(probe.sys, "argv", argv),
            patch.object(probe, "build") as build,
            patch.object(probe, "unit_rows", return_value=["residual", "another"]),
            patch.object(probe, "pool"),
            patch.object(probe, "strucdiff") as struc,
            patch.object(probe, "ndiff") as ndiff,
            patch.object(probe, "run", return_value=completed) as run,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(probe.main(), 0)
        build.assert_not_called()
        struc.assert_called_once_with(["residual", "another"])
        ndiff.assert_called_once_with(["residual", "another"])
        run.assert_called_once_with([probe.sys.executable, "tools/tricky_link_probe.py"])

    def test_baseline_is_read_before_building_even_for_the_current_output(self):
        events = []
        path = probe.ROOT / probe.OBJ_TARGET

        def read(current):
            self.assertEqual(current, path)
            events.append("read")
            return len(events)

        with (
            patch.object(probe.sys, "argv", ["tricky_probe.py", "--baseline-object", str(path)]),
            patch.object(probe, "read_object", side_effect=read),
            patch.object(probe, "build", side_effect=lambda: events.append("build")),
            patch.object(probe, "unit_rows", return_value=[]),
            patch.object(probe, "pool"),
            patch.object(probe, "compare_objects", return_value={"byte_identical": False}) as compare,
            patch.object(probe, "comparison_summary", return_value="changed") as summary,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(probe.main(), 0)
        self.assertEqual(events, ["read", "build", "read"])
        compare.assert_called_once_with(1, 3)
        summary.assert_called_once_with({"byte_identical": False})

    def test_object_details_requires_a_baseline(self):
        with (
            patch.object(probe.sys, "argv", ["tricky_probe.py", "--object-details"]),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as error,
        ):
            probe.main()
        self.assertEqual(error.exception.code, 2)

    def test_missing_baseline_fails_before_build(self):
        with (
            patch.object(probe.sys, "argv", ["tricky_probe.py", "--baseline-object", "missing.o"]),
            patch.object(probe, "read_object", side_effect=FileNotFoundError("missing.o")) as read,
            patch.object(probe, "build") as build,
            self.assertRaises(FileNotFoundError),
        ):
            probe.main()
        read.assert_called_once_with(Path("missing.o"))
        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
