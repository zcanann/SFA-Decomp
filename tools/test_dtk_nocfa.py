"""The experimental overlay must survive DTK normalization and refresh on input edits."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dtk_nocfa


class OverlayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.build = self.root / "build with spaces"
        self.config = self.root / "config/GSAE01"
        self.config.mkdir(parents=True)
        (self.config / "symbols.txt").write_text(dtk_nocfa.SYMBOL + "\n")
        (self.config / "config.yml").write_text("symbols: config/GSAE01/symbols.txt\n")
        self.root_patch = patch.object(dtk_nocfa, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_preserves_dtk_enrichment_without_touching_canonical_input(self):
        config, symbols = dtk_nocfa.write_overlay(self.build)
        self.assertIn('"', config.read_text())  # Quoted YAML path with spaces.
        self.assertEqual(symbols.read_text(), dtk_nocfa.ANNOTATED + "\n")
        enriched = symbols.read_text() + "// analyzer result\n"
        symbols.write_text(enriched)
        modified = symbols.stat().st_mtime_ns
        self.assertEqual(dtk_nocfa.write_overlay(self.build), (config, symbols))
        self.assertEqual(symbols.read_text(), enriched)
        self.assertEqual(symbols.stat().st_mtime_ns, modified)
        self.assertEqual((self.config / "symbols.txt").read_text(), dtk_nocfa.SYMBOL + "\n")

    def test_refreshes_after_canonical_input_changes(self):
        config, symbols = dtk_nocfa.write_overlay(self.build)
        (self.config / "symbols.txt").write_text(dtk_nocfa.SYMBOL + "\n// new symbol input\n")
        dtk_nocfa.write_overlay(self.build)
        self.assertIn("// new symbol input", symbols.read_text())
        (self.config / "config.yml").write_text("symbols: config/GSAE01/symbols.txt\nname: main\n")
        dtk_nocfa.write_overlay(self.build)
        self.assertIn("name: main", config.read_text())

    def test_refuses_changed_function_metadata(self):
        (self.config / "symbols.txt").write_text(dtk_nocfa.ANNOTATED + "\n")
        with self.assertRaisesRegex(RuntimeError, "re-audit"):
            dtk_nocfa.write_overlay(self.build)


if __name__ == "__main__":
    unittest.main()
