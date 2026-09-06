"""The project compiler default is independent of the linker release."""
import ast
from pathlib import Path
import unittest

from project import Object, ProjectConfig


class CompilerVersionTests(unittest.TestCase):
    def setUp(self):
        self.config = ProjectConfig()
        self.config.version = "GSAE01"
        self.config.compiler_version = "GC/1.3"
        self.config.linker_version = "GC/1.3.2"

    def test_project_default(self):
        obj = Object(False, "test.c").resolve(self.config, {})
        self.assertEqual(obj.options["mw_version"], "GC/1.3")

    def test_legacy_linker_fallback(self):
        self.config.compiler_version = None
        obj = Object(False, "test.c").resolve(self.config, {})
        self.assertEqual(obj.options["mw_version"], "GC/1.3.2")

    def test_explicit_library_version(self):
        obj = Object(False, "test.c").resolve(self.config, {"mw_version": "GC/2.0"})
        self.assertEqual(obj.options["mw_version"], "GC/2.0")

    def test_explicit_object_version(self):
        obj = Object(False, "test.c", mw_version="GC/1.2.5n").resolve(
            self.config, {"mw_version": "GC/2.0"}
        )
        self.assertEqual(obj.options["mw_version"], "GC/1.2.5n")

    def test_active_config_has_no_compiler_overrides(self):
        source = Path(__file__).resolve().parents[1] / "configure.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword):
                self.assertNotEqual(node.arg, "mw_version")
            elif isinstance(node, ast.Dict):
                self.assertFalse(any(isinstance(key, ast.Constant) and key.value == "mw_version"
                                     for key in node.keys))


if __name__ == "__main__":
    unittest.main()
