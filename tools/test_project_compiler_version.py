"""The project compiler default is independent of the linker release."""
import os
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import patch

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


class ActiveCompilerProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        previous_directory = Path.cwd()
        try:
            os.chdir(root)
            with patch.object(sys, "argv", ["configure.py", "-v", "GSAE01", "--matching"]), \
                    patch("tools.project.generate_build") as generate:
                namespace = runpy.run_path(str(root / "configure.py"))
                cls.config = namespace["config"]
                generate.assert_called_once_with(cls.config)
            cls.objects = {
                obj.name: obj.resolve(cls.config, lib)
                for lib in cls.config.libs for obj in lib["objects"]
            }
            cls.dolphin_lib = namespace["DolphinLib"]("test", [Object(False, "test.c")])
        finally:
            os.chdir(previous_directory)

    def test_game_code_uses_gc13(self):
        self.assertEqual(self.config.compiler_version, "GC/1.3")
        for name, obj in self.objects.items():
            if obj.options["progress_category"] == "game" and name != "main/zlb.c":
                with self.subTest(source=name):
                    self.assertEqual(obj.options["mw_version"], "GC/1.3")

    def test_dolphin_library_default_is_gc125n(self):
        obj = self.dolphin_lib["objects"][0].resolve(self.config, self.dolphin_lib)
        self.assertEqual(obj.options["mw_version"], "GC/1.2.5n")
        for name in ("dolphin/os/OS.c", "dolphin/gx/GXTexture.c", "dolphin/vi/vi.c"):
            with self.subTest(source=name):
                self.assertEqual(self.objects[name].options["mw_version"], "GC/1.2.5n")
                self.assertTrue(self.objects[name].completed)

    def test_sdk_and_middleware_keep_their_profiles(self):
        expected = {
            "dolphin/mtx/mtx.c": "GC/1.2.5",
            "dolphin/mtx/vec.c": "GC/1.2.5",
            "dolphin/thp/THPDec.c": "GC/1.2.5",
            "dolphin/OdemuExi2/DebuggerDriver.c": "GC/1.2.5",
            "dolphin/TRK_MINNOW_DOLPHIN/mainloop.c": "GC/1.3",
            "Runtime.PPCEABI.H/__start.c": "GC/1.2.5n",
            "Runtime.PPCEABI.H/__mem.c": "GC/1.3",
            "Runtime.PPCEABI.H/__va_arg.c": "GC/1.3.2",
            "dolphin/MSL_C/PPCEABI/bare/H/floorf.c": "GC/1.2.5n",
            "dolphin/MSL_C/PPCEABI/bare/H/mbstring.c": "GC/1.3.2r",
            "dolphin/MSL_C/PPCEABI/bare/H/mem.c": "GC/1.3",
            "musyx/runtime/synth.c": "GC/1.2.5n",
            "musyx/runtime/hw_break.c": "GC/2.0",
        }
        for name, compiler in expected.items():
            with self.subTest(source=name):
                self.assertEqual(self.objects[name].options["mw_version"], compiler)
                self.assertTrue(self.objects[name].completed)

    def test_prodg_and_linker_remain_independent(self):
        self.assertEqual(self.objects["main/zlb.c"].options["custom_rule"], "prodg")
        self.assertEqual(self.config.linker_version, "GC/1.3.2")

    def test_vector_reflection_preserves_separate_rounding(self):
        obj = self.objects["dolphin/mtx/vec.c"]
        self.assertEqual(obj.options["mw_version"], "GC/1.2.5")
        self.assertEqual(obj.options["extra_cflags"], ["-fp_contract", "off"])

    def test_matrix_projection_preserves_separate_rounding(self):
        obj = self.objects["dolphin/mtx/mtx.c"]
        self.assertEqual(obj.options["mw_version"], "GC/1.2.5")
        self.assertEqual(obj.options["extra_cflags"], ["-DGEKKO", "-fp_contract", "off"])

    def test_float_math_uses_native_cpp_linkage_and_initialization(self):
        for name, compiler in (("trigf", "GC/1.2.5"), ("hyperbolicsf", "GC/1.2.5n")):
            with self.subTest(source=name):
                obj = self.objects[f"dolphin/MSL_C/PPCEABI/bare/H/{name}.c"]
                self.assertEqual(obj.options["mw_version"], compiler)
                self.assertEqual(obj.options["extra_cflags"], ["-lang=c++"])
                self.assertTrue(obj.completed)

    def test_exponential_tables_use_normal_small_data_rules(self):
        prefix = "dolphin/MSL_C/PPCEABI/bare/H/"
        constants = self.objects[prefix + "float.c"]
        self.assertEqual(constants.options["mw_version"], "GC/1.2.5n")
        self.assertTrue(constants.completed)
        exponentials = self.objects[prefix + "exponentialsf.c"]
        self.assertEqual(exponentials.options["mw_version"], "GC/1.2.5n")
        self.assertEqual(exponentials.options["extra_cflags"], ["-O3,p", "-opt", "nopeephole"])


if __name__ == "__main__":
    unittest.main()
