"""Check production atan range reduction under host debug and optimized builds."""
import ctypes
import math
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AtanReductionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("clang is required for the source-body harness")
        source = (ROOT / "src/main/acosf.c").read_text()
        function = re.search(r"^float atanf\(.*?^\}", source, re.M | re.S).group()
        function = function.replace("float atanf(", "EXPORT float sfa_atanf(", 1)
        constants = "\n".join(re.findall(r"^const (?:float|double) \w+ = [^;]+;", source, re.M))
        cls.temporary = tempfile.TemporaryDirectory(prefix="sfa-atan-reduction-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / "atan.c"
        fixture.write_text(r'''
#define __fabsf __builtin_fabsf
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
int _fltused;
#else
#define EXPORT
#endif
''' + constants + "\n" + function)
        cls.functions = []
        for optimization in ("-O0", "-O2"):
            library = directory / (optimization[1:] + (".dll" if sys.platform == "win32" else ".so"))
            command = [compiler, "-shared", optimization, "-fno-builtin", "-Werror=unsequenced",
                       str(fixture), "-o", str(library)]
            command += (["-fuse-ld=lld", "-nostdlib", "-Wl,/noentry"]
                        if sys.platform == "win32" else ["-fPIC"])
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            module = ctypes.CDLL(str(library))
            if sys.platform == "win32":
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
                cls.addClassCleanup(kernel.FreeLibrary, module._handle)
            function = module.sfa_atanf
            function.argtypes = [ctypes.c_float]
            function.restype = ctypes.c_float
            cls.functions.append((optimization, module, function))

    def check_value(self, value):
        value = ctypes.c_float(value).value
        expected = math.atan(value)
        for optimization, _, function in self.functions:
            actual = function(value)
            if math.isnan(expected):
                self.assertTrue(math.isnan(actual), optimization)
            else:
                self.assertAlmostEqual(actual, expected, delta=2e-7,
                                       msg=(optimization, value, actual, expected))
                self.assertEqual(math.copysign(1.0, actual), math.copysign(1.0, expected),
                                 (optimization, value))

    def test_range_boundary_and_special_values(self):
        for value in (0.0, -0.0, 2.0 ** -149, -(2.0 ** -149), 0.5, -0.5,
                      1.0 - 2.0 ** -24, 1.0, 1.0 + 2.0 ** -23,
                      -1.0 + 2.0 ** -24, -1.0, -1.0 - 2.0 ** -23,
                      2.0, -2.0, 100.0, -100.0, math.inf, -math.inf, math.nan):
            with self.subTest(value=value):
                self.check_value(value)

    def test_dense_reduced_interval_and_large_magnitudes(self):
        for i in range(-1024, 1025):
            self.check_value(i / 512.0)
        rng = random.Random(31)
        for _ in range(512):
            self.check_value(rng.choice((-1.0, 1.0)) * 10.0 ** rng.uniform(-35.0, 35.0))


if __name__ == "__main__":
    unittest.main()
