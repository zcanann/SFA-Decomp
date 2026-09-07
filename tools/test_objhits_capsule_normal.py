"""Execute the capsule normal and its vector helpers with native float literals."""
import ctypes
import math
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]


def function_source(source, name, prefix):
    start, end = find_function_body(source, name)
    declaration = source.rfind(prefix + ' ' + name, 0, start)
    if declaration < 0:
        raise ValueError('missing function declaration: ' + name)
    return source[declaration:end + 1]


def normalized(vector):
    length = math.sqrt(sum(value * value for value in vector))
    return [value / length for value in vector] if length else list(vector)


class CapsuleNormalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('clang')
        if not compiler:
            raise unittest.SkipTest('clang is required for the source-body harness')
        source = (ROOT / 'src/main/objhits.c').read_text()
        vectors = (ROOT / 'src/main/vecmath_vec3.c').read_text()
        helpers = '\n'.join(function_source(vectors, name, prefix) for name, prefix in (
            ('Vec3_ScaleAdd', 'void'), ('Vec3_Normalize', 'f32'), ('Vec3_Cross', 'void')))
        function = function_source(source, 'ObjHits_CalcTaperedCapsuleNormal', 'float*')
        cls.temporary = tempfile.TemporaryDirectory(prefix='sfa-capsule-normal-')
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / 'capsule.c'
        fixture.write_text(r'''
typedef float f32;
#define sqrtf __builtin_sqrtf
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
int _fltused;
#else
#define EXPORT
#endif
''' + helpers + '\nEXPORT ' + function)
        cls.functions = []
        for optimization in ('-O0', '-O2'):
            library = directory / (optimization[1:] + ('.dll' if sys.platform == 'win32' else '.so'))
            command = [compiler, '-shared', optimization, '-fno-builtin', '-fno-math-errno',
                       str(fixture), '-o', str(library)]
            command += ['-fuse-ld=lld', '-nostdlib', '-Wl,/noentry'] if sys.platform == 'win32' else ['-fPIC']
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            module = ctypes.CDLL(str(library))
            if sys.platform == 'win32':
                kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
                cls.addClassCleanup(kernel.FreeLibrary, module._handle)
            function = module.ObjHits_CalcTaperedCapsuleNormal
            pointer = ctypes.POINTER(ctypes.c_float)
            function.argtypes = [pointer, ctypes.c_float, pointer, pointer, ctypes.c_float,
                                 ctypes.c_float, ctypes.c_float, pointer]
            function.restype = pointer
            cls.functions.append((optimization, module, function))

    def check_case(self, base, tip, point, axial, base_radius, tip_radius, length, expected):
        for optimization, _, function in self.functions:
            for alias in (False, True):
                with self.subTest(optimization=optimization, alias=alias, axial=axial,
                                  radii=(base_radius, tip_radius), tip=tip):
                    point_arg = (ctypes.c_float * 3)(*point)
                    base_arg = (ctypes.c_float * 3)(*base)
                    tip_arg = (ctypes.c_float * 3)(*tip)
                    output = point_arg if alias else (ctypes.c_float * 3)()
                    result = function(point_arg, axial, base_arg, tip_arg,
                                      base_radius, tip_radius, length, output)
                    self.assertEqual(ctypes.addressof(result.contents), ctypes.addressof(output))
                    for actual, reference in zip(output, expected):
                        self.assertAlmostEqual(actual, reference, delta=2e-6)

    def test_endpoint_and_interior_directions(self):
        base = (3.0, -2.0, 1.0)
        length = 10.0
        for axis, radial in (((0, 1, 0), (1, 0, 0)), ((0.6, 0.8, 0), (0, 0, 1))):
            tip = [base[i] + length * axis[i] for i in range(3)]
            for axial in (-1.0, 0.0, 2.5, 5.0, 10.0, 11.0):
                point = [base[i] + axial * axis[i] + 3 * radial[i] for i in range(3)]
                for base_radius, tip_radius in ((0.5, 0.5), (2, 2), (0.5, 2), (2, 0.5)):
                    if axial <= 0 or axial >= length:
                        # Both retail endpoint branches use point minus tip, including axial <= 0.
                        expected = normalized([point[i] - tip[i] for i in range(3)])
                    elif base_radius == tip_radius:
                        expected = radial
                    else:
                        # The two retail cross products reverse the radial direction for a taper.
                        slope = (tip_radius - base_radius) / length
                        expected = normalized([slope * axis[i] - radial[i] for i in range(3)])
                    self.check_case(base, tip, point, axial, base_radius, tip_radius, length, expected)

    def test_zero_length_and_zero_normal(self):
        self.check_case((1, 2, 3), (1, 2, 3), (1, 2, 3), 0, 1, 1, 0, (0, 0, 0))
        self.check_case((1, 2, 3), (1, 2, 3), (4, 2, 3), 0, 1, 2, 0, (1, 0, 0))


if __name__ == '__main__':
    unittest.main()
