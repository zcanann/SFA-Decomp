"""Check the time-list pulse's signed color arguments at the text API boundary."""
import ctypes
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]


class TimeListColorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('clang')
        if not compiler:
            raise unittest.SkipTest('clang is required for the source-body harness')
        source = (ROOT / 'src/dlls/engine/0/0.c').read_text()
        start, end = find_function_body(source, 'timeListDraw')
        declaration = source.rfind('void timeListDraw', 0, start)
        cls.temporary = tempfile.TemporaryDirectory(prefix='sfa-time-list-')
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / 'time_list.c'
        fixture.write_text(r'''
#define _TYPES_H_
typedef unsigned char u8;
typedef short s16;
typedef unsigned short u16;
typedef float f32;
#include "main/gametext_color_api.h"
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
int _fltused;
#else
#define EXPORT
#endif
#define GAMEUI_TIME_LIST_COUNT 6
typedef struct { u16 ids[GAMEUI_TIME_LIST_COUNT]; } GameUiTimeIdList;
static const GameUiTimeIdList sTimeListTimeBits = {{1, 2, 3, 4, 5, 6}};
typedef struct { void *tex28, *tex2C, *tex30, *tex34; } HudTextures;
static HudTextures textures;
static void* hudTextures = &textures;
static int pauseMenuState;
static s16 gTimeListPulseAngle, gTimeListPulseAngleStep;
static f32 gTimeListPulseAmplitude, gTimeListPulseBias, sineValue;
static u8 gTimeListPromptSelection;
static const char sGameUiTimeFormat[] = "";
static int colors[12], colorCount, sineAngle;
static void drawTexture(void* texture, f32 x, f32 y, int alpha, int scale) {}
static void drawScaledTexture(void* texture, f32 x, f32 y, int alpha, int scale,
                              int width, int height, int flags) {}
static f32 fsin16Precise(u16 angle) { sineAngle = angle; return sineValue; }
void gameTextSetColor(int r, int g, int b, int a) {
    if (colorCount < 3) {
        colors[colorCount * 4] = r; colors[colorCount * 4 + 1] = g;
        colors[colorCount * 4 + 2] = b; colors[colorCount * 4 + 3] = a;
    }
    colorCount++;
}
static void gameTextShowAt(int id, int x, int y) {}
static void gameTextShow(int id) {}
static void gameTextSetWindowById(int id) {}
static int mainGetBit(int id) { return 0; }
static int sprintf(char* out, const char* format, ...) { out[0] = 0; return 0; }
static void gameTextShowTimeStr(char* text) {}
''' + source[declaration:end + 1] + r'''
EXPORT void run(int selection, int paused, int angle, int step,
                f32 amplitude, f32 bias, f32 sine, int* out) {
    int i;
    gTimeListPromptSelection = selection;
    pauseMenuState = paused;
    gTimeListPulseAngle = angle; gTimeListPulseAngleStep = step;
    gTimeListPulseAmplitude = amplitude; gTimeListPulseBias = bias;
    sineValue = sine; sineAngle = -1; colorCount = 0;
    for (i = 0; i < 12; i++) colors[i] = -999;
    timeListDraw(0, 0, 0);
    out[0] = colorCount; out[1] = gTimeListPulseAngle; out[2] = sineAngle;
    for (i = 0; i < 12; i++) out[i + 3] = colors[i];
}
''')
        cls.runs = []
        for optimization in ('-O0', '-O2'):
            library = directory / (optimization[1:] + ('.dll' if sys.platform == 'win32' else '.so'))
            command = [compiler, '-shared', optimization, '-fno-builtin', '-ffp-contract=off',
                       '-I', str(ROOT / 'include'), str(fixture), '-o', str(library)]
            command += ['-fuse-ld=lld', '-nostdlib', '-Wl,/noentry'] if sys.platform == 'win32' else ['-fPIC']
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            module = ctypes.CDLL(str(library))
            if sys.platform == 'win32':
                kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
                cls.addClassCleanup(kernel.FreeLibrary, module._handle)
            module.run.argtypes = [ctypes.c_int] * 4 + [ctypes.c_float] * 3 + [ctypes.POINTER(ctypes.c_int)]
            module.run.restype = None
            cls.runs.append((optimization, module.run))

    def test_prompt_color_arguments(self):
        cases = [(55.0, 200.0, sine) for sine in (-1.0, -0.5, 0.0, 0.5, 1.0)]
        # Out-of-byte-range values expose premature narrowing at the caller.
        cases += [(0.0, bias, 0.0) for bias in (-257.75, -1.75, 256.75, 511.75)]
        for optimization, run in self.runs:
            for selection in (0, 1, 2, 255):
                for amplitude, bias, sine in cases:
                    with self.subTest(optimization=optimization, selection=selection, bias=bias, sine=sine):
                        out = (ctypes.c_int * 15)()
                        run(selection, 0, 32700, 1200, amplitude, bias, sine, out)
                        brightness = int(amplitude * sine + bias)
                        first, second = (brightness, 255) if selection == 1 else (255, brightness)
                        expected = [3, -31636, 33900] + [first] * 3 + [255] + [second] * 3 + [255] * 5
                        self.assertEqual(list(out), expected)

    def test_paused_preserves_pulse(self):
        for optimization, run in self.runs:
            with self.subTest(optimization=optimization):
                out = (ctypes.c_int * 15)()
                run(1, 1, 32700, 1200, 55.0, 200.0, 1.0, out)
                self.assertEqual(list(out), [0, 32700, -1] + [-999] * 12)


if __name__ == '__main__':
    unittest.main()
