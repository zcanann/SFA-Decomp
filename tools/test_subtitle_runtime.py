"""Check subtitle storage and execute the recovered scheduling source bodies."""
import ctypes
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from brute_match import find_function_body
from tricky_object_compare import read_object

ROOT = Path(__file__).resolve().parents[1]


class SubtitleLayoutTests(unittest.TestCase):
    def test_native_storage(self):
        path = ROOT / 'build/GSAE01/src/main/subtitle.o'
        if not path.exists():
            self.skipTest('build the subtitle source object first')
        obj = read_object(path)
        self.assertEqual(obj.sections['.bss'][3], 0xc00)
        self.assertEqual(obj.symbols['gSubtitleLineTable'][:3], ('.bss', 0, 0xc00))
        self.assertNotIn('gSubtitleLineStrs', obj.symbols)
        self.assertNotIn('gSubtitleLineTimes', obj.symbols)


class SubtitleHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('clang')
        if not compiler:
            raise unittest.SkipTest('clang is required for source-body tests')
        source = (ROOT / 'src/main/subtitle.c').read_text()
        source = re.sub(r'^#include.*\n', '', source, flags=re.M)
        header = '\n'.join((ROOT / path).read_text() for path in (
            'include/main/subtitle.h', 'include/main/gametext_internal.h',
            'include/main/gametext_box_api.h', 'include/main/textrender_internal.h'))
        records = '\n'.join(re.search(r'typedef struct(?: ' + name + r')?\s*\{[^}]*\} '
                                      + name + ';', header).group()
                            for name in ('SubtitleLineTable', 'SubtitleCmd', 'GameTextDef', 'GameTextBox'))
        constants = '\n'.join(line for line in header.splitlines()
                              if re.match(r'#define (SUBTITLE_LINE_COUNT|TEXT_CTRL_(SEQ_TIME|COLOR))\s', line))
        drawing = (ROOT / 'src/main/textrender_drawbox.c').read_text()
        start, end = find_function_body(drawing, 'subtitleInit')
        initializer = drawing[drawing.rfind('void subtitleInit', 0, start):end + 1]
        cls.temporary = tempfile.TemporaryDirectory(prefix='sfa-subtitle-')
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / 'subtitle.c'
        fixture.write_text(PREFIX + constants + '\n' + records + MOCKS + source + initializer + CHECKS)
        cls.modules = []
        for optimization in ('-O0', '-O2'):
            library = directory / (optimization[1:] + ('.dll' if sys.platform == 'win32' else '.so'))
            command = [compiler, '-shared', optimization, '-fno-builtin', str(fixture), '-o', str(library)]
            command += ['-fuse-ld=lld', '-nostdlib', '-Wl,/noentry'] if sys.platform == 'win32' else ['-fPIC']
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            module = ctypes.CDLL(str(library))
            if sys.platform == 'win32':
                kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
                cls.addClassCleanup(kernel.FreeLibrary, module._handle)
            cls.modules.append((optimization, module))

    def check(self, name, cases):
        for optimization, module in self.modules:
            function = getattr(module, name)
            function.argtypes = [ctypes.c_int]
            function.restype = ctypes.c_int
            for case in range(cases):
                with self.subTest(optimization=optimization, case=case):
                    self.assertEqual(function(case), 0)

    def test_partial_initialization(self):
        self.check('checkInit', 1)

    def test_stop_ownership_and_directory(self):
        self.check('checkStop', 6)

    def test_line_wrapping_and_timing(self):
        self.check('checkBuild', 8)

    def test_playback_and_color(self):
        self.check('checkUpdate', 64)

    def test_inactive_and_short_tracks(self):
        self.check('checkShortTrack', 12)

    def test_build_gate(self):
        self.check('checkGate', 48)


PREFIX = r'''
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef short s16;
typedef float f32;
#define NULL ((void*)0)
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
int _fltused;
#else
#define EXPORT
#endif
'''

MOCKS = r'''
static int gSubtitleActive, gSubtitlesEnabled, gGameTextSequenceMode, gGameTextSavedDir;
static int gGameTextPendingDir, gGameTextPendingTextId, gSubtitleElapsedFrames;
static int gSubtitleLineCount, gSubtitleBlockCount, gSubtitleLineIndex;
static u8 gSubtitleColorR, gSubtitleColorG, gSubtitleColorB, gSubtitleColorA, framesThisStep;
static f32 gSubtitleCurTime;
static GameTextBox gTextBoxes[148];
static GameTextDef text;
static int charset, charsetCalls, charsetValues[8], charsetFlags[8], hidden, states[2], directory;
static int freeDelay, delayCalls, delayValues[16], freeCalls, loadedDir;
static void* freed[8];
static int activeAtFree[8], getCalls, wrapCalls, wrapFailure, parseCalls, drawCalls, colorCalls;
static char *parsed, *drawn;
static int drawnColor[4], drawBox;
static float wrapWidth, wrapScale;
static char sourceStrings[3][2] = {{0, 0}, {1, 0}, {2, 0}};
static char* sourcePointers[3] = {sourceStrings[0], sourceStrings[1], sourceStrings[2]};
static char lineStorage[4][16] = {"AAAA", "BBBBBB", "CCC", "DDDDD"};
static char* wrapped[3][2] = {{lineStorage[0], lineStorage[1]}, {lineStorage[2], NULL}, {lineStorage[3], NULL}};
static int oldBlocks[4];
static int timeCodes[3][3];
static SubtitleCmd commands[3];
static int parseEnabled;

void subtitleStop(void);
static int gameTextGetCharset(void) { return charset; }
static void gameTextSetCharset(int value, int flags) {
    charsetValues[charsetCalls] = value; charsetFlags[charsetCalls++] = flags; charset = value;
}
static int getHudHiddenFrameCount(void) { return hidden; }
static int mmSetFreeDelay(int value) {
    int old = freeDelay; delayValues[delayCalls++] = value; freeDelay = value; return old;
}
static void mm_free(void* block) {
    activeAtFree[freeCalls] = gSubtitleActive; freed[freeCalls++] = block;
}
static void gameTextLoadDir(int value) { loadedDir = value; }
static void gameTextSetColor(int r, int g, int b, int a) {
    colorCalls++; drawnColor[0] = r; drawnColor[1] = g; drawnColor[2] = b; drawnColor[3] = a;
}
static void gameTextShowStr(char* line, int box, int unused1, int unused2) {
    drawCalls++; drawn = line; drawBox = box;
}
static SubtitleCmd* subtitleParseControlCmds(char* line, int* count) {
    parseCalls++; parsed = line; *count = 3; return parseEnabled ? commands : NULL;
}
static int gameTextGetState(int slot) { return states[slot]; }
static int getCurGameText(void) { return directory; }
static void* gameTextGet(int id) { getCalls++; return &text; }
static int GameText_FindControlCodeArgs(u8* line, u32 code, int* args) {
    int i; for (i = 0; i < 3; i++) args[i] = timeCodes[line[0]][i]; return 3;
}
static char** gameTextWrapLines(char* line, f32 width, f32 scale, int* count, void* unused) {
    int index = (u8)line[0]; wrapCalls++; wrapWidth = width; wrapScale = scale;
    *count = index == 0 ? 2 : 1;
    return index == wrapFailure ? NULL : wrapped[index];
}
static int GameText_CountPrintableChars(u8* line) {
    int count = 0; while (line[count]) count++; return count;
}
'''

CHECKS = r'''
static void reset(void) {
    int i;
    gSubtitleActive = 1; gSubtitlesEnabled = 0; gGameTextSequenceMode = 0; gGameTextSavedDir = -1;
    gGameTextPendingDir = directory = 9; gGameTextPendingTextId = 42;
    gSubtitleElapsedFrames = 77; gSubtitleLineIndex = 2; gSubtitleLineCount = 123; gSubtitleBlockCount = 99;
    gSubtitleColorR = 10; gSubtitleColorG = 11; gSubtitleColorB = 12; gSubtitleColorA = 13;
    gSubtitleCurTime = 123.0f; framesThisStep = 60;
    charset = 7; charsetCalls = hidden = 0; states[0] = states[1] = 2;
    freeDelay = 5; delayCalls = freeCalls = getCalls = wrapCalls = 0; loadedDir = -99;
    parseCalls = drawCalls = colorCalls = 0; drawn = parsed = NULL; parseEnabled = 1;
    wrapFailure = -1; text.count = 3; text.strings = sourcePointers;
    gTextBoxes[10].maxWidth = 321; gTextBoxes[10].scale = 0.75f;
    for (i = 0; i < 256; i++) {
        gSubtitleLineTable.blocks[i] = &oldBlocks[i % 4];
        gSubtitleLineTable.lines[i] = lineStorage[i % 4];
        gSubtitleLineTable.times[i] = (float)i + 50.0f;
    }
    for (i = 0; i < 3; i++) {
        timeCodes[i][0] = 1; timeCodes[i][1] = 2 + i * 10; timeCodes[i][2] = 119;
        commands[i].code = TEXT_CTRL_COLOR;
        commands[i].r = 0x123; commands[i].g = 0x234; commands[i].b = 0x345; commands[i].a = 0x456;
    }
    commands[0].r = 1; commands[1].code = 0;
}
static int delaysCorrect(void) {
    int i;
    if (freeDelay != 5 || delayCalls != freeCalls * 2) return 0;
    for (i = 0; i < freeCalls; i++) if (delayValues[i * 2] || delayValues[i * 2 + 1] != 5) return 0;
    return 1;
}
EXPORT int checkInit(int unused) {
    int i; reset(); subtitleInit();
    for (i = 0; i < 256; i++) {
        if (gSubtitleLineTable.blocks[i]) return 1;
        if (gSubtitleLineTable.lines[i] != lineStorage[i % 4] || gSubtitleLineTable.times[i] != i + 50.0f) return 2;
    }
    if (gSubtitleActive || gSubtitlesEnabled != 1 || gGameTextSavedDir != -1) return 3;
    if (gSubtitleLineCount != 123 || gSubtitleBlockCount != 99 || gSubtitleElapsedFrames != 77 || gSubtitleLineIndex != 2) return 4;
    return 0;
}
EXPORT int checkStop(int mode) {
    int i, active = mode % 3; reset(); gSubtitleActive = active;
    gGameTextSavedDir = mode / 3 ? 7 : -1;
    gSubtitleBlockCount = 3; gSubtitleLineTable.blocks[1] = NULL;
    subtitleStop();
    if (!active) {
        if (freeCalls || delayCalls || loadedDir != -99 || gSubtitleLineTable.blocks[0] != &oldBlocks[0]) return 1;
        if (gGameTextSavedDir != (mode / 3 ? 7 : -1)) return 2;
    } else {
        if (gSubtitleActive || freeCalls != 2 || freed[0] != &oldBlocks[0] || freed[1] != &oldBlocks[2]) return 3;
        if (!delaysCorrect() || activeAtFree[0] || activeAtFree[1]) return 4;
        for (i = 0; i < 3; i++) if (gSubtitleLineTable.blocks[i]) return 5;
        if (loadedDir != (mode / 3 ? 7 : -99) || gGameTextSavedDir != -1) return 6;
    }
    if (gSubtitleLineTable.blocks[3] != &oldBlocks[3] || gSubtitleBlockCount != 3 || gSubtitleLineCount != 123) return 7;
    for (i = 0; i < 256; i++)
        if (gSubtitleLineTable.lines[i] != lineStorage[i % 4] || gSubtitleLineTable.times[i] != i + 50.0f) return 8;
    return 0;
}
EXPORT int checkBuild(int mode) {
    int i, expectedBlocks = 3, expectedLines = 4;
    int line = 0, block = 0;
    float expectedTimes[4];
    reset(); gGameTextSequenceMode = mode & 1;
    wrapFailure = mode / 2 - 1;
    if (wrapFailure >= 0) { expectedBlocks--; expectedLines -= wrapFailure == 0 ? 2 : 1; }
    subtitleBuildLineTable();
    if (gSubtitleActive != 2 || gSubtitleLineIndex || gSubtitleElapsedFrames) return 1;
    if (gSubtitleBlockCount != expectedBlocks || gSubtitleLineCount != expectedLines) return 2;
    if (freeCalls != expectedBlocks || !delaysCorrect() || wrapCalls != 3 || getCalls != 1) return 3;
    if (wrapWidth != 321.0f || wrapScale != 0.75f) return 4;
    for (i = 0; i < expectedBlocks; i++) if (freed[i] != &oldBlocks[i] || activeAtFree[i] != 1) return 5;
    if (gSubtitleLineTable.blocks[expectedBlocks] != &oldBlocks[expectedBlocks]) return 6;
    if (charset != 7 || charsetCalls != (mode & 1 ? 2 : 0)) return 7;
    if (charsetCalls && (charsetValues[0] != 1 || charsetValues[1] != 7 || charsetFlags[0] != 1 || charsetFlags[1] != 1)) return 8;
    for (i = 0; i < 3; i++) {
        int j;
        if (i == wrapFailure) continue;
        if (gSubtitleLineTable.blocks[block++] != wrapped[i]) return 9;
        for (j = 0; j < (i == 0 ? 2 : 1); j++)
            if (gSubtitleLineTable.lines[line++] != wrapped[i][j]) return 10;
    }
    for (i = expectedLines; i < 256; i++)
        if (gSubtitleLineTable.lines[i] != lineStorage[i % 4]) return 11;
    expectedTimes[0] = 63.0f; expectedTimes[1] = 67.0f; expectedTimes[2] = 73.0f; expectedTimes[3] = 83.0f;
    if (wrapFailure == 0) {
        expectedTimes[0] = 73.0f; expectedTimes[1] = 83.0f;
        expectedTimes[2] = expectedTimes[3] = SUBTITLE_TIME_NONE;
    } else if (wrapFailure == 1) {
        expectedTimes[1] = 71.0f; expectedTimes[2] = 83.0f; expectedTimes[3] = SUBTITLE_TIME_NONE;
    }
    for (i = 0; i < 4; i++) if (gSubtitleLineTable.times[i] != expectedTimes[i]) return 12;
    for (i = 4; i < 256; i++) if (gSubtitleLineTable.times[i] != SUBTITLE_TIME_NONE) return 13;
    return 0;
}
EXPORT int checkUpdate(int mode) {
    int i, ending = (mode >> 4) & 1, advance;
    reset(); gSubtitleActive = 2; gGameTextSequenceMode = mode & 1;
    hidden = (mode >> 1) & 1; parseEnabled = (mode >> 2) & 1;
    if (mode & 32) { commands[1].code = TEXT_CTRL_COLOR; commands[2].code = 0; }
    gSubtitleElapsedFrames = (mode & 8) ? 120 : 0;
    gSubtitleLineCount = 4; gSubtitleLineIndex = ending ? 2 : 0; gSubtitleBlockCount = 0;
    for (i = 0; i < 4; i++) gSubtitleLineTable.times[i] = (float)i;
    advance = gSubtitleElapsedFrames + (hidden ? 0 : 60) >= (ending ? 180 : 60);
    subtitleUpdateAndDraw(0);
    if (parseCalls != advance || (advance && parsed != lineStorage[ending ? 2 : 0])) return 1;
    if (gSubtitleLineIndex != (ending ? 2 : 0) + advance || gSubtitleElapsedFrames != ((mode & 8) ? 120 : 0) + (hidden ? 0 : 60)) return 2;
    if (gSubtitleCurTime != (float)gSubtitleElapsedFrames / 60.0f) return 3;
    if (advance && parseEnabled) {
        if (freeCalls != 1 || freed[0] != commands || !delaysCorrect()) return 4;
        if (gSubtitleColorR != 0x23 || gSubtitleColorG != 0x34 || gSubtitleColorB != 0x45 || gSubtitleColorA != 0x56) return 5;
    } else if (freeCalls || gSubtitleColorR != 10) return 6;
    if (ending && advance) {
        if (gSubtitleActive || drawCalls || colorCalls) return 7;
    } else {
        if (gSubtitleActive != 2 || drawCalls != 1 || colorCalls != 1 || drawn != lineStorage[gSubtitleLineIndex] || drawBox != 10) return 8;
        if (drawnColor[0] != gSubtitleColorR || drawnColor[1] != gSubtitleColorG || drawnColor[2] != gSubtitleColorB || drawnColor[3] != gSubtitleColorA) return 9;
    }
    if (charset != 7 || charsetCalls != (mode & 1 ? 2 : 0)) return 10;
    if (charsetCalls && (charsetValues[0] != 1 || charsetValues[1] != 7 || charsetFlags[0] != 2 || charsetFlags[1] != 2)) return 11;
    return 0;
}
EXPORT int checkShortTrack(int mode) {
    int active = mode % 3, count = (mode / 3) % 2, sequence = mode / 6;
    reset(); gSubtitleActive = active; gSubtitleLineCount = count;
    gSubtitleLineIndex = 0; gSubtitleElapsedFrames = 0; gGameTextSequenceMode = sequence;
    subtitleUpdateAndDraw(0);
    if (gSubtitleActive != active || gSubtitleLineIndex || parseCalls || freeCalls) return 1;
    if (active == 2) {
        if (drawCalls != 1 || drawn != lineStorage[0] || gSubtitleElapsedFrames != 60) return 2;
        if (charsetCalls != (sequence ? 2 : 0)) return 3;
    } else if (drawCalls || colorCalls || charsetCalls || gSubtitleElapsedFrames) return 4;
    return 0;
}
EXPORT int checkGate(int mode) {
    int sequence = mode & 1, ready = (mode >> 1) % 4, active = (mode / 8) % 3, wrongDir = mode / 24;
    int expected = ready == 2 && active == 1 && (sequence || !wrongDir);
    reset(); gGameTextSequenceMode = sequence; gSubtitleActive = active;
    states[sequence] = ready; if (wrongDir) directory++;
    text.count = 0;
    mainLoopDoGameText();
    if (getCalls != expected || gSubtitleActive != (expected ? 2 : active)) return 1;
    return 0;
}
'''


if __name__ == '__main__':
    unittest.main()
