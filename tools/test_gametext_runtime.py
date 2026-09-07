"""Check native gametext BSS layout and execute fallback/parser source bodies."""
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


class GameTextRuntimeTests(unittest.TestCase):
    def test_retail_bss_boundaries(self):
        obj = ROOT / 'build/GSAE01/src/main/gametext.o'
        if not obj.exists():
            self.skipTest('build the gametext source object first')
        snapshot = read_object(obj)
        expected = {
            'sGameTextFallbackElapsedFrames': (0x000, 0x20),
            'sGameTextFallbackRequestDelta': (0x020, 0x20),
            'sGameTextFallbackDefs': (0x040, 0x60),
            'sGameTextFallbackStrings': (0x0A0, 0x20),
            'sGameTextFallbackBuffers': (0x0C0, 0x200),
            'sSubtitleCtrlCmdScratch': (0x2C0, 0xC0),
            'sGameTextPath': (0x380, 0x40),
            'sGameTextCommandStringBuffer': (0x3C0, 0x800),
            'lbl_8033A540': (0xBC0, 0xA00),
            'gGameTextCharsets': (0x15C0, 0xA0),
            'curGameTexts': (0x1660, 0x260),
        }
        self.assertEqual(snapshot.sections['.bss'][3], 0x18C0)
        for name, (offset, size) in expected.items():
            with self.subTest(symbol=name):
                self.assertEqual(snapshot.symbols[name][:3], ('.bss', offset, size))


class GameTextRuntimeHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('clang')
        if not compiler:
            raise unittest.SkipTest('clang is required for source-body tests')
        source = (ROOT / 'src/main/gametext.c').read_text()
        headers = '\n'.join((ROOT / path).read_text() for path in (
            'include/main/gametext_internal.h', 'include/main/gametext_box_api.h',
            'include/main/textrender_internal.h'))
        records = '\n'.join(re.search(r'typedef struct(?: ' + name + r')?\s*\{[^}]*\} '
                                      + name + ';', headers).group()
                            for name in ('GameTextDef', 'TextFont', 'GameTextBox', 'SubtitleCmd'))
        constants = '\n'.join(line for line in headers.splitlines() if line.startswith('#define ')
                              and re.match(r'#define (GAMETEXT_(FALLBACK|BOX_COUNT|PENDING_SOURCE|SLOT_|INVALID_)|SUBTITLE_CONTROL_COMMAND)', line))
        private_arrays = '\n'.join(line.removeprefix('extern ') for line in headers.splitlines()
                                   if line.startswith('extern ') and re.search(
                                       r'\b(sGameText(Fallback|Path|CommandString)|gGameText(LastEntry|FallbackRequestDelta)|sSubtitleCtrlCmdScratch)', line))
        bodies = []
        for name, prefix in (('gameTextInitRendererState', 'void'),
                             ('gameTextSelectFallbackBuffer', 'static inline void'),
                             ('gameTextGet', 'void*'), ('gameTextGetPhrase', 'void*'),
                             ('gameTextGetStr', 'void*'), ('subtitleParseControlCmds', 'SubtitleCmd*')):
            start, end = find_function_body(source, name)
            declaration = source.rfind(prefix + ' ' + name, 0, start)
            if declaration < 0:
                raise ValueError('missing declaration: ' + name)
            bodies.append(source[declaration:end + 1])
        cls.temporary = tempfile.TemporaryDirectory(prefix='sfa-text-runtime-')
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        fixture = directory / 'runtime.c'
        fixture.write_text(r'''
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef short s16;
typedef float f32;
typedef struct TextGlyph TextGlyph;
typedef struct Texture Texture;
#define NULL ((void*)0)
#define ARRAY_COUNT(x) (sizeof(x) / sizeof((x)[0]))
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
int _fltused;
#else
#define EXPORT
#endif
''' + records + '\n' + constants + '\n' + private_arrays + r'''
static TextFont gGameTextCharsets[4], *gameTextFonts;
static GameTextBox gTextBoxes[GAMETEXT_BOX_COUNT];
static int gameTextCharset, curLanguage, curGameTextDir, gGameTextLastLanguage, gGameTextLastDir;
static int gGameTextMeasureOnly, gGameTextCommandCount, gGameTextBufferIndex;
static int gGameTextShadowOffsetX, gGameTextShadowOffsetY, gGameTextShadowEnabled;
static u8 gGameTextColorR, gGameTextColorG, gGameTextColorB, gGameTextColorA;
static u8 gGameTextShadowColorR, gGameTextShadowColorG, gGameTextShadowColorB, lbl_803DC980;
static void *gCurTextBox, *gGameTextStringStore;
static char *gCurTextBuffer, *gGameTextCommandStringCursor;
static f32 timeDelta;
static char* sMapDirectoryNameTable[] = {"test"};
static char sGameTextBlankFormat[] = "";
static int atlasCalls, storeSize, formatKind, allocatedSize, copiedSize, argCount;
static union { void* alignment; u8 bytes[256]; } allocation;
static void gameTextBuildSystemFontAtlas(void) { atlasCalls++; }
static void* mmCreateMemoryStore(int size) { storeSize = size; return &storeSize; }
static void* mmAlloc(int size, int tag, int flags) {
    allocatedSize = size;
    return allocation.bytes;
}
static int equalFormat(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}
static int sprintf(char* destination, const char* format, ...) {
    formatKind = format == sGameTextBlankFormat ? 0 :
                 equalFormat(format, "<%d's not in %s>") ? 1 :
                 equalFormat(format, "<%d, doesn't have phrase %d>") ? 2 : 3;
    destination[0] = (char)('A' + formatKind);
    destination[1] = 0;
    return 1;
}
static void* memcpy(void* destination, const void* source, unsigned long long size) {
    unsigned long long i, available = sizeof(sSubtitleCtrlCmdScratch);
    copiedSize = (int)size;
    /* Capture retail's overread request without executing host out-of-bounds reads. */
    for (i = 0; i < size && i < available; i++) ((u8*)destination)[i] = ((const u8*)source)[i];
    return destination;
}
static u32 utf8GetNextChar(u8* source, int* size) {
    *size = 2;
    return ((u32)source[0] << 8) | source[1];
}
static int ctrlCharLen(u32 code) { return argCount; }
''' + '\n'.join(bodies) + r'''
EXPORT int checkInit(void) {
    int i, j;
    for (i = 0; i < GAMETEXT_BOX_COUNT; i++) {
        gTextBoxes[i].maxWidth = 100 + i; gTextBoxes[i].maxHeight = 200 + i;
        gTextBoxes[i].width = gTextBoxes[i].height = 0;
        gTextBoxes[i].flags = 0x5678; gTextBoxes[i].alpha = 0;
    }
    for (i = 0; i < 4; i++) {
        TextFont* font = &gGameTextCharsets[i];
        font->glyphs = (TextGlyph*)1; font->entries = (GameTextDef*)1;
        font->glyphCount = font->entryCount = 11;
        font->status = 3; font->timer = 77; font->dirId = font->languageId = 2;
        for (j = 0; j < 3; j++) font->textures[j] = (Texture*)1;
    }
    for (i = 0; i < 8; i++) {
        sGameTextFallbackElapsedFrames[i] = 17; sGameTextFallbackRequestDelta[i] = 29;
        for (j = 0; j < 64; j++) sGameTextFallbackBuffers[i][j] = 'Z';
    }
    gCurTextBox = (void*)1; gGameTextMeasureOnly = gGameTextCommandCount = gGameTextBufferIndex = 7;
    gGameTextShadowColorR = gGameTextShadowColorG = gGameTextShadowColorB = lbl_803DC980 = 3;
    atlasCalls = storeSize = 0;
    gameTextInitRendererState();
    for (i = 0; i < GAMETEXT_BOX_COUNT; i++)
        if (gTextBoxes[i].width != 100 + i || gTextBoxes[i].height != 200 + i ||
            gTextBoxes[i].flags != 0x5678 || gTextBoxes[i].alpha != 255) return 1;
    for (i = 0; i < 8; i++) {
        GameTextDef* entry = &sGameTextFallbackDefs[i];
        if (entry->identifier != 65535 || entry->count != 1 || entry->boxId != 255 ||
            entry->alignH || entry->alignV || entry->language ||
            entry->strings != &sGameTextFallbackStrings[i] ||
            *entry->strings != sGameTextFallbackBuffers[i] ||
            sGameTextFallbackElapsedFrames[i] != 17 || sGameTextFallbackRequestDelta[i] != 29) return 2;
        for (j = 0; j < 64; j++) if (sGameTextFallbackBuffers[i][j] != 'Z') return 2;
    }
    for (i = 0; i < 4; i++) {
        TextFont* font = &gGameTextCharsets[i];
        if (font->glyphs || font->entries || font->glyphCount || font->entryCount ||
            font->status || font->timer || font->dirId != 255 || font->languageId != 6) return 3;
        for (j = 0; j < 3; j++) if (font->textures[j]) return 4;
    }
    if (gameTextFonts != &gGameTextCharsets[2] || gameTextCharset != 2 ||
        gGameTextLastEntry != sGameTextFallbackDefs || gCurTextBuffer != sGameTextFallbackBuffers[0] ||
        gGameTextCommandStringCursor != sGameTextCommandStringBuffer || gGameTextBufferIndex ||
        gGameTextCommandCount || gCurTextBox || gGameTextMeasureOnly || lbl_803DC980 ||
        curLanguage != -1 || curGameTextDir != 3 || gGameTextLastLanguage != -1 || gGameTextLastDir != -1 ||
        gGameTextColorR != 255 || gGameTextColorG != 255 || gGameTextColorB != 255 || gGameTextColorA != 255 ||
        gGameTextShadowColorR || gGameTextShadowColorG || gGameTextShadowColorB ||
        gGameTextShadowOffsetX != 5 || gGameTextShadowOffsetY != 5 || !gGameTextShadowEnabled ||
        atlasCalls != 1 || storeSize != 0x800 || gGameTextStringStore != &storeSize) return 5;
    return 0;
}
EXPORT int checkRing(int method, int status, int previous) {
    void* result;
    int next = (previous + 1) % 8;
    gameTextInitRendererState();
    gameTextFonts->status = status;
    gGameTextBufferIndex = previous;
    result = method == 0 ? gameTextGet(42) : method == 1 ? gameTextGetPhrase(42, 0) : gameTextGetStr(42);
    return result == &sGameTextFallbackDefs[next] && gGameTextBufferIndex == next &&
           gGameTextLastEntry == result && gCurTextBuffer == sGameTextFallbackBuffers[next] &&
           gGameTextFallbackRequestDelta == &sGameTextFallbackRequestDelta[next] &&
           sGameTextFallbackDefs[next].identifier == 65535 && formatKind == 3;
}
EXPORT int checkLookup(int mode, int position, int delta) {
    GameTextDef entries[3];
    char* phrases[] = {"first", "second"};
    GameTextDef* result;
    int i;
    gameTextInitRendererState(); curGameTextDir = 0;
    for (i = 0; i < 3; i++) {
        entries[i].identifier = 100 + i; entries[i].count = 2; entries[i].strings = phrases;
    }
    gameTextFonts->status = 2; gameTextFonts->entries = entries; gameTextFonts->entryCount = 3;
    timeDelta = (f32)delta;
    if (mode == 0) return gameTextGet(100 + position) == &entries[position] &&
                         gameTextGetStr(100 + position) == phrases[0] &&
                         gameTextGetPhrase(100 + position, 1) == phrases[1] && !gGameTextBufferIndex;
    if (mode == 1) {
        result = gameTextGet(500);
        return result == &sGameTextFallbackDefs[1] && result->identifier == 500 &&
               sGameTextFallbackRequestDelta[1] == 0 && formatKind == 0;
    }
    if (mode == 2) {
        sGameTextFallbackDefs[position].identifier = 500;
        sGameTextFallbackElapsedFrames[position] = 77;
        sGameTextFallbackRequestDelta[position] = 88;
        formatKind = -1;
        result = gameTextGet(500);
        return result == &sGameTextFallbackDefs[position] && !gGameTextBufferIndex &&
               sGameTextFallbackElapsedFrames[position] == 0 &&
               sGameTextFallbackRequestDelta[position] == (f32)delta && formatKind == (delta >= 120 ? 1 : -1);
    }
    result = gameTextGetPhrase(100, 2);
    return result == &sGameTextFallbackDefs[1] && result->identifier == 65535 && formatKind == 2;
}
EXPORT int checkParser(int count, int args) {
    u8 input[256];
    int i, j, offset = 0, outputCount = -1, accepted = count > 16 ? 16 : count;
    SubtitleCmd* result;
    argCount = args; allocatedSize = copiedSize = 0;
    for (i = 0; i < 16; i++) {
        sSubtitleCtrlCmdScratch[i].code = 0x12345678;
        sSubtitleCtrlCmdScratch[i].r = sSubtitleCtrlCmdScratch[i].g =
        sSubtitleCtrlCmdScratch[i].b = sSubtitleCtrlCmdScratch[i].a = 0x5678;
    }
    for (i = 0; i < count; i++) {
        input[offset++] = 0xE0; input[offset++] = (u8)i;
        for (j = 0; j < args; j++) { input[offset++] = (u8)i; input[offset++] = (u8)(j + 1); }
    }
    input[offset++] = 0; input[offset] = 0;
    result = subtitleParseControlCmds((char*)input, &outputCount);
    if (!count) return !result && outputCount == -1 && !allocatedSize && !copiedSize;
    if (result != (SubtitleCmd*)allocation.bytes || outputCount != (count > 16 ? 17 : count) ||
        allocatedSize != outputCount * 12 || copiedSize != allocatedSize) return 0;
    if (sSubtitleCtrlCmdScratch[0].code != (u32)(0xE000 + accepted - 1)) return 0;
    for (j = 0; j < 4; j++) {
        u16 value = j < args ? (u16)(((accepted - 1) << 8) | (j + 1)) : 0x5678;
        if (((u16*)&sSubtitleCtrlCmdScratch[0].r)[j] != value) return 0;
    }
    for (i = 1; i < 16; i++) if (sSubtitleCtrlCmdScratch[i].code != 0x12345678) return 0;
    return 1;
}
''')
        library = directory / ('runtime.dll' if sys.platform == 'win32' else 'runtime.so')
        command = [compiler, '-shared', '-O2', '-fno-builtin', str(fixture), '-o', str(library)]
        command += ['-fuse-ld=lld', '-nostdlib', '-Wl,/noentry'] if sys.platform == 'win32' else ['-fPIC']
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        cls.library = ctypes.CDLL(str(library))
        if sys.platform == 'win32':
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
            cls.addClassCleanup(kernel.FreeLibrary, cls.library._handle)
        for name, count in [('checkInit', 0), ('checkRing', 3), ('checkLookup', 3), ('checkParser', 2)]:
            function = getattr(cls.library, name)
            function.argtypes = [ctypes.c_int] * count
            function.restype = ctypes.c_int

    def test_initialization(self):
        self.assertEqual(self.library.checkInit(), 0)

    def test_unavailable_font_ring_wrap(self):
        for method in range(3):
            for status in (0, 1, 3, 4):
                for previous in range(8):
                    with self.subTest(method=method, status=status, previous=previous):
                        self.assertEqual(self.library.checkRing(method, status, previous), 1)

    def test_loaded_lookup_and_delayed_fallback(self):
        cases = [(0, i, 1) for i in range(3)] + [(1, 0, 1), (3, 0, 1)]
        cases += [(2, i, delta) for i in range(8) for delta in (0, 1, 119, 120, 121)]
        for mode, position, delta in cases:
            with self.subTest(mode=mode, position=position, delta=delta):
                self.assertEqual(self.library.checkLookup(mode, position, delta), 1)

    def test_parser_retains_first_record_overwrite_and_overread(self):
        for count in (0, 1, 2, 16, 17, 18):
            for args in (0, 1, 4):
                with self.subTest(count=count, args=args):
                    self.assertEqual(self.library.checkParser(count, args), 1)


if __name__ == '__main__':
    unittest.main()
