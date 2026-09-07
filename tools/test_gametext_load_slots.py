"""Execute the production text-load search, loaders, and DVD callbacks on the host."""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]


class GameTextLoadSlotTests(unittest.TestCase):
    def test_load_slot_lifecycle(self):
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('clang is required for source-body tests')
        source = (ROOT / 'src/main/gametext.c').read_text()
        headers = '\n'.join((ROOT / path).read_text() for path in (
            'include/main/gametext_internal.h', 'include/main/textrender_internal.h'))
        records = '\n'.join(re.search(
            r'typedef struct(?: ' + name + r')?\s*\{[^}]*\} ' + name + ';', headers).group()
            for name in ('GameTextDef', 'TextFont', 'LanguageName', 'GameTextLoadSlot'))
        constants = '\n'.join(line for line in headers.splitlines()
                              if line.startswith('#define GAMETEXT_'))
        names = ('gameTextFindFreeLoadSlot', 'loadGameTextSequence', 'gameTextLoadForCurMap',
                 'gameTextLoadCancelCallback', 'gameTextLoadCompleteCallback')
        bodies = []
        for name in names:
            start, end = find_function_body(source, name)
            declaration = source.rfind('\n', 0, source.rfind(name, 0, start)) + 1
            bodies.append(source[declaration:end + 1])
        fixture = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef unsigned char u8;
typedef unsigned short u16;
typedef int s32;
typedef float f32;
typedef struct TextGlyph TextGlyph;
typedef struct DVDCommandBlock { int identity; } DVDCommandBlock;
typedef struct DVDFileInfo { DVDCommandBlock cb; } DVDFileInfo;
typedef void (*DVDCallback)(s32, DVDFileInfo*);
typedef void (*DVDCBCallback)(s32, DVDCommandBlock*);
''' + records + '\n' + constants + r'''
static GameTextLoadSlot curGameTexts[GAMETEXT_LOAD_SLOT_COUNT];
static TextFont gGameTextCharsets[GAMETEXT_PENDING_SOURCE_COUNT];
static LanguageName sLanguageNameTable[6] = {
    {"English"}, {"French"}, {"German"}, {"Italian"}, {"Japanese"}, {"Spanish"}
};
static char* sMapDirectoryNameTable[GAMETEXT_MAP_DIR_COUNT];
static char sGameTextPath[64];
static int curLanguage, curGameTextDir, gGameTextLastDir, gGameTextLastLanguage;
static int lbl_803DC9D0, lbl_803DC9D4, gameState, heap, freeDelay;
static int loads, frees, cancellations, completeCancel, scenarios;
static int bufferToken;
static DVDFileInfo* currentFileInfo;
static DVDCommandBlock* cancelledBlock;
static DVDCBCallback cancelCallback;
static void gameTextLoadCompleteCallback(s32, DVDFileInfo*);
static void gameTextLoadCancelCallback(s32, DVDCommandBlock*);
static int mmSetForceHeap3Only(int value) {
    int previous = heap;
    heap = value;
    return previous;
}
static int getGameState(void) { return gameState; }
static void mmSetFreeDelay(int value) { freeDelay = value; }
static void mm_free(void* value) {
    assert(freeDelay == 0);
    frees++;
}
static int DVDCancelAsync(DVDCommandBlock* block, DVDCBCallback callback) {
    assert(heap == 0);
    cancelledBlock = block;
    cancelCallback = callback;
    cancellations++;
    if (completeCancel) callback(0, block);
    return 1;
}
static void setFileInfo(DVDFileInfo* info) { currentFileInfo = info; }
static void* loadFileByPathAsync(char* path, int* size, int flag, DVDCallback callback) {
    assert(currentFileInfo != NULL && heap == 0 && flag == 1);
    assert(callback == gameTextLoadCompleteCallback);
    assert(path == sGameTextPath);
    loads++;
    *size = 123;
    return &bufferToken;
}
''' + '\n'.join(bodies) + r'''
static void reset(void) {
    memset(curGameTexts, 0, sizeof(curGameTexts));
    memset(gGameTextCharsets, 0, sizeof(gGameTextCharsets));
    memset(sGameTextPath, 0, sizeof(sGameTextPath));
    for (int i = 0; i < GAMETEXT_MAP_DIR_COUNT; i++) sMapDirectoryNameTable[i] = "Map";
    for (int i = 0; i < 8; i++) curGameTexts[i].sourceId = 3;
    curLanguage = 0;
    curGameTextDir = 4;
    gGameTextLastDir = gGameTextLastLanguage = -1;
    gameState = 0;
    heap = 17;
    freeDelay = 2;
    loads = frees = cancellations = completeCancel = 0;
    currentFileInfo = NULL;
    cancelledBlock = NULL;
    cancelCallback = NULL;
    scenarios++;
}
static void check_first_free(void) {
    for (int mask = 0; mask < 256; mask++) {
        reset();
        int first = -1;
        for (int i = 0; i < 8; i++) {
            curGameTexts[i].active = mask & (1 << i) ? (i & 1 ? 0x80 : 1) : 0;
            if (!curGameTexts[i].active && first < 0) first = i;
        }
        GameTextLoadSlot before[8];
        memcpy(before, curGameTexts, sizeof(before));
        assert(gameTextFindFreeLoadSlot() == (first < 0 ? NULL : &curGameTexts[first]));
        assert(memcmp(before, curGameTexts, sizeof(before)) == 0);
    }
}
static void check_loaders(void) {
    for (int sequence = 0; sequence < 2; sequence++) {
        for (int language = 0; language < 6; language++) {
            for (int first = 0; first < 8; first++) {
                reset();
                curLanguage = language;
                gameState = first & 1;
                lbl_803DC9D4 = 98;
                for (int i = 0; i < first; i++) curGameTexts[i].active = 1;
                GameTextLoadSlot before[8];
                memcpy(before, curGameTexts, sizeof(before));
                if (sequence) loadGameTextSequence(7, 42);
                else gameTextLoadForCurMap(0);
                GameTextLoadSlot* slot = &curGameTexts[first];
                assert(slot->state == 1 && slot->active == 1);
                assert(slot->dirId == (sequence ? 7 : 4) && slot->languageId == language);
                assert(slot->sourceId == sequence && slot->loadHandle == &bufferToken);
                assert(slot->loadedSize == 123 && loads == 1 && frees == 0 && cancellations == 0);
                assert(heap == 17 && freeDelay == 2 && currentFileInfo == NULL);
                char expected[64];
                if (sequence) {
                    snprintf(expected, sizeof(expected), "gametext/Sequences/42_%s.bin",
                             sLanguageNameTable[language].name);
                    assert(lbl_803DC9D0 == 98 && gGameTextCharsets[1].status == 1);
                } else {
                    snprintf(expected, sizeof(expected), "gametext/Map/%s.bin",
                             sLanguageNameTable[language].name);
                    assert(gGameTextLastDir == 4 && gGameTextLastLanguage == language);
                    assert(gGameTextCharsets[0].dirId == 255 && gGameTextCharsets[0].languageId == 6);
                }
                assert(strcmp(expected, sGameTextPath) == 0);
                for (int i = 0; i < 8; i++) {
                    if (i != first) assert(memcmp(&before[i], &curGameTexts[i], sizeof(before[i])) == 0);
                }
                gameTextLoadCompleteCallback(123, &slot->fileInfo);
                assert(slot->state == 2);
            }
        }
    }
    reset();
    for (int i = 0; i < 8; i++) curGameTexts[i].active = 1;
    gameTextLoadForCurMap(0);
    assert(loads == 0 && heap == 17);
    assert(gGameTextCharsets[0].status == 1 && gGameTextCharsets[0].dirId == 4);
    assert(gGameTextCharsets[0].languageId == 0);
    /* Retail sequence loading dereferences NULL here; test the helper's exhausted
       result above without deliberately executing that invalid access. */
}
static void check_cancellation(void) {
    for (int sequence = 0; sequence < 2; sequence++) {
        for (int synchronous = 0; synchronous < 2; synchronous++) {
            for (int hasBuffer = 0; hasBuffer < 2; hasBuffer++) {
                reset();
                completeCancel = synchronous;
                curGameTexts[0].sourceId = sequence;
                curGameTexts[0].active = 1;
                curGameTexts[0].state = 1;
                curGameTexts[1].sourceId = sequence;
                curGameTexts[1].active = 1;
                curGameTexts[1].state = 3;
                curGameTexts[1].loadHandle = hasBuffer ? &bufferToken : NULL;
                if (sequence) loadGameTextSequence(7, 42);
                else gameTextLoadForCurMap(0);
                assert(cancellations == 1 && cancelledBlock == &curGameTexts[0].fileInfo.cb);
                assert(curGameTexts[0].state == (synchronous ? 5 : 4));
                assert(curGameTexts[0].active == 1);
                assert(frees == (sequence || hasBuffer) && freeDelay == 2);
                assert(curGameTexts[1].state == 1 && curGameTexts[1].loadHandle == &bufferToken);
                assert(loads == 1 && heap == 17);
                if (!synchronous) cancelCallback(0, cancelledBlock);
                assert(curGameTexts[0].state == 5);
            }
        }
    }
    const int statuses[] = {-3, -1, 0, 123};
    for (int slot = 0; slot < 8; slot++) {
        for (int i = 0; i < 4; i++) {
            reset();
            gameTextLoadCompleteCallback(statuses[i], &curGameTexts[slot].fileInfo);
            for (int n = 0; n < 8; n++) {
                assert(curGameTexts[n].state == (n == slot ? (statuses[i] < 0 ? 5 : 2) : 0));
            }
        }
    }
    reset();
    DVDFileInfo unknown = {0};
    gameTextLoadCompleteCallback(123, &unknown);
    gameTextLoadCancelCallback(0, &unknown.cb);
    for (int i = 0; i < 8; i++) assert(curGameTexts[i].state == 0);
}
static void check_rejected_requests(void) {
    for (int sequence = 0; sequence < 2; sequence++) {
        for (int reason = 0; reason < 5; reason++) {
            if (sequence && reason >= 3) continue;
            reset();
            if (reason == 0) gameState = 2;
            if (reason == 1) curLanguage = -1;
            if (reason == 2) curLanguage = 6;
            if (reason == 3) curGameTextDir = -1;
            if (reason == 4) curGameTextDir = 73;
            GameTextLoadSlot before[8];
            memcpy(before, curGameTexts, sizeof(before));
            if (sequence) loadGameTextSequence(7, 42);
            else gameTextLoadForCurMap(0);
            assert(loads == 0 && cancellations == 0 && frees == 0 && heap == 17);
            assert(memcmp(before, curGameTexts, sizeof(before)) == 0);
        }
    }
}
int main(void) {
    check_first_free();
    check_loaders();
    check_cancellation();
    check_rejected_requests();
    printf("%d text load scenarios passed\n", scenarios);
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='sfa-text-load-') as temporary:
            directory = Path(temporary)
            path = directory / 'load_slots.c'
            path.write_text(fixture)
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    executable = directory / 'load_slots'
                    subprocess.run([compiler, '-std=c99', optimization, str(path), '-o', str(executable)],
                                   check=True, capture_output=True, text=True)
                    result = subprocess.run([str(executable)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    print(optimization, result.stdout.strip())


if __name__ == '__main__':
    unittest.main()
