"""Exercise C-menu filtering and texture lifecycle using the actual source body."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]


def harness(source):
    start, end = find_function_body(source, 'cMenuSetItems')
    declaration = source.rfind('int cMenuSetItems', 0, start)
    header = (ROOT / 'include/main/dll/dll_0000_gameui.h').read_text()
    hud_end = header.index('} CMenuHud;') + len('} CMenuHud;')
    hud_start = header.rfind('typedef struct {', 0, hud_end)
    return r'''
#include <assert.h>
#include <stddef.h>
#include <string.h>
#define _TYPES_H_
typedef unsigned char u8;
typedef short s16;
typedef unsigned short u16;
typedef int s32;
typedef float f32;
typedef struct Texture { int id; } Texture;
#define HUD_STATUS_COUNT 13
#define CMENU_ITEM_SLOT_COUNT 64
#include "main/dll/cmenu_item_table.h"
''' + header[hud_start:hud_end] + r'''
static CMenuHud state;
#define lbl_803A87F0 (&state)
static int gCMenuForcedSelIndex, gCMenuPreselectOwnedBit;
static int gTrickyHudItemMask, gTrickyHudActionMask;
static int yButtonItem, yButtonState, yButtonItemTextureId;
CMenuItemDef gCMenuStaffAbilities[65];
static CMenuItemDef items[65];
static Texture textures[512];
static int bits[512], events[1024], eventCount, fileFlags, failLoad;
static void record(int kind, int id) { events[eventCount++] = kind * 1000 + id; }
static unsigned int mainGetBit(int id) { assert(id >= 0); record(1, id); return bits[id]; }
static void getTrickyObject(void) { record(2, 0); }
static void textureFree(Texture* texture) { record(3, texture->id); }
static int getLoadedFileFlags(int id) { record(4, id); return fileFlags; }
static Texture* textureLoadAsset(int id) {
    record(5, id);
    return failLoad ? 0 : &textures[id];
}
''' + source[declaration:end + 1] + r'''
static void reset(void) {
    int i;
    memset(&state, 0, sizeof(state));
    memset(bits, 0, sizeof(bits));
    memset(items, 0, sizeof(items));
    for (i = 0; i < 64; i++) {
        state.itemSlots[i] = -1;
        state.ownedBits[i] = state.activeBits[i] = state.usedBits[i] = 777;
        items[i].ownedGameBit = i + 1;
        items[i].usedGameBit = -1;
        items[i].activeGameBit = -1;
        items[i].iconTextureId = i + 100;
        items[i].nameTextId = i + 200;
        items[i].auxiliaryValue = -123;
        items[i].auxiliaryByte = 255;
        items[i].closeMode = 1;
    }
    items[64].ownedGameBit = -1;
    for (i = 0; i < 512; i++) textures[i].id = i;
    gCMenuForcedSelIndex = 17;
    gCMenuPreselectOwnedBit = 0;
    gTrickyHudItemMask = gTrickyHudActionMask = 0;
    yButtonState = 2; yButtonItem = 8; yButtonItemTextureId = 321;
    eventCount = fileFlags = failLoad = 0;
}
static void filtering(void) {
    int staff;
    for (staff = 0; staff < 2; staff++) {
        reset();
        items[4].ownedGameBit = -1;
        bits[2] = 1; bits[3] = 258; bits[4] = 1;
        items[1].usedGameBit = 20; bits[20] = 1;
        items[2].activeGameBit = 21; bits[21] = 1;
        gCMenuPreselectOwnedBit = 3;
        memcpy(gCMenuStaffAbilities, items, sizeof(items));
        assert(cMenuSetItems(staff ? gCMenuStaffAbilities : items, 0) == 2);
        assert(gCMenuForcedSelIndex == (staff ? -1 : 0));
        assert(state.ownedBits[0] == 3 && state.ownedBits[1] == 4);
        assert(state.itemFlags[0] == 2 && state.enabled[0] == 0);
        assert(state.enabled[1] == 1 && state.activeBits[0] == 21);
        assert(state.usedBits[0] == -1 && state.textIds[0] == 202);
        assert(state.auxiliaryValues[0] == -123 && state.auxiliaryBytes[0] == 255);
        assert(state.closeMode[0] == 1 && state.itemSlots[2] == -1);
        assert(state.textIds[63] == 0 && state.itemFlags[63] == 1);
        { int expected[] = {1001, 1002, 1020, 1003, 1021, 1004, 4000, 5102, 5103};
          assert(eventCount == 9 && memcmp(events, expected, sizeof(expected)) == 0); }
    }
}
static void tricky(void) {
    int invalid;
    for (invalid = 0; invalid < 2; invalid++) {
        reset();
        items[0].ownedGameBit = 1; items[0].activeGameBit = 7;
        items[1].ownedGameBit = 2; items[1].activeGameBit = 8;
        items[2].ownedGameBit = 4; items[2].activeGameBit = 9;
        items[3].ownedGameBit = -1;
        gTrickyHudActionMask = 5;
        gTrickyHudItemMask = invalid ? -1 : 1;
        assert(cMenuSetItems(items, 1) == (invalid ? 0 : 2));
        assert(events[0] == 2000 && events[1] == 4000);
        assert(yButtonState == 0 && yButtonItemTextureId == -1);
        assert(gCMenuForcedSelIndex == 17);
        assert(state.activeBits[0] == 777 && state.usedBits[0] == 777);
        if (!invalid) {
            assert(state.ownedBits[0] == 7 && state.ownedBits[1] == 9);
            assert(state.enabled[0] == 1 && state.enabled[1] == 0);
        } else {
            assert(state.ownedBits[0] == -1 && eventCount == 2);
        }
    }
}
static void texture_lifecycle(void) {
    int blocked, failure;
    for (blocked = 0; blocked < 2; blocked++) for (failure = 0; failure < 2; failure++) {
        reset(); fileFlags = blocked; failLoad = failure;
        bits[1] = bits[2] = bits[3] = 1; items[3].ownedGameBit = -1;
        state.itemSlots[0] = 100; state.itemTextures[0] = &textures[100];
        state.itemSlots[1] = 90; state.itemTextures[1] = &textures[90];
        state.itemSlots[63] = 91; state.itemTextures[63] = &textures[91];
        assert(cMenuSetItems(items, 0) == 3);
        assert(state.itemTextures[0] == &textures[100]);
        assert(state.itemTextures[1] == (blocked || failure ? 0 : &textures[101]));
        assert(state.itemTextures[2] == (blocked || failure ? 0 : &textures[102]));
        assert(state.itemTextures[63] == 0);
        assert(events[3] == 3090 && events[4] == 3091 && events[5] == 4000);
        assert(eventCount == (blocked ? 6 : 8));
    }
}
static void full_and_empty(void) {
    int i;
    reset();
    for (i = 1; i <= 64; i++) bits[i] = 1;
    assert(cMenuSetItems(items, 0) == 64);
    assert(state.itemSlots[63] == 163 && state.itemTextures[63] == &textures[163]);
    items[0].ownedGameBit = -1;
    eventCount = 0;
    assert(cMenuSetItems(items, 0) == 0);
    assert(state.ownedBits[0] == -1 && state.ownedBits[1] == 2);
    assert(eventCount == 65 && events[64] == 4000);
}
int main(void) { filtering(); tricky(); texture_lifecycle(); full_and_empty(); return 0; }
'''


class CMenuSetItemsTests(unittest.TestCase):
    def test_filtering_commands_and_texture_lifecycle(self):
        compiler = shutil.which('clang')
        if not compiler:
            self.skipTest('clang is required for the source-body harness')
        source = (ROOT / 'src/dlls/engine/0/0.c').read_text()
        with tempfile.TemporaryDirectory(prefix='sfa-cmenu-') as temporary:
            directory = Path(temporary)
            fixture = directory / 'cmenu.c'
            fixture.write_text(harness(source))
            for optimization in ('-O0', '-O2'):
                with self.subTest(optimization=optimization):
                    binary = directory / 'cmenu'
                    subprocess.run([compiler, optimization, '-iquote', str(ROOT / 'include'),
                                    str(fixture), '-o', str(binary)], check=True)
                    subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    unittest.main()
