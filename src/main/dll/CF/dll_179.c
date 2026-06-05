#include "ghidra_import.h"
#include "main/dll/CF/dll_179.h"

extern uint GameBit_Get(int eventId);
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);

extern int *gPartfxInterface;
extern f32 lbl_803E3DD8;

#define PARTFX_SPAWN(obj, fxId, a, b, c, d) \
  ((void (*)(int, int, int, int, int, int))(*(u32 *)((u8 *)*gPartfxInterface + 0x8)))((obj), (fxId), (a), (b), (c), (d))

#pragma scheduling off
#pragma peephole off
void cfccrate_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int objectType;
    u8 *state;

    state = *(u8 **)(obj + 0xb8);
    if ((s32)visible != 0) {
        objectType = *(s16 *)(obj + 0x46);
        if (objectType == 0x1b8) {
            return;
        }
        if (visible == 0 || objectType == 0x6bf) {
            if (GameBit_Get(*(s16 *)(state + 0x3a)) == 0) {
                return;
            }
        }
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E3DD8);
    }
}

int CFCrate_SeqFn(int obj, int unused, u8 *seq)
{
    u8 *state;
    int i;

    state = *(u8 **)(obj + 0xb8);
    switch (*(s16 *)(obj + 0x46)) {
    case 0x85:
    case 0x87:
    case 0x88:
    case 0x89:
    case 0x8A:
    case 0x8B:
    case 0x8C:
    case 0x8D:
        break;
    case 0x8E:
        return 0;
    case 0xAB:
        break;
    case 0xAE:
        break;
    case 0x10D:
        break;
    case 0x409:
        break;
    case 0x2B7:
        if (GameBit_Get(*(s16 *)(state + 0x3a)) != 0) {
            seq[0x90] = (u8)(seq[0x90] | 4);
        }
        for (i = 0; i < (int)seq[0x8b]; i++) {
            if (seq[0x81 + i] == 1) {
                PARTFX_SPAWN(obj, 0x44, 0, 2, -1, 0);
            }
            seq[0x81 + i] = 0;
        }
        break;
    }
    return 0;
}

void cfccrate_hitDetect(void) {}

#pragma peephole reset
#pragma scheduling reset
