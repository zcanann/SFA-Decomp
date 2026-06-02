#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int dustmotesou_getExtraSize(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int dustmotesou_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dustmotesou_free(int obj)
{
    (*(void (**)(int))(*gExpgfxInterface + 0x18))(obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dustmotesou_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {}
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dustmotesou_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dustmotesou_init(int obj, int setup)
{
    *(s16 *)(obj + 4) = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);
    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x1a) << 8);
    *(u16 *)(obj + 0xb0) |= 0x2000;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dustmotesou_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);

    if (*(s16 *)(setup + 0x24) != -1 && (u32)GameBit_Get(*(s16 *)(setup + 0x24)) == 0) {
        return;
    }
    if (*(s16 *)(obj + 0x46) == 2055) {
        if (*(u8 *)(setup + 0x1b) == 0) {
            return;
        }
        if (*(u8 *)(setup + 0x1c) == 0) {
            return;
        }
        objfx_spawnMaskedHitEffect(obj, *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c), *(f32 *)(setup + 0x20),
                    *(u8 *)(setup + 0x1d), 0);
        return;
    }
    if (*(s16 *)(obj + 0x46) == 2062) {
        if (*(u8 *)(setup + 0x1b) == 0) {
            return;
        }
        if (*(u8 *)(setup + 0x1c) == 0) {
            return;
        }
        hitDetectFn_80097070(obj, *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c),
                             *(f32 *)(setup + 0x20), *(u8 *)(setup + 0x1d), 0);
        return;
    }
    if (*(u8 *)(setup + 0x1b) == 0) {
        return;
    }
    if (*(u8 *)(setup + 0x1c) == 0) {
        return;
    }
    if (*(u8 *)(setup + 0x1d) == 0) {
        return;
    }
    if (*(u8 *)(setup + 0x2a) == 0) {
        objfx_spawnBoxBurst(obj, *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c), *(u8 *)(setup + 0x1d),
                            *(f32 *)(setup + 0x20), (f32)(u32)*(u8 *)(setup + 0x26),
                            (f32)(u32)*(u8 *)(setup + 0x27), (f32)(u32)*(u8 *)(setup + 0x28),
                            *(u8 *)(setup + 0x29), 0, 0);
    } else if (*(u8 *)(setup + 0x2a) == 1) {
        objfx_spawnArcedBurst(obj, *(u8 *)(setup + 0x1b), *(f32 *)(setup + 0x20),
                               *(u8 *)(setup + 0x1c), *(u8 *)(setup + 0x1d), *(u8 *)(setup + 0x29),
                               (f32)(u32)*(u8 *)(setup + 0x26), (f32)(u32)*(u8 *)(setup + 0x27),
                               (f32)(u32)*(u8 *)(setup + 0x28), 0, 0);
    } else {
        objfx_spawnDirectionalBurst(obj, *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c), *(u8 *)(setup + 0x1d),
                       *(f32 *)(setup + 0x20), (f32)(u32)*(u8 *)(setup + 0x26),
                       *(u8 *)(setup + 0x29), 0, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dustmotesou_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dustmotesou_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
