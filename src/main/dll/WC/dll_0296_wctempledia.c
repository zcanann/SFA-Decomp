#include "main/dll/dll_80220608_shared.h"

#define SFXmn_sml_trex_fstep 126
#define SFXmn_sml_trex_roar 127

#pragma peephole off
#pragma scheduling off
void wctempledia_syncPartVisibility(int obj, u8 mask)
{
    u8 *block;
    int part;
    int slot;
    int bit;

    block = mapGetBlock(objPosToMapBlockIdx(*(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14)));
    if (block != NULL) {
        for (part = 1; part < 4; part++) {
            bit = mask & (1 << (part - 1));
            for (slot = 0; slot < block[0xa2]; slot++) {
                int entry = fn_8006070C((int)block, slot);
                if (*(u8 *)(entry + 0x29) == part) {
                    if (bit != 0) {
                        mapTextureOverrideSetValue(part, *(int *)(entry + 0x24), 0x100);
                    } else {
                        mapTextureOverrideSetValue(part, *(int *)(entry + 0x24), 0);
                    }
                }
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wctempledia_getExtraSize(void) { return 0x14; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wctempledia_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctempledia_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wctempledia_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E58);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctempledia_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wctempledia_interactCallback(int obj, int p2, int p3)
{
    f32 *p = *(f32 **)(obj + 0xb8);

    *p = lbl_803E6E48 * -*p * timeDelta + *p;
    *(s16 *)(obj + 4) = (int)(timeDelta * *p + (f32)*(s16 *)(obj + 4));
    *(s8 *)(p3 + 0x56) = 0;
    *(s16 *)(p3 + 0x70) &= ~2;
    *(s16 *)(p3 + 0x6e) &= ~2;
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctempledia_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int r4c = *(int *)(obj + 0x4c);
    int i;
    int j;
    int k;

    if (*(u8 *)(state + 9) & 1) {
        wctempledia_syncPartVisibility(obj, *(u8 *)(state + 8));
        return;
    }
    *(f32 *)state =
        timeDelta * (lbl_803E6E48 * (*(f32 *)(state + 4) - *(f32 *)state)) + *(f32 *)state;
    *(s16 *)(obj + 4) = (int)(timeDelta * *(f32 *)state + (f32)*(s16 *)(obj + 4));
    Sfx_KeepAliveLoopedObjectSound(obj, SFXmn_sml_trex_roar);
    {
        f32 ratio = *(f32 *)state / *(f32 *)(*(int *)(state + 0xc) + 8);
        Sfx_SetObjectSfxVolume(obj, SFXmn_sml_trex_roar, (u8)(lbl_803E6E60 * ratio + lbl_803E6E5C),
                               lbl_803E6E68 * ratio + lbl_803E6E64);
    }
    for (i = 0; i < 3; i++) {
        int bit = 1 << i;
        if ((*(u8 *)(state + 8) & bit) == 0 &&
            GameBit_Get(*(s16 *)(*(int *)(state + 0x10) + i * 2)) != 0) {
            int found = 0;
            for (j = 0; j < i; j++) {
                if ((*(u8 *)(state + 8) & (1 << j)) == 0) {
                    found = 1;
                    break;
                }
            }
            if (found) {
                for (k = 0; k < 3; k++) {
                    GameBit_Set(*(s16 *)(*(int *)(state + 0x10) + k * 2), 0);
                }
                Sfx_PlayFromObject(0, 0x487);
                *(u8 *)(state + 8) = 0;
                *(f32 *)(state + 4) = *(f32 *)(*(int *)(state + 0xc) + 0);
                break;
            }
            *(u8 *)(state + 8) |= bit;
            if (i == 0) {
                *(f32 *)(state + 4) = *(f32 *)(*(int *)(state + 0xc) + 4);
                Sfx_PlayFromObject(0, 0x409);
            } else if (i == 1) {
                *(f32 *)(state + 4) = *(f32 *)(*(int *)(state + 0xc) + 8);
                Sfx_PlayFromObject(0, 0x409);
            }
        }
    }
    wctempledia_syncPartVisibility(obj, *(u8 *)(state + 8));
    if (*(u8 *)(state + 8) == 7) {
        GameBit_Set(*(s16 *)(r4c + 0x1e), 1);
        Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
        *(u8 *)(state + 9) |= 1;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctempledia_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    *(s16 *)obj = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    *(u8 *)(obj + 0xad) = *(u8 *)(setup + 0x19);
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(u8 *)(obj + 0xad) = 0;
    }
    if (*(s8 *)(obj + 0xad) == 0) {
        *(s16 **)(state + 0x10) = &lbl_803DC3B8;
        *(f32 **)(state + 0xc) = lbl_8032B348;
    } else {
        *(s16 **)(state + 0x10) = &lbl_803DC3C0;
        *(f32 **)(state + 0xc) = lbl_8032B354;
    }
    for (i = 0; i < 3; i++) {
        if ((u32)GameBit_Get((*(s16 **)(state + 0x10))[i]) != 0) {
            *(u8 *)(state + 8) |= (1 << i);
        }
    }
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        *(u8 *)(state + 8) = 7;
        *(u8 *)(state + 9) |= 1;
    }
    if (*(u8 *)(state + 8) & 2) {
        *(f32 *)state = (*(f32 **)(state + 0xc))[2];
    } else if (*(u8 *)(state + 8) & 1) {
        *(f32 *)state = (*(f32 **)(state + 0xc))[1];
    } else {
        *(f32 *)state = (*(f32 **)(state + 0xc))[0];
    }
    *(f32 *)(state + 4) = *(f32 *)state;
    *(void **)(obj + 0xbc) = (void *)wctempledia_interactCallback;
    wctempledia_syncPartVisibility(obj, *(u8 *)(state + 8));
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctempledia_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctempledia_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
