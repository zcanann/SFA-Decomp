#include "main/dll/dll_80220608_shared.h"
#include "main/audio/sfx_ids.h"

#define WCTEMPLE_DIA_EXTRA_SIZE 0x14
#define WCTEMPLE_DIA_STAGE_COUNT 3
#define WCTEMPLE_DIA_ALL_STAGES_MASK 7
#define WCTEMPLE_DIA_VISIBLE_OVERRIDE 0x100

#define WCTEMPLE_DIA_SETUP_TYPE_OFFSET 0x18
#define WCTEMPLE_DIA_SETUP_MODEL_INDEX_OFFSET 0x19
#define WCTEMPLE_DIA_SETUP_SOLVED_BIT_OFFSET 0x1e

#define WCTEMPLE_DIA_STATE_CURRENT_SPEED 0x00
#define WCTEMPLE_DIA_STATE_TARGET_SPEED 0x04
#define WCTEMPLE_DIA_STATE_STAGE_MASK 0x08
#define WCTEMPLE_DIA_STATE_FLAGS 0x09
#define WCTEMPLE_DIA_STATE_TARGET_TABLE 0x0c
#define WCTEMPLE_DIA_STATE_GAMEBITS 0x10

#define WCTEMPLE_DIA_FLAG_SOLVED 1

#define WCTEMPLE_DIA_PAYLOAD_SUPPRESS_OFFSET 0x56
#define WCTEMPLE_DIA_PAYLOAD_FLAGS_A 0x70
#define WCTEMPLE_DIA_PAYLOAD_FLAGS_B 0x6e
#define WCTEMPLE_DIA_PAYLOAD_BLOCK_FLAG 2

#define WCTEMPLE_DIA_RESET_SFX 0x487
#define WCTEMPLE_DIA_STAGE_SFX 0x409

#define WCTEMPLE_DIA_SPEED(state) (*(f32 *)((state) + WCTEMPLE_DIA_STATE_CURRENT_SPEED))
#define WCTEMPLE_DIA_TARGET_SPEED(state) (*(f32 *)((state) + WCTEMPLE_DIA_STATE_TARGET_SPEED))
#define WCTEMPLE_DIA_STAGE_MASK_BYTE(state) (*(u8 *)((state) + WCTEMPLE_DIA_STATE_STAGE_MASK))
#define WCTEMPLE_DIA_FLAGS(state) (*(u8 *)((state) + WCTEMPLE_DIA_STATE_FLAGS))
#define WCTEMPLE_DIA_TARGET_TABLE(state) (*(f32 **)((state) + WCTEMPLE_DIA_STATE_TARGET_TABLE))
#define WCTEMPLE_DIA_GAMEBITS(state) (*(s16 **)((state) + WCTEMPLE_DIA_STATE_GAMEBITS))

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
        for (part = 1; part < WCTEMPLE_DIA_STAGE_COUNT + 1; part++) {
            bit = mask & (1 << (part - 1));
            for (slot = 0; slot < block[0xa2]; slot++) {
                int entry = fn_8006070C((int)block, slot);
                if (*(u8 *)(entry + 0x29) == part) {
                    if (bit != 0) {
                        mapTextureOverrideSetValue(part, *(int *)(entry + 0x24), WCTEMPLE_DIA_VISIBLE_OVERRIDE);
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

#pragma peephole off
#pragma scheduling off
int wctempledia_interactCallback(int obj, int p2, int p3)
{
    f32 *p = *(f32 **)(obj + 0xb8);

    *p = lbl_803E6E48 * -*p * timeDelta + *p;
    *(s16 *)(obj + 4) = (int)(timeDelta * *p + (f32)*(s16 *)(obj + 4));
    *(s8 *)(p3 + WCTEMPLE_DIA_PAYLOAD_SUPPRESS_OFFSET) = 0;
    *(s16 *)(p3 + WCTEMPLE_DIA_PAYLOAD_FLAGS_A) &= ~WCTEMPLE_DIA_PAYLOAD_BLOCK_FLAG;
    *(s16 *)(p3 + WCTEMPLE_DIA_PAYLOAD_FLAGS_B) &= ~WCTEMPLE_DIA_PAYLOAD_BLOCK_FLAG;
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wctempledia_getExtraSize(void) { return WCTEMPLE_DIA_EXTRA_SIZE; }
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
void wctempledia_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int r4c = *(int *)(obj + 0x4c);
    int i;
    int j;
    int k;

    if (WCTEMPLE_DIA_FLAGS(state) & WCTEMPLE_DIA_FLAG_SOLVED) {
        wctempledia_syncPartVisibility(obj, WCTEMPLE_DIA_STAGE_MASK_BYTE(state));
        return;
    }
    WCTEMPLE_DIA_SPEED(state) = timeDelta * (lbl_803E6E48 * (WCTEMPLE_DIA_TARGET_SPEED(state) -
                                                            WCTEMPLE_DIA_SPEED(state))) +
                                WCTEMPLE_DIA_SPEED(state);
    *(s16 *)(obj + 4) = (int)(timeDelta * WCTEMPLE_DIA_SPEED(state) + (f32)*(s16 *)(obj + 4));
    Sfx_KeepAliveLoopedObjectSound(obj, SFXmn_sml_trex_roar);
    {
        f32 ratio = WCTEMPLE_DIA_SPEED(state) / WCTEMPLE_DIA_TARGET_TABLE(state)[2];
        Sfx_SetObjectSfxVolume(obj, SFXmn_sml_trex_roar, (u8)(lbl_803E6E60 * ratio + lbl_803E6E5C),
                               lbl_803E6E68 * ratio + lbl_803E6E64);
    }
    for (i = 0; i < WCTEMPLE_DIA_STAGE_COUNT; i++) {
        int bit = 1 << i;
        if ((WCTEMPLE_DIA_STAGE_MASK_BYTE(state) & bit) == 0 &&
            GameBit_Get(WCTEMPLE_DIA_GAMEBITS(state)[i]) != 0) {
            int found = 0;
            for (j = 0; j < i; j++) {
                if ((WCTEMPLE_DIA_STAGE_MASK_BYTE(state) & (1 << j)) == 0) {
                    found = 1;
                    break;
                }
            }
            if (found) {
                for (k = 0; k < WCTEMPLE_DIA_STAGE_COUNT; k++) {
                    GameBit_Set(WCTEMPLE_DIA_GAMEBITS(state)[k], 0);
                }
                Sfx_PlayFromObject(0, WCTEMPLE_DIA_RESET_SFX);
                WCTEMPLE_DIA_STAGE_MASK_BYTE(state) = 0;
                WCTEMPLE_DIA_TARGET_SPEED(state) = WCTEMPLE_DIA_TARGET_TABLE(state)[0];
                break;
            }
            WCTEMPLE_DIA_STAGE_MASK_BYTE(state) |= bit;
            if (i == 0) {
                WCTEMPLE_DIA_TARGET_SPEED(state) = WCTEMPLE_DIA_TARGET_TABLE(state)[1];
                Sfx_PlayFromObject(0, WCTEMPLE_DIA_STAGE_SFX);
            } else if (i == 1) {
                WCTEMPLE_DIA_TARGET_SPEED(state) = WCTEMPLE_DIA_TARGET_TABLE(state)[2];
                Sfx_PlayFromObject(0, WCTEMPLE_DIA_STAGE_SFX);
            }
        }
    }
    wctempledia_syncPartVisibility(obj, WCTEMPLE_DIA_STAGE_MASK_BYTE(state));
    if (WCTEMPLE_DIA_STAGE_MASK_BYTE(state) == WCTEMPLE_DIA_ALL_STAGES_MASK) {
        GameBit_Set(*(s16 *)(r4c + WCTEMPLE_DIA_SETUP_SOLVED_BIT_OFFSET), 1);
        Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
        WCTEMPLE_DIA_FLAGS(state) |= WCTEMPLE_DIA_FLAG_SOLVED;
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

    *(s16 *)obj = (s16)((s8)*(u8 *)(setup + WCTEMPLE_DIA_SETUP_TYPE_OFFSET) << 8);
    *(u8 *)(obj + 0xad) = *(u8 *)(setup + WCTEMPLE_DIA_SETUP_MODEL_INDEX_OFFSET);
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(u8 *)(obj + 0xad) = 0;
    }
    if (*(s8 *)(obj + 0xad) == 0) {
        WCTEMPLE_DIA_GAMEBITS(state) = &lbl_803DC3B8;
        WCTEMPLE_DIA_TARGET_TABLE(state) = lbl_8032B348;
    } else {
        WCTEMPLE_DIA_GAMEBITS(state) = &lbl_803DC3C0;
        WCTEMPLE_DIA_TARGET_TABLE(state) = lbl_8032B354;
    }
    for (i = 0; i < WCTEMPLE_DIA_STAGE_COUNT; i++) {
        if ((u32)GameBit_Get(WCTEMPLE_DIA_GAMEBITS(state)[i]) != 0) {
            WCTEMPLE_DIA_STAGE_MASK_BYTE(state) |= (1 << i);
        }
    }
    if ((u32)GameBit_Get(*(s16 *)(setup + WCTEMPLE_DIA_SETUP_SOLVED_BIT_OFFSET)) != 0) {
        WCTEMPLE_DIA_STAGE_MASK_BYTE(state) = WCTEMPLE_DIA_ALL_STAGES_MASK;
        WCTEMPLE_DIA_FLAGS(state) |= WCTEMPLE_DIA_FLAG_SOLVED;
    }
    if (WCTEMPLE_DIA_STAGE_MASK_BYTE(state) & 2) {
        WCTEMPLE_DIA_SPEED(state) = WCTEMPLE_DIA_TARGET_TABLE(state)[2];
    } else if (WCTEMPLE_DIA_STAGE_MASK_BYTE(state) & 1) {
        WCTEMPLE_DIA_SPEED(state) = WCTEMPLE_DIA_TARGET_TABLE(state)[1];
    } else {
        WCTEMPLE_DIA_SPEED(state) = WCTEMPLE_DIA_TARGET_TABLE(state)[0];
    }
    WCTEMPLE_DIA_TARGET_SPEED(state) = WCTEMPLE_DIA_SPEED(state);
    *(void **)(obj + 0xbc) = (void *)wctempledia_interactCallback;
    wctempledia_syncPartVisibility(obj, WCTEMPLE_DIA_STAGE_MASK_BYTE(state));
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
