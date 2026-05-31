#include "main/dll/VF/vf_shared.h"

#define SFXmn_sml_trex_snap1 128
#define SFXsc_mpick1_b 179
#define SFXsp_lf_mutter4 265

extern void objFn_800972dc(int *obj, u8 idx, f32 scale, int model, int mode, u8 chance,
                           f32 alpha, int flags, int unused);
extern u8 fn_8016F16C(int *obj);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern f32 lbl_803E60B8;

typedef struct VfpStatueBallState {
    s16 gameBit;
    s16 timer;
    u8 unk4;
    u8 active;
    u8 playActivateSfx;
    u8 prevActive;
    u8 unk8;
    u8 particleIdx;
    u8 particleAlpha;
    u8 particleChance;
} VfpStatueBallState;

int vfpstatueball_getExtraSize(void) { return 0xc; }

int vfpstatueball_getObjectTypeId(void) { return 0x0; }

void vfpstatueball_render(void) {}

void vfpstatueball_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
void vfpstatueball_update(int *obj) {
    int *setup;
    VfpStatueBallState *state;
    int *hitObj;
    int hitType;
    int variant;

    setup = *(int **)((char *)obj + 0x4c);
    state = *(VfpStatueBallState **)((char *)obj + 0xb8);
    hitObj = 0;

    if (state->active != 0) {
        state->particleIdx = 6;
        state->particleChance = 0x14;
        state->particleAlpha = 0xa;
    } else {
        state->particleIdx = 5;
        state->particleChance = 0x28;
        state->particleAlpha = 5;
    }

    state->timer = state->timer - (s32)timeDelta;

    variant = *(s16 *)((char *)setup + 0x1a);
    if (variant == 0) {
        objFn_800972dc(obj, state->particleIdx, lbl_803E60B8, 5, 1, state->particleChance,
                       (f32)state->particleAlpha, 0, 0);
    } else if (variant == 1) {
        objFn_800972dc(obj, state->particleIdx, lbl_803E60B8, 2, 1, state->particleChance,
                       (f32)state->particleAlpha, 0, 0);
    } else {
        objFn_800972dc(obj, state->particleIdx, lbl_803E60B8, 1, 1, state->particleChance,
                       (f32)state->particleAlpha, 0, 0);
    }

    Vec_distance((void *)((char *)Obj_GetPlayerObject() + 0x18), (void *)((char *)obj + 0x18));
    state->prevActive = state->active;

    if ((u32)GameBit_Get(state->gameBit) == 0) {
        hitType = ObjHits_GetPriorityHit((int)obj, (int *)&hitObj, 0, 0);
        if ((hitObj != NULL) && (hitType != 0) && (hitObj != NULL) &&
            (*(s16 *)((char *)hitObj + 0x46) == 0x14b)) {
            if ((u8)fn_8016F16C(hitObj) == *(s16 *)((char *)setup + 0x1a)) {
                state->active = (u8)(1 - state->active);
            } else {
                Sfx_PlayFromObject(0, SFXsc_mpick1_b);
            }
        }

        *(s16 *)obj = (s16)(*(s16 *)obj + ((s32)timeDelta * 0x82));
    }

    if ((state->active != 0) && (state->playActivateSfx != 0)) {
        state->playActivateSfx = 0;
        Sfx_PlayFromObject((int)obj, SFXmn_sml_trex_snap1);
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }

    if (state->active != state->prevActive) {
        if (state->active != 0) {
            if (state->gameBit != -1) {
                if ((u32)GameBit_Get(state->gameBit) == 0) {
                    GameBit_Set(state->gameBit, 1);
                }
            }
            state->playActivateSfx = 1;
        } else {
            Sfx_StopObjectChannel((int)obj, 0x40);
            (*(void (*)(int *))(*(int *)(*gExpgfxInterface + 0x14)))(obj);
            if (state->gameBit != -1) {
                if ((u32)GameBit_Get(state->gameBit) != 0) {
                    GameBit_Set(state->gameBit, 0);
                }
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

void vfpstatueball_release(void) {}

void vfpstatueball_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void vfpstatueball_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x14)))(obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfpstatueball_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)inner = *(s16 *)((char *)init + 0x1e);
    *(s16 *)((char *)inner + 2) = 0x19;
    *(u16 *)((char *)obj + 0xb0) |= 0x4000;
    if (*(s16 *)((char *)init + 0x1a) > 2) {
        *(s16 *)((char *)init + 0x1a) = 2;
    }
    if (*(s16 *)((char *)init + 0x1c) > 1) {
        *(f32 *)((char *)obj + 8) = *(f32 *)((char *)obj + 8) * (f32)(s32)*(s16 *)((char *)init + 0x1c);
    }
    Obj_SetActiveModelIndex((int)obj, *(s16 *)((char *)init + 0x1a));
    *(u8 *)((char *)inner + 5) = (u8)GameBit_Get(*(s16 *)inner);
}
#pragma scheduling reset
#pragma peephole reset
