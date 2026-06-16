#include "main/dll/VF/vf_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"

typedef struct VfpstatueballPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} VfpstatueballPlacement;

extern void objfx_spawnDirectionalBurst(int* obj, u8 idx, f32 scale, int model, int mode, u8 chance,
                                        f32 alpha, int flags, int unused);
extern u8 fn_8016F16C(int* obj);
extern f32 lbl_803E60B8;

typedef struct VfpStatueBallState
{
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

void vfpstatueball_render(void)
{
}

void vfpstatueball_hitDetect(void)
{
}

void vfpstatueball_update(int* obj)
{
    int* setup;
    VfpStatueBallState* state;
    int* hitObj;
    int hitType;
    int variant;

    setup = *(int**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    hitObj = 0;

    if (state->active != 0)
    {
        state->particleIdx = 6;
        state->particleChance = 0x14;
        state->particleAlpha = 0xa;
    }
    else
    {
        state->particleIdx = 5;
        state->particleChance = 0x28;
        state->particleAlpha = 5;
    }

    state->timer -= (s16)timeDelta;

    variant = ((VfpstatueballPlacement*)setup)->unk1A;
    if (variant == 0)
    {
        objfx_spawnDirectionalBurst(obj, state->particleIdx, lbl_803E60B8, 5, 1, state->particleChance,
                                    (f32)state->particleAlpha, 0, 0);
    }
    else if (variant == 1)
    {
        objfx_spawnDirectionalBurst(obj, state->particleIdx, lbl_803E60B8, 2, 1, state->particleChance,
                                    (f32)state->particleAlpha, 0, 0);
    }
    else
    {
        objfx_spawnDirectionalBurst(obj, state->particleIdx, lbl_803E60B8, 1, 1, state->particleChance,
                                    (f32)state->particleAlpha, 0, 0);
    }

    Vec_distance((void*)((char*)Obj_GetPlayerObject() + 0x18), (void*)&((GameObject*)obj)->anim.worldPosX);
    state->prevActive = state->active;

    if ((u32)GameBit_Get(state->gameBit) == 0)
    {
        hitType = ObjHits_GetPriorityHit((int)obj, (int*)&hitObj, 0, 0);
        if ((hitObj != NULL) && (hitType != 0) && (hitObj != NULL) &&
            (((GameObject*)hitObj)->anim.seqId == 0x14b))
        {
            if ((u8)fn_8016F16C(hitObj) == ((VfpstatueballPlacement*)setup)->unk1A)
            {
                state->active = (u8)(1 - state->active);
            }
            else
            {
                Sfx_PlayFromObject(0, SFXsc_mpick1_b);
            }
        }

        *(s16*)obj = (s16)(*(s16*)obj + ((s32)timeDelta * 0x82));
    }

    if ((state->active != 0) && (state->playActivateSfx != 0))
    {
        state->playActivateSfx = 0;
        Sfx_PlayFromObject((int)obj, SFXmn_sml_trex_snap1);
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }

    if (state->active != state->prevActive)
    {
        if (state->active != 0)
        {
            if (state->gameBit != -1)
            {
                if ((u32)GameBit_Get(state->gameBit) == 0)
                {
                    GameBit_Set(state->gameBit, 1);
                }
            }
            state->playActivateSfx = 1;
        }
        else
        {
            Sfx_StopObjectChannel((int)obj, 0x40);
            (*gExpgfxInterface)->freeSource((u32)obj);
            if (state->gameBit != -1)
            {
                if ((u32)GameBit_Get(state->gameBit) != 0)
                {
                    GameBit_Set(state->gameBit, 0);
                }
            }
        }
    }
}

void vfpstatueball_release(void)
{
}

void vfpstatueball_initialise(void)
{
}

void vfpstatueball_free(int obj)
{
    (*gExpgfxInterface)->freeSource(obj);
}

void vfpstatueball_init(int* obj, u8* init)
{
    VfpStatueBallState* inner = ((GameObject*)obj)->extra;
    inner->gameBit = *(s16*)((char*)init + 0x1e);
    inner->timer = 0x19;
    ((GameObject*)obj)->objectFlags |= 0x4000;
    if (*(s16*)((char*)init + 0x1a) > 2)
    {
        *(s16*)((char*)init + 0x1a) = 2;
    }
    if (*(s16*)((char*)init + 0x1c) > 1)
    {
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * (f32)(s32) * (s16*)((char
            *)init + 0x1c);
    }
    Obj_SetActiveModelIndex((int)obj, *(s16*)((char*)init + 0x1a));
    inner->active = (u8)GameBit_Get(inner->gameBit);
}
