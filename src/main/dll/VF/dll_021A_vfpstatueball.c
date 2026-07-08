/*
 * vfpstatueball (DLL 0x21A, VFP_statueball) - one of the rotatable
 * spell-stone / statue balls in the Volcano Force Point Temple puzzle.
 *
 * The ball slowly spins and emits a directional particle plume whose
 * density depends on whether it is currently "active". When the player
 * strikes it with the staff (hit object seqId 0x14B) the ball toggles
 * active only if the striking object's variant matches this ball's
 * variant; a mismatch plays a rejection sfx. Toggling active drives the
 * ball's bound game bit and plays activate / deactivate sfx + gfx.
 *
 * The placement variant (0..2) selects both the displayed model and the
 * particle-burst model.
 */
#include "main/dll/VF/vf_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/VF/dll_021A_vfpstatueball.h"

#define VFPSTATUEBALL_OBJFLAG_HIDDEN 0x4000

#define VFPSTATUEBALL_HIT_SEQID 0x14b /* staff-strike object seq id */

extern f32 lbl_803E60B8;
extern void objfx_spawnDirectionalBurst(int* obj, u8 idx, f32 scale, int model, int mode, u8 chance, f32 alpha,
                                        int flags, int unused);
extern u8 fn_8016F16C(int* obj);

int VFP_statueball_getExtraSize(void)
{
    return 0xc;
}

int VFP_statueball_getObjectTypeId(void)
{
    return 0x0;
}

void VFP_statueball_free(int obj)
{
    (*gExpgfxInterface)->freeSource(obj);
}

void VFP_statueball_render(void)
{
}

void VFP_statueball_hitDetect(void)
{
}

void VFP_statueball_update(int* obj)
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

    variant = ((VfpStatueBallPlacement*)setup)->variant;
    if (variant == 0)
    {
        objfx_spawnDirectionalBurst(obj, state->particleIdx, lbl_803E60B8, 5, 1, state->particleChance,
                                    state->particleAlpha, 0, 0);
    }
    else if (variant == 1)
    {
        objfx_spawnDirectionalBurst(obj, state->particleIdx, lbl_803E60B8, 2, 1, state->particleChance,
                                    state->particleAlpha, 0, 0);
    }
    else
    {
        objfx_spawnDirectionalBurst(obj, state->particleIdx, lbl_803E60B8, 1, 1, state->particleChance,
                                    state->particleAlpha, 0, 0);
    }

    Vec_distance((void*)((char*)Obj_GetPlayerObject() + 0x18), &((GameObject*)obj)->anim.worldPosX);
    state->prevActive = state->active;

    if ((u32)mainGetBit(state->gameBit) == 0)
    {
        hitType = ObjHits_GetPriorityHit((int)obj, &hitObj, 0, 0);
        if ((hitObj != NULL) && (hitType != 0) && (hitObj != NULL) &&
            (((GameObject*)hitObj)->anim.seqId == VFPSTATUEBALL_HIT_SEQID))
        {
            if ((u8)fn_8016F16C(hitObj) == ((VfpStatueBallPlacement*)setup)->variant)
            {
                state->active = (u8)(1 - state->active);
            }
            else
            {
                Sfx_PlayFromObject(0, SFXTRIG_npu_216);
            }
        }

        ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + ((s32)timeDelta * 0x82));
    }

    if ((state->active != 0) && (state->playActivateSfx != 0))
    {
        state->playActivateSfx = 0;
        Sfx_PlayFromObject((int)obj, SFXTRIG_cvdrip1c);
        Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
    }

    if (state->active != state->prevActive)
    {
        if (state->active != 0)
        {
            if (state->gameBit != -1)
            {
                if ((u32)mainGetBit(state->gameBit) == 0)
                {
                    mainSetBits(state->gameBit, 1);
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
                if ((u32)mainGetBit(state->gameBit) != 0)
                {
                    mainSetBits(state->gameBit, 0);
                }
            }
        }
    }
}

void VFP_statueball_init(int* obj, u8* init)
{
    VfpStatueBallPlacement* setup = (VfpStatueBallPlacement*)init;
    VfpStatueBallState* state = ((GameObject*)obj)->extra;
    state->gameBit = setup->gameBit;
    state->timer = 0x19;
    ((GameObject*)obj)->objectFlags |= VFPSTATUEBALL_OBJFLAG_HIDDEN;
    if (setup->variant > 2)
    {
        setup->variant = 2;
    }
    if (setup->modelScale > 1)
    {
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.rootMotionScale * (f32)(s32)setup->modelScale;
    }
    Obj_SetActiveModelIndex((int)obj, setup->variant);
    state->active = mainGetBit(state->gameBit);
}

void VFP_statueball_release(void)
{
}

void VFP_statueball_initialise(void)
{
}
