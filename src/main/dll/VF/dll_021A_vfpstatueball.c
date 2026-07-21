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
#include "main/frame_timing.h"
#include "main/vecmath_distance_api.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/dll/expgfx_interface.h"
#include "main/objhits.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/objfx.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_00E3_fireball_api.h"
#include "main/dll/VF/dll_021A_vfpstatueball.h"

#define VFPSTATUEBALL_HIT_SEQID 0x14b /* staff-strike object seq id */

int VFP_statueball_getExtraSize(void)
{
    return sizeof(VfpStatueBallState);
}

int VFP_statueball_getObjectTypeId(void)
{
    return 0x0;
}

void VFP_statueball_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void VFP_statueball_render(void)
{
}

void VFP_statueball_hitDetect(void)
{
}

void VFP_statueball_update(GameObject* obj)
{
    VfpStatueBallPlacement* placement;
    VfpStatueBallState* state;
    GameObject* hitObj;
    int hitType;
    int variant;

    placement = (VfpStatueBallPlacement*)obj->anim.placementData;
    state = obj->extra;
    hitObj = 0;

    if (state->active != 0)
    {
        state->burstEffectId = 6;
        state->burstChance = 0x14;
        state->burstScale = 0xa;
    }
    else
    {
        state->burstEffectId = 5;
        state->burstChance = 0x28;
        state->burstScale = 5;
    }

    state->timer -= (s16)timeDelta;

    variant = placement->variant;
    if (variant == 0)
    {
        objfx_spawnDirectionalBurst(obj, state->burstEffectId, 1.0f, 5, 1, state->burstChance,
                                    state->burstScale, 0, 0);
    }
    else if (variant == 1)
    {
        objfx_spawnDirectionalBurst(obj, state->burstEffectId, 1.0f, 2, 1, state->burstChance,
                                    state->burstScale, 0, 0);
    }
    else
    {
        objfx_spawnDirectionalBurst(obj, state->burstEffectId, 1.0f, 1, 1, state->burstChance,
                                    state->burstScale, 0, 0);
    }

    Vec_distance(&Obj_GetPlayerObject()->anim.worldPosX, &obj->anim.worldPosX);
    state->previousActive = state->active;

    if ((u32)mainGetBit(state->activationGameBit) == 0)
    {
        hitType = ObjHits_GetPriorityHit(obj, (int*)&hitObj, 0, 0);
        if ((hitObj != NULL) && (hitType != 0) && (hitObj != NULL) &&
            (hitObj->anim.seqId == VFPSTATUEBALL_HIT_SEQID))
        {
            if ((u8)fn_8016F16C(hitObj) == placement->variant)
            {
                state->active = (u8)(1 - state->active);
            }
            else
            {
                Sfx_PlayFromObject(0, SFXTRIG_npu_216);
            }
        }

        obj->anim.rotX = (s16)(obj->anim.rotX + ((s32)timeDelta * 0x82));
    }

    if ((state->active != 0) && (state->activateSfxPending != 0))
    {
        state->activateSfxPending = 0;
        Sfx_PlayFromObject((int)obj, SFXTRIG_cvdrip1c);
        Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
    }

    if (state->active != state->previousActive)
    {
        if (state->active != 0)
        {
            if (state->activationGameBit != -1)
            {
                if ((u32)mainGetBit(state->activationGameBit) == 0)
                {
                    mainSetBits(state->activationGameBit, 1);
                }
            }
            state->activateSfxPending = 1;
        }
        else
        {
            Sfx_StopObjectChannel((int)obj, 0x40);
            (*gExpgfxInterface)->freeSource((u32)obj);
            if (state->activationGameBit != -1)
            {
                if ((u32)mainGetBit(state->activationGameBit) != 0)
                {
                    mainSetBits(state->activationGameBit, 0);
                }
            }
        }
    }
}

void VFP_statueball_init(GameObject* obj, VfpStatueBallPlacement* placement)
{
    VfpStatueBallState* state = obj->extra;
    state->activationGameBit = placement->activationGameBit;
    state->timer = 0x19;
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
    if (placement->variant > 2)
    {
        placement->variant = 2;
    }
    if (placement->scale > 1)
    {
        obj->anim.rootMotionScale = obj->anim.rootMotionScale * (f32)(s32)placement->scale;
    }
    Obj_SetActiveModelIndex(obj, placement->variant);
    state->active = mainGetBit(state->activationGameBit);
}

void VFP_statueball_release(void)
{
}

void VFP_statueball_initialise(void)
{
}
