/* DLL 0x00FA (invisiblehitswitch) - Invisible hit switch object [0x8017A8EC-0x8017AC2C). */
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/dll/dll_00FA_invisiblehitswitch.h"

#define INVISIBLEHITSWITCH_OBJFLAG_HIDDEN 0x4000
#define INVISIBLEHITSWITCH_OBJFLAG_HITDETECT_DISABLED 0x2000

/*
 * Low 2 bits of InvisibleHitSwitchPlacement.triggerMode select the switch
 * behaviour when hit. (Same mode field as dll_00F9 projectileswitch.)
 */
#define SWITCH_MODE_MASK 3
#define SWITCH_MODE_LATCH 0     /* activates and stays on; cannot be toggled off */
#define SWITCH_MODE_TOGGLE 1    /* a second hit while active turns it back off */
#define SWITCH_MODE_MOMENTARY 2 /* activates, then auto-clears after cooldownFrames */
#define SWITCH_MODE_DELAYED 3   /* hit arms an activation wind-up before turning on */

extern f32 lbl_803E3750;

int InvisibleHitSwitch_getExtraSize(void) { return 0xc; }

void InvisibleHitSwitch_update(GameObject *obj)
{

    InvisibleHitSwitchPlacement* placement;
    InvisibleHitSwitchState* state;
    int hitId;
    f32 zero = 0.0f;

    placement = (InvisibleHitSwitchPlacement*)obj->anim.placementData;
    state = obj->extra;
    if (state->active != 0)
    {
        if (mainGetBit((int)placement->gameBitId) == 0)
        {
            state->active = 0;
        }
    }
    else
    {
        if (mainGetBit((int)placement->gameBitId) != 0)
        {
            state->active = 1;
        }
    }

    if (state->cooldownTimer > 0.0f)
    {
        state->cooldownTimer = state->cooldownTimer - (f32)(u32)framesThisStep;
        if (state->cooldownTimer <= 0.0f)
        {
            state->cooldownTimer = 0.0f;
            mainSetBits((int)placement->gameBitId, 0);
        }
        else
        {
            return;
        }
    }

    if (state->activationTimer != zero)
    {
        state->activationTimer = state->activationTimer - timeDelta;
        if (state->activationTimer < 60.0f)
        {
            hitId = ObjHits_GetPriorityHit(obj, 0, 0, 0);
            if ((int)state->hitId == hitId)
            {
                state->activationTimer = 0.0f;
                state->active = 1;
                mainSetBits((int)placement->gameBitId, 1);
            }
            else if (state->activationTimer <= 0.0f)
            {
                state->activationTimer = 0.0f;
            }
        }
    }
    else
    {
        hitId = ObjHits_GetPriorityHit(obj, 0, 0, 0);
        if ((int)state->hitId != hitId) return;
        if (state->active != 0)
        {
            if ((placement->triggerMode & SWITCH_MODE_MASK) != SWITCH_MODE_TOGGLE) return;
            state->active = 0;
            mainSetBits((int)placement->gameBitId, 0);
        }
        else
        {
            if ((placement->triggerMode & SWITCH_MODE_MASK) == SWITCH_MODE_DELAYED)
            {
                state->activationTimer = 120.0f;
                return;
            }
            state->active = 1;
            mainSetBits((int)placement->gameBitId, 1);
            if ((placement->triggerMode & SWITCH_MODE_MASK) == SWITCH_MODE_MOMENTARY)
            {
                state->cooldownTimer = 60.0f * (0.1f * (f32)placement->cooldownFrames);
            }
        }
    }
}

void InvisibleHitSwitch_init(GameObject* obj, InvisibleHitSwitchPlacement* placement)
{

    InvisibleHitSwitchState* info;

    info = obj->extra;
    (obj)->objectFlags = (u16)((obj)->objectFlags | (INVISIBLEHITSWITCH_OBJFLAG_HIDDEN | INVISIBLEHITSWITCH_OBJFLAG_HITDETECT_DISABLED));
    if (placement->radiusScale == 0)
    {
        (obj)->anim.rootMotionScale = (obj)->anim.modelInstance->rootMotionScaleBase;
    }
    else
    {
        {
            f32 v = (f32)(u32)placement->radiusScale * (obj)->anim.modelInstance->rootMotionScaleBase;
            (obj)->anim.rootMotionScale = v * lbl_803E3750;
        }
    }
    ObjHitbox_SetSphereRadius(
        (ObjAnimComponent*)obj,
        (s16)((placement->radiusScale * (int)(obj)->anim.modelInstance->primaryHitboxRadius) / 64));
    info->active = mainGetBit(placement->gameBitId);
    switch ((placement->hitType & 0xe) >> 1)
    {
    case 0:
    default:
        info->hitId = 5;
        break;
    case 1:
        info->hitId = 0x10;
        break;
    case 2:
        info->hitId = 0x15;
        break;
    }
}

ObjectDescriptor gInvisibleHitSwitchObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0, 0, 0,
    (ObjectDescriptorCallback)InvisibleHitSwitch_init,
    (ObjectDescriptorCallback)InvisibleHitSwitch_update,
    0, 0, 0, 0,
    InvisibleHitSwitch_getExtraSize,
};
