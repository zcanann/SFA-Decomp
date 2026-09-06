/*
 * InvisibleHi (DLL 0xFA) - invisible hit-triggered switches.
 *
 * The switch mirrors a game bit, accepts one placement-selected hit priority,
 * and supports latched, toggle, timed-reset, and delayed modes.
 */
#include "dlls/objects/250_InvisibleHi.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/objhits.h"

extern f32 gInvisibleHitSwitchScaleUnit;

#define INVISIBLE_HIT_SWITCH_SCALE_UNITS 64

#define INVISIBLE_HIT_SWITCH_FRAMES_PER_SECOND 60.0f
#define INVISIBLE_HIT_SWITCH_TENTHS_PER_SECOND 0.1f

#define INVISIBLE_HIT_SWITCH_DELAY_START  120.0f
#define INVISIBLE_HIT_SWITCH_DELAY_WINDOW 60.0f

#define INVISIBLE_HIT_SWITCH_HIT_TYPE_MASK  0xE
#define INVISIBLE_HIT_SWITCH_HIT_TYPE_SHIFT 1

enum {
    INVISIBLE_HIT_SWITCH_HIT_TYPE_DEFAULT = 0,
    INVISIBLE_HIT_SWITCH_HIT_TYPE_1 = 1,
    INVISIBLE_HIT_SWITCH_HIT_TYPE_2 = 2
};

#define INVISIBLE_HIT_SWITCH_PRIORITY_DEFAULT 5
#define INVISIBLE_HIT_SWITCH_PRIORITY_TYPE_1  0x10
#define INVISIBLE_HIT_SWITCH_PRIORITY_TYPE_2  0x15

int InvisibleHitSwitch_getExtraSize(void) {
    return sizeof(InvisibleHitSwitchState);
}

void InvisibleHitSwitch_update(GameObject* obj) {
    InvisibleHitSwitchPlacement* placement;
    InvisibleHitSwitchState* state;
    int hitPriority;
    f32 zeroTimer = 0.0f;

    placement = (InvisibleHitSwitchPlacement*)obj->anim.placementData;
    state = obj->extra;
    if (state->isOn != 0) {
        if (mainGetBit((int)placement->gameBitId) == 0) {
            state->isOn = 0;
        }
    } else {
        if (mainGetBit((int)placement->gameBitId) != 0) {
            state->isOn = 1;
        }
    }

    if (state->autoResetTimerFrames > 0.0f) {
        state->autoResetTimerFrames = state->autoResetTimerFrames - (f32)(u32)framesThisStep;
        if (state->autoResetTimerFrames <= 0.0f) {
            state->autoResetTimerFrames = 0.0f;
            mainSetBits((int)placement->gameBitId, 0);
        } else {
            return;
        }
    }

    if (state->delayedTriggerTimer != zeroTimer) {
        state->delayedTriggerTimer -= timeDelta;
        if (state->delayedTriggerTimer < INVISIBLE_HIT_SWITCH_DELAY_WINDOW) {
            hitPriority = ObjHits_GetPriorityHit(obj, NULL, NULL, NULL);
            if (state->hitPriority == hitPriority) {
                state->delayedTriggerTimer = 0.0f;
                state->isOn = 1;
                mainSetBits((int)placement->gameBitId, 1);
            } else if (state->delayedTriggerTimer <= 0.0f) {
                state->delayedTriggerTimer = 0.0f;
            }
        }
    } else {
        hitPriority = ObjHits_GetPriorityHit(obj, NULL, NULL, NULL);
        if (state->hitPriority != hitPriority) {
            return;
        }
        if (state->isOn != 0) {
            if ((placement->mode & INVISIBLE_HIT_SWITCH_MODE_MASK) != INVISIBLE_HIT_SWITCH_MODE_TOGGLE) {
                return;
            }
            state->isOn = 0;
            mainSetBits((int)placement->gameBitId, 0);
        } else {
            if ((placement->mode & INVISIBLE_HIT_SWITCH_MODE_MASK) == INVISIBLE_HIT_SWITCH_MODE_DELAYED) {
                state->delayedTriggerTimer = INVISIBLE_HIT_SWITCH_DELAY_START;
                return;
            }
            state->isOn = 1;
            mainSetBits((int)placement->gameBitId, 1);
            if ((placement->mode & INVISIBLE_HIT_SWITCH_MODE_MASK) == INVISIBLE_HIT_SWITCH_MODE_TIMED_RESET) {
                state->autoResetTimerFrames =
                    INVISIBLE_HIT_SWITCH_FRAMES_PER_SECOND *
                    (INVISIBLE_HIT_SWITCH_TENTHS_PER_SECOND * (f32)placement->autoResetDelayTenths);
            }
        }
    }
}

void InvisibleHitSwitch_init(GameObject* obj, InvisibleHitSwitchPlacement* placement) {
    InvisibleHitSwitchState* state;

    state = obj->extra;
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
    if (placement->radiusScale64 == 0) {
        obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase;
    } else {
        f32 scaledScale = (f32)(u32)placement->radiusScale64 * obj->anim.modelInstance->rootMotionScaleBase;
        obj->anim.rootMotionScale = scaledScale * gInvisibleHitSwitchScaleUnit;
    }
    ObjHitbox_SetSphereRadius(&obj->anim,
                              (s16)((placement->radiusScale64 * (int)obj->anim.modelInstance->primaryHitboxRadius) /
                                    INVISIBLE_HIT_SWITCH_SCALE_UNITS));
    state->isOn = mainGetBit(placement->gameBitId);
    switch ((placement->hitPriorityType & INVISIBLE_HIT_SWITCH_HIT_TYPE_MASK) >> INVISIBLE_HIT_SWITCH_HIT_TYPE_SHIFT) {
    case INVISIBLE_HIT_SWITCH_HIT_TYPE_DEFAULT:
    default:
        state->hitPriority = INVISIBLE_HIT_SWITCH_PRIORITY_DEFAULT;
        break;
    case INVISIBLE_HIT_SWITCH_HIT_TYPE_1:
        state->hitPriority = INVISIBLE_HIT_SWITCH_PRIORITY_TYPE_1;
        break;
    case INVISIBLE_HIT_SWITCH_HIT_TYPE_2:
        state->hitPriority = INVISIBLE_HIT_SWITCH_PRIORITY_TYPE_2;
        break;
    }
}

ObjectDescriptor gInvisibleHitSwitchObjDescriptor = {
    0,                                                   /* reserved0 */
    0,                                                   /* reserved1 */
    0,                                                   /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,                    /* slotCountAndFlags */
    0,                                                   /* initialise */
    0,                                                   /* release */
    0,                                                   /* slot02 */
    (ObjectDescriptorCallback)InvisibleHitSwitch_init,   /* init */
    (ObjectDescriptorCallback)InvisibleHitSwitch_update, /* update */
    0,                                                   /* hitDetect */
    0,                                                   /* render */
    0,                                                   /* free */
    0,                                                   /* getObjectTypeId */
    InvisibleHitSwitch_getExtraSize,                     /* getExtraSize */
};
