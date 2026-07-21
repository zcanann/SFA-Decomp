/*
 * wcbeacon (DLL 0x28E) - a Tricky-activated beacon puzzle prop in the
 * Walled City (WC).
 *
 * The beacon advances through WCBEACON_PHASE_*:
 *  - IDLE: waits until its armBit game bit is set, then runs the arm
 *    trigger sequence and moves to WAITING_FOR_TRICKY.
 *  - WAITING_FOR_TRICKY: blocks the player and waits for Tricky (the
 *    companion) to take ownership and accept the prompt; the A-button
 *    callback marks acceptedInteraction and sets solvedBit. If the arm
 *    bit clears or Tricky leaves, it runs the release sequence and falls
 *    back to IDLE. Once accepted it plays the lift sfx and goes ACTIVATING.
 *  - ACTIVATING: counts the timer up by timeDelta, then goes ACTIVE.
 *  - ACTIVE: emits the active particle fx and fires the final trigger
 *    sequence once.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/dll_80136a40.h"
#include "main/object.h"
#include "main/dll/WC/WCbeacon.h"
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/game_timer.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"

#define WCBEACON_RENDER_TYPE_BASE  0x400
#define WCBEACON_RENDER_TYPE_SHIFT 0xb

#define WCBEACON_PHASE_IDLE               0
#define WCBEACON_PHASE_WAITING_FOR_TRICKY 1
#define WCBEACON_PHASE_ACTIVATING         2
#define WCBEACON_PHASE_ACTIVE             3

#define WCBEACON_PARTFX_ACTIVE        0x73a
#define WCBEACON_PARTFX_KIND          2
#define WCBEACON_TRIGGER_ARM_SLOT     0
#define WCBEACON_TRIGGER_RELEASE_SLOT 1
#define WCBEACON_TRIGGER_ACCEPT_ARG   1
#define WCBEACON_TRIGGER_NO_ARG       -1
#define WCBEACON_FINAL_TRIGGER_ID     105

int wcbeacon_aButtonCallback(GameObject* obj)
{
    WCBeaconState* state = obj->extra;
    WCBeaconSetup* setup = (WCBeaconSetup*)obj->anim.placementData;

    if (isGameTimerDisabled() == 0)
    {
        state->acceptedInteraction = 1;
        mainSetBits(setup->solvedBit, 1);
    }
    return 1;
}

int wcbeacon_getExtraSize(void)
{
    return sizeof(WCBeaconState);
}

int wcbeacon_getObjectTypeId(GameObject* obj)
{
    int modelIndex = ((WCBeaconSetup*)obj->anim.placementData)->modelIndex;
    int modelCount = obj->anim.modelInstance->modelCount;

    if (modelIndex >= modelCount)
    {
        modelIndex = 0;
    }
    return (modelIndex << WCBEACON_RENDER_TYPE_SHIFT) | WCBEACON_RENDER_TYPE_BASE;
}

void wcbeacon_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, WCBEACON_RENDER_SCALE);
    }
}

void wcbeacon_update(GameObject* obj)
{
    WCBeaconSetup* setup = (WCBeaconSetup*)obj->anim.placementData;
    WCBeaconState* state = obj->extra;
    u32 phase;

    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    phase = state->phase;
    if (phase == WCBEACON_PHASE_WAITING_FOR_TRICKY)
    {
        GameObject* tricky = getTrickyObject();
        if ((u32)mainGetBit(setup->armBit) == 0)
        {
            GameObject* stayPoint = trickyGetStayPoint(tricky);
            if (stayPoint != obj || trickyFn_80138f14(tricky) != 0)
            {
                (*gObjectTriggerInterface)
                    ->runSequence(WCBEACON_TRIGGER_RELEASE_SLOT, obj, WCBEACON_TRIGGER_NO_ARG);
                state->phase = WCBEACON_PHASE_IDLE;
            }
        }
        else
        {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            if (tricky != NULL && (obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE))
            {
                (*(WCBeaconTrickyInterfaceVTable**)tricky->anim.dll)->acceptInteraction(
                    tricky, obj, WCBEACON_TRIGGER_ACCEPT_ARG, INTERACT_FLAG_IN_RANGE);
            }
        }
        if (state->acceptedInteraction != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_en_trpopn_c_9f);
            Sfx_PlayFromObject((int)obj, SFXTRIG_forcecryslp11);
            state->phase = WCBEACON_PHASE_ACTIVATING;
            state->timer = WCBEACON_TIMER_INITIAL;
        }
    }
    else if (phase == WCBEACON_PHASE_IDLE)
    {
        if ((u32)mainGetBit(setup->armBit) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(WCBEACON_TRIGGER_ARM_SLOT, obj, WCBEACON_TRIGGER_NO_ARG);
            state->phase = WCBEACON_PHASE_WAITING_FOR_TRICKY;
        }
    }
    else if (phase == WCBEACON_PHASE_ACTIVATING)
    {
        f32 v = state->timer + timeDelta;
        state->timer = v;
        if (v >= WCBEACON_ACTIVATION_DURATION)
        {
            state->phase = WCBEACON_PHASE_ACTIVE;
        }
    }
    else if (phase == WCBEACON_PHASE_ACTIVE)
    {
        if (obj->objectFlags & OBJECT_OBJFLAG_RENDERED)
        {
            (*gPartfxInterface)
                ->spawnObject(obj, WCBEACON_PARTFX_ACTIVE, NULL, WCBEACON_PARTFX_KIND, WCBEACON_TRIGGER_NO_ARG,
                              NULL);
        }
        if (obj->userData1 == 0)
        {
            (*gObjectTriggerInterface)->preempt((int)obj, WCBEACON_FINAL_TRIGGER_ID);
            (*gObjectTriggerInterface)->runSequence(WCBEACON_TRIGGER_ARM_SLOT, obj, WCBEACON_TRIGGER_ACCEPT_ARG);
        }
    }
    obj->userData1 = 1;
}

void wcbeacon_init(GameObject* obj, WCBeaconSetup* setup)
{
    WCBeaconState* state = obj->extra;
    s16 objType;

    (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
    objType = (s16)(setup->type << 8);
    obj->anim.rotX = objType;
    obj->anim.bankIndex = setup->modelIndex;
    if (obj->anim.bankIndex >= obj->anim.modelInstance->modelCount)
    {
        obj->anim.bankIndex = 0;
    }
    if ((u32)mainGetBit(setup->armBit) != 0)
    {
        if ((u32)mainGetBit(setup->solvedBit) != 0)
        {
            state->phase = WCBEACON_PHASE_ACTIVE;
        }
        else
        {
            state->phase = WCBEACON_PHASE_WAITING_FOR_TRICKY;
        }
    }
}

ObjectDescriptor gWCBeaconObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)wcbeacon_init,
    (ObjectDescriptorCallback)wcbeacon_update,
    0,
    (ObjectDescriptorCallback)wcbeacon_render,
    0,
    (ObjectDescriptorCallback)wcbeacon_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)wcbeacon_getExtraSize,
};
