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
#include "main/object_render_legacy.h"
#include "main/object_descriptor.h"

#define WCBEACON_EXTRA_SIZE 0x8

#define WCBEACON_RENDER_TYPE_BASE  0x400
#define WCBEACON_RENDER_TYPE_SHIFT 0xb

#define WCBEACON_PHASE_IDLE               0
#define WCBEACON_PHASE_WAITING_FOR_TRICKY 1
#define WCBEACON_PHASE_ACTIVATING         2
#define WCBEACON_PHASE_ACTIVE             3

#define WCBEACON_BLOCK_PLAYER_FLAG   0x8
#define WCBEACON_TRICKY_PROMPT_FLAG  0x4
#define WCBEACON_VISIBLE_PARTFX_FLAG 0x800

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
    return WCBEACON_EXTRA_SIZE;
}

int wcbeacon_getObjectTypeId(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int modelIndex = ((WCBeaconSetup*)obj->anim.placementData)->modelIndex;
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount)
    {
        modelIndex = 0;
    }
    return (modelIndex << WCBEACON_RENDER_TYPE_SHIFT) | WCBEACON_RENDER_TYPE_BASE;
}

void wcbeacon_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6DE0);
    }
}

void wcbeacon_update(GameObject* obj)
{
    WCBeaconSetup* setup = (WCBeaconSetup*)obj->anim.placementData;
    WCBeaconState* state = obj->extra;
    u32 phase;

    *(u8*)&obj->anim.resetHitboxMode |= WCBEACON_BLOCK_PLAYER_FLAG;
    phase = state->phase;
    if (phase == WCBEACON_PHASE_WAITING_FOR_TRICKY)
    {
        GameObject* tricky = getTrickyObject();
        if ((u32)mainGetBit(setup->armBit) == 0)
        {
            GameObject* owner = fn_80138F84(tricky);
            if (owner != obj || trickyFn_80138f14(tricky) != 0)
            {
                (*gObjectTriggerInterface)
                    ->runSequence(WCBEACON_TRIGGER_RELEASE_SLOT, obj, WCBEACON_TRIGGER_NO_ARG);
                state->phase = WCBEACON_PHASE_IDLE;
            }
        }
        else
        {
            *(u8*)&obj->anim.resetHitboxMode &= ~WCBEACON_BLOCK_PLAYER_FLAG;
            if (tricky != NULL && (*(u8*)&obj->anim.resetHitboxMode & WCBEACON_TRICKY_PROMPT_FLAG))
            {
                int recv;
                (*(void (**)(int, int, int, int, int))(recv + 0x28))((int)tricky, (int)obj, WCBEACON_TRIGGER_ACCEPT_ARG,
                                                                     WCBEACON_TRICKY_PROMPT_FLAG,
                                                                     (recv = *(int*)(*(int*)((u8*)tricky + 0x68))));
            }
        }
        if (state->acceptedInteraction != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_en_trpopn_c_9f);
            Sfx_PlayFromObject((int)obj, SFXTRIG_forcecryslp11);
            state->phase = WCBEACON_PHASE_ACTIVATING;
            state->timer = lbl_803E6DE4;
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
        if (v >= lbl_803E6DE8)
        {
            state->phase = WCBEACON_PHASE_ACTIVE;
        }
    }
    else if (phase == WCBEACON_PHASE_ACTIVE)
    {
        if (obj->objectFlags & WCBEACON_VISIBLE_PARTFX_FLAG)
        {
            (*gPartfxInterface)
                ->spawnObject(obj, WCBEACON_PARTFX_ACTIVE, NULL, WCBEACON_PARTFX_KIND, WCBEACON_TRIGGER_NO_ARG,
                              NULL);
        }
        if (obj->unkF4 == 0)
        {
            (*gObjectTriggerInterface)->preempt((int)obj, WCBEACON_FINAL_TRIGGER_ID);
            (*gObjectTriggerInterface)->runSequence(WCBEACON_TRIGGER_ARM_SLOT, obj, WCBEACON_TRIGGER_ACCEPT_ARG);
        }
    }
    obj->unkF4 = 1;
}

void wcbeacon_init(GameObject* obj, WCBeaconSetup* setup)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCBeaconState* state = obj->extra;
    s16 objType;

    (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
    objType = (s16)(setup->type << 8);
    obj->anim.rotX = objType;
    objAnim->bankIndex = setup->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
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
