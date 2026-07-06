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
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"

#define WCBEACON_EXTRA_SIZE 0x8

#define WCBEACON_RENDER_TYPE_BASE 0x400
#define WCBEACON_RENDER_TYPE_SHIFT 0xb

#define WCBEACON_SETUP_TYPE_OFFSET 0x18
#define WCBEACON_SETUP_MODEL_INDEX_OFFSET 0x19
#define WCBEACON_SETUP_SOLVED_BIT_OFFSET 0x1e
#define WCBEACON_SETUP_ARM_BIT_OFFSET 0x20

#define WCBEACON_STATE_TIMER 0x0
#define WCBEACON_STATE_PHASE 0x4
#define WCBEACON_STATE_ACCEPTED_INTERACTION 0x5

#define WCBEACON_PHASE_IDLE 0
#define WCBEACON_PHASE_WAITING_FOR_TRICKY 1
#define WCBEACON_PHASE_ACTIVATING 2
#define WCBEACON_PHASE_ACTIVE 3

#define WCBEACON_BLOCK_PLAYER_FLAG 0x8
#define WCBEACON_TRICKY_PROMPT_FLAG 0x4
#define WCBEACON_VISIBLE_PARTFX_FLAG 0x800

#define WCBEACON_PARTFX_ACTIVE 0x73a
#define WCBEACON_PARTFX_KIND 2
#define WCBEACON_TRIGGER_ARM_SLOT 0
#define WCBEACON_TRIGGER_RELEASE_SLOT 1
#define WCBEACON_TRIGGER_ACCEPT_ARG 1
#define WCBEACON_TRIGGER_NO_ARG -1
#define WCBEACON_FINAL_TRIGGER_ID 105

typedef struct WCBeaconSetup
{
    ObjPlacement base;
    s8 type;
    s8 modelIndex;
    u8 pad1A[WCBEACON_SETUP_SOLVED_BIT_OFFSET - 0x1A];
    s16 solvedBit;
    s16 armBit;
    u8 pad22[0x24 - 0x22];
} WCBeaconSetup;

typedef struct WCBeaconState
{
    f32 timer;
    u8 phase;
    u8 acceptedInteraction;
    u8 pad06[WCBEACON_EXTRA_SIZE - 0x06];
} WCBeaconState;

STATIC_ASSERT(sizeof(WCBeaconState) == WCBEACON_EXTRA_SIZE);
STATIC_ASSERT(sizeof(WCBeaconSetup) == 0x24);
STATIC_ASSERT(offsetof(WCBeaconState, timer) == WCBEACON_STATE_TIMER);
STATIC_ASSERT(offsetof(WCBeaconState, phase) == WCBEACON_STATE_PHASE);
STATIC_ASSERT(offsetof(WCBeaconState, acceptedInteraction) == WCBEACON_STATE_ACCEPTED_INTERACTION);
STATIC_ASSERT(offsetof(WCBeaconSetup, type) == WCBEACON_SETUP_TYPE_OFFSET);
STATIC_ASSERT(offsetof(WCBeaconSetup, modelIndex) == WCBEACON_SETUP_MODEL_INDEX_OFFSET);
STATIC_ASSERT(offsetof(WCBeaconSetup, solvedBit) == WCBEACON_SETUP_SOLVED_BIT_OFFSET);
STATIC_ASSERT(offsetof(WCBeaconSetup, armBit) == WCBEACON_SETUP_ARM_BIT_OFFSET);

int wcbeacon_aButtonCallback(int obj)
{
    WCBeaconState* state = ((GameObject*)obj)->extra;
    WCBeaconSetup* setup = (WCBeaconSetup*)((GameObject*)obj)->anim.placementData;

    if (isGameTimerDisabled() == 0)
    {
        state->acceptedInteraction = 1;
        GameBit_Set(setup->solvedBit, 1);
    }
    return 1;
}

int wcbeacon_getExtraSize(void) { return WCBEACON_EXTRA_SIZE; }

int wcbeacon_getObjectTypeId(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int modelIndex = ((WCBeaconSetup*)((GameObject*)obj)->anim.placementData)->modelIndex;
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

void wcbeacon_update(int obj)
{
    WCBeaconSetup* setup = (WCBeaconSetup*)((GameObject*)obj)->anim.placementData;
    WCBeaconState* state = ((GameObject*)obj)->extra;
    u32 phase;

    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= WCBEACON_BLOCK_PLAYER_FLAG;
    phase = state->phase;
    if (phase == WCBEACON_PHASE_WAITING_FOR_TRICKY)
    {
        int tricky = getTrickyObject();
        if ((u32)GameBit_Get(setup->armBit) == 0)
        {
            u32 owner = fn_80138F84(tricky);
            if (owner != obj || trickyFn_80138f14(tricky) != 0)
            {
                (*gObjectTriggerInterface)
                    ->runSequence(WCBEACON_TRIGGER_RELEASE_SLOT, (void*)obj, WCBEACON_TRIGGER_NO_ARG);
                state->phase = WCBEACON_PHASE_IDLE;
            }
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~WCBEACON_BLOCK_PLAYER_FLAG;
            if ((u32)tricky != 0 && (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & WCBEACON_TRICKY_PROMPT_FLAG))
            {
                int recv;
                (*(void (**)(int, int, int, int, int))(recv + 0x28))(
                    tricky, obj, WCBEACON_TRIGGER_ACCEPT_ARG, WCBEACON_TRICKY_PROMPT_FLAG,
                    (recv = *(int*)(*(int*)(tricky + 0x68))));
            }
        }
        if (state->acceptedInteraction != 0)
        {
            Sfx_PlayFromObject(obj, SFXmv_mushdizzylp12);
            Sfx_PlayFromObject(obj, SFXmv_liftloop);
            state->phase = WCBEACON_PHASE_ACTIVATING;
            state->timer = lbl_803E6DE4;
        }
    }
    else if (phase == WCBEACON_PHASE_IDLE)
    {
        if ((u32)GameBit_Get(setup->armBit) != 0)
        {
            (*gObjectTriggerInterface)
                ->runSequence(WCBEACON_TRIGGER_ARM_SLOT, (void*)obj, WCBEACON_TRIGGER_NO_ARG);
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
        if (((GameObject*)obj)->objectFlags & WCBEACON_VISIBLE_PARTFX_FLAG)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, WCBEACON_PARTFX_ACTIVE, NULL,
                                             WCBEACON_PARTFX_KIND, WCBEACON_TRIGGER_NO_ARG, NULL);
        }
        if (((GameObject*)obj)->unkF4 == 0)
        {
            (*gObjectTriggerInterface)->preempt(obj, WCBEACON_FINAL_TRIGGER_ID);
            (*gObjectTriggerInterface)
                ->runSequence(WCBEACON_TRIGGER_ARM_SLOT, (void*)obj, WCBEACON_TRIGGER_ACCEPT_ARG);
        }
    }
    ((GameObject*)obj)->unkF4 = 1;
}

void wcbeacon_init(u8* obj, u8* setup)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCBeaconState* state = ((GameObject*)obj)->extra;
    WCBeaconSetup* setupData = (WCBeaconSetup*)setup;
    s16 objType;

    (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
    objType = (s16)(setupData->type << 8);
    ((GameObject*)obj)->anim.rotX = objType;
    objAnim->bankIndex = setupData->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    if ((u32)GameBit_Get(setupData->armBit) != 0)
    {
        if ((u32)GameBit_Get(setupData->solvedBit) != 0)
        {
            state->phase = WCBEACON_PHASE_ACTIVE;
        }
        else
        {
            state->phase = WCBEACON_PHASE_WAITING_FOR_TRICKY;
        }
    }
}
