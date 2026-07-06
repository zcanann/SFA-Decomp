/*
 * babycloudrunner (DLL 0xFC) - a follower object that latches onto the
 * nearest object of a placement-named group and mirrors its position and
 * rotation every frame. Once latched (mode 1) it watches a gate game bit
 * and, when the player triggers it (INTERACT_FLAG_ACTIVATED), fires a
 * trigger sequence and advances/remembers state through two placement
 * game bits.
 *
 * State machine (BabyCloudRunnerState.mode):
 *   0 = uninitialised (no target yet)
 *   1 = latched and interactive
 *   2 = waiting for the gate game bit to be set again
 *   3 = finished (remembered bit was already set, or flags bit 1 holds it)
 *
 * Placement flags (BabyCloudRunnerPlacement.flags):
 *   0x1 = remembered-bit set means "already done" -> go straight to mode 3
 *   0x2 = clear the gate game bit when the sequence fires
 *   0x4 = pick the trigger sequence id randomly in [triggerIdMin..Max]
 */
#include "main/dll/dll_0117_appleontree.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/obj_placement.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"

#define BABYCLOUDRUNNER_OBJFLAG_HIDDEN 0x4000

typedef struct BabyCloudRunnerPlacement
{
    ObjPlacement base;
    s16 gateGameBit;        /* 0x18: -1 = none */
    s16 rememberedGameBit;  /* 0x1A: -1 = none */
    u8 targetGroup;         /* 0x1C: object group to follow */
    u8 triggerIdMin;        /* 0x1D */
    u8 triggerIdMax;        /* 0x1E */
    u8 flags;               /* 0x1F: BABYCLOUDRUNNER_FLAG_* */
    u8 pad20[4];
} BabyCloudRunnerPlacement;

typedef struct BabyCloudRunnerState
{
    u8 mode;                    /* 0x00 */
    u8 triggerId;               /* 0x01: trigger sequence index */
    u8 rememberedGameBitValue;  /* 0x02 */
    u8 pad03;
    GameObject* target;         /* 0x04: followed object */
} BabyCloudRunnerState;

STATIC_ASSERT(sizeof(BabyCloudRunnerState) == 0x8);
STATIC_ASSERT(sizeof(BabyCloudRunnerPlacement) == 0x24);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, gateGameBit) == 0x18);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, rememberedGameBit) == 0x1A);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, targetGroup) == 0x1C);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, triggerIdMin) == 0x1D);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, triggerIdMax) == 0x1E);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, flags) == 0x1F);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, target) == 0x4);

/* BabyCloudRunnerState.mode */
#define BABYCLOUDRUNNER_MODE_UNINIT 0
#define BABYCLOUDRUNNER_MODE_LATCHED 1
#define BABYCLOUDRUNNER_MODE_WAIT_GATE 2
#define BABYCLOUDRUNNER_MODE_FINISHED 3

/* BabyCloudRunnerPlacement.flags bits */
#define BABYCLOUDRUNNER_FLAG_REMEMBERED_DONE 0x1
#define BABYCLOUDRUNNER_FLAG_CLEAR_GATE_BIT 0x2
#define BABYCLOUDRUNNER_FLAG_RANDOM_TRIGGER 0x4

extern f32 lbl_803E3848; /* render distance constant */
extern f32 lbl_803E384C; /* initial max-distance for the nearest-object search */
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void objRenderFn_80041018(int* obj);


void dll_FC_initialise_nop(void);
void dll_FC_release_nop(void);
void dll_FC_init(int obj, int objDef);
void dll_FC_update(int obj);
void dll_FC_hitDetect(int* obj);

void dll_FC_free_nop(void)
{
}

int dll_FC_getExtraSize_ret_8(void) { return sizeof(BabyCloudRunnerState); }
int dll_FC_getObjectTypeId(void) { return 0x0; }

void dll_FC_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 isVisible = visible;
    if (isVisible != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E3848);
}

void dll_FC_hitDetect(int* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    if ((objAnim->modelInstance->flags & 1u) == 0u) return;
    if (objAnim->hitVolumeTransforms == NULL) return;
    objRenderFn_80041018(obj);
}

ObjectDescriptor gDllFCObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_FC_initialise_nop,
    (ObjectDescriptorCallback)dll_FC_release_nop,
    0,
    (ObjectDescriptorCallback)dll_FC_init,
    (ObjectDescriptorCallback)dll_FC_update,
    (ObjectDescriptorCallback)dll_FC_hitDetect,
    (ObjectDescriptorCallback)dll_FC_render,
    (ObjectDescriptorCallback)dll_FC_free_nop,
    (ObjectDescriptorCallback)dll_FC_getObjectTypeId,
    dll_FC_getExtraSize_ret_8,
};

void dll_FC_update(int obj)
{
    BabyCloudRunnerPlacement* placement;
    BabyCloudRunnerState* state;
    u32 gameBitValue;
    u32 randomTrigger;
    f32 maxDist;

    maxDist = lbl_803E384C;
    placement = (BabyCloudRunnerPlacement*)((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;

    if (state->target == NULL)
    {
        state->target = (GameObject*)ObjGroup_FindNearestObject(placement->targetGroup, obj, &maxDist);
        if (state->target == NULL) goto end;
        if ((int)placement->rememberedGameBit == -1)
        {
            state->rememberedGameBitValue = 0;
        }
        else
        {
            gameBitValue = GameBit_Get((int)placement->rememberedGameBit);
            state->rememberedGameBitValue = gameBitValue;
        }
        state->mode = BABYCLOUDRUNNER_MODE_LATCHED;
    }

    ((GameObject*)obj)->anim.localPosX = state->target->anim.localPosX;
    ((GameObject*)obj)->anim.localPosY = state->target->anim.localPosY;
    ((GameObject*)obj)->anim.localPosZ = state->target->anim.localPosZ;
    ((GameObject*)obj)->anim.rotX = state->target->anim.rotX;
    ((GameObject*)obj)->anim.rotZ = state->target->anim.rotZ;
    ((GameObject*)obj)->anim.rotY = state->target->anim.rotY;

    switch (state->mode)
    {
    case BABYCLOUDRUNNER_MODE_FINISHED:
        break;
    case BABYCLOUDRUNNER_MODE_LATCHED:
        if ((state->rememberedGameBitValue != 0) && ((placement->flags & BABYCLOUDRUNNER_FLAG_REMEMBERED_DONE) == 0))
        {
            state->target->anim.resetHitboxFlags &= ~0x20;
            ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            state->mode = BABYCLOUDRUNNER_MODE_FINISHED;
        }
        else if (((int)placement->gateGameBit != -1) &&
            (GameBit_Get((int)placement->gateGameBit) == 0))
        {
            state->target->anim.resetHitboxFlags &= ~0x20;
            ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            state->mode = BABYCLOUDRUNNER_MODE_WAIT_GATE;
        }
        else if ((((GameObject*)obj)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
        {
            if ((placement->flags & BABYCLOUDRUNNER_FLAG_CLEAR_GATE_BIT) != 0)
            {
                GameBit_Set((int)placement->gateGameBit, 0);
            }
            if ((int)placement->rememberedGameBit != -1)
            {
                GameBit_Set((int)placement->rememberedGameBit, 1);
            }
            if ((placement->flags & BABYCLOUDRUNNER_FLAG_RANDOM_TRIGGER) != 0)
            {
                randomTrigger = randomGetRange((int)placement->triggerIdMin, placement->triggerIdMax);
                state->triggerId = randomTrigger;
            }
            else
            {
                state->triggerId += 1;
                if (state->triggerId > placement->triggerIdMax)
                {
                    state->triggerId = placement->triggerIdMin;
                }
            }
            ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            state->rememberedGameBitValue = 1;
            (*gObjectTriggerInterface)->runSequence(state->triggerId, (void*)obj, -1);
        }
        else
        {
            state->target->anim.resetHitboxFlags |= 0x20;
            ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        }
        break;
    case BABYCLOUDRUNNER_MODE_WAIT_GATE:
        if (GameBit_Get((int)placement->gateGameBit) != 0)
        {
            state->mode = BABYCLOUDRUNNER_MODE_LATCHED;
        }
        break;
    }
end:
    return;
}

void dll_FC_init(int obj, int objDef)
{
    BabyCloudRunnerState* state;
    BabyCloudRunnerPlacement* placement;

    state = ((GameObject*)obj)->extra;
    placement = (BabyCloudRunnerPlacement*)objDef;
    state->mode = BABYCLOUDRUNNER_MODE_UNINIT;
    state->triggerId = placement->triggerIdMax;
    ((GameObject*)obj)->objectFlags |= BABYCLOUDRUNNER_OBJFLAG_HIDDEN;
}

void dll_FC_release_nop(void)
{
}

void dll_FC_initialise_nop(void)
{
}
