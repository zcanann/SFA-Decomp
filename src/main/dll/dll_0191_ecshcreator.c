/*
 * DLL 0x0191 - ecshcreator ("ECSH_Creato", the ecshrine-map SharpClaw
 * wave spawner). TU 0x801C6E0C-0x801C70F0.
 *
 * A placement-spawned manager object: on init it stores a per-instance
 * EcshCreatorState (in obj->extra) with the countdown (=100) and the
 * trigger game bit read from the placement. update() waits until that
 * game bit is set, then acquires resource 0x82, runs its two setup
 * vtable slots, plays a sfx and starts
 * the countdown (decremented by framesThisStep each tick). Once object
 * loading is unlocked and the countdown reaches <= 0 it allocates a 0x38
 * byte spawn descriptor and creates a SharpClaw child (defNo 0x11
 * "sharpclawGr") via Obj_SetupObject, sets configFlags 0x20 on its
 * GroundBaddieState, then re-arms the countdown.
 */
#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/obj_placement.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0191_ecshcreator.h"
#include "main/dll/foodbag.h"
#include "main/dll/baddie_state.h"

#define ECSH_SHRINE_RESOURCE 0x82 /* setup resource (Resource_Acquire id) */
#define ECSH_SHARPCLAW_OBJ 0x11 /* defNo of the spawned child: "sharpclawGr" (DLL 0xC9) */
#define ECSH_COUNTDOWN_START 100
#define ECSH_CHILD_GROUP_SLOT_BASE 2
#define ECSH_SHARPCLAW_DISABLE_CAMERA_TARGET 0x20

extern f32 lbl_803E4FF8;

ObjectDescriptor gECSH_CreatorObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)ecsh_creator_initialise, (ObjectDescriptorCallback)ecsh_creator_release, 0,
    (ObjectDescriptorCallback)ecsh_creator_init, (ObjectDescriptorCallback)ecsh_creator_update,
    (ObjectDescriptorCallback)ecsh_creator_hitDetect, (ObjectDescriptorCallback)ecsh_creator_render,
    (ObjectDescriptorCallback)ecsh_creator_free, (ObjectDescriptorCallback)ecsh_creator_getObjectTypeId,
    ecsh_creator_getExtraSize,
};

int ecsh_creator_getExtraSize(void)
{
    return sizeof(EcshCreatorState);
}
int ecsh_creator_getObjectTypeId(void)
{
    return 0x0;
}

void ecsh_creator_free(void)
{
}

void ecsh_creator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E4FF8);
}

void ecsh_creator_hitDetect(void)
{
}

void ecsh_creator_update(GameObject* obj)
{
    EcshCreatorPlacement* placement;
    EcshCreatorState* state;
    Dll82Interface** effectResource;
    EcshSharpClawSpawnSetup* spawnSetup;
    GameObject* sharpClaw;

    placement = (EcshCreatorPlacement*)obj->anim.placementData;
    state = obj->extra;
    if (obj->userData2 == 0 && (u32)mainGetBit(state->triggerGameBit) != 0)
    {
        effectResource = Resource_Acquire(ECSH_SHRINE_RESOURCE, 1);
        (*effectResource)->spawn(obj, 0, NULL, 1, -1, NULL);
        (*effectResource)->spawn(obj, 1, NULL, 1, -1, NULL);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_wp_hitpos_6);
        Resource_Release(effectResource);
        state->spawnTimerStep = 1;
        obj->userData2 = 1;
    }
    if (state->spawnTimerStep != 0)
    {
        state->spawnTimer = state->spawnTimer - state->spawnTimerStep * framesThisStep;
    }
    if (Obj_IsLoadingLocked() != 0 && state->spawnTimer <= 0)
    {
        spawnSetup = mmAlloc(sizeof(EcshSharpClawSpawnSetup), 0xe, 0);
        spawnSetup->base.posX = placement->base.posX;
        spawnSetup->base.posY = placement->base.posY;
        spawnSetup->base.posZ = placement->base.posZ;
        spawnSetup->base.objectId = ECSH_SHARPCLAW_OBJ;
        spawnSetup->base.mapId = -1;
        spawnSetup->base.color[0] = placement->base.color[0];
        spawnSetup->base.color[1] = placement->base.color[1];
        spawnSetup->base.color[2] = placement->base.color[2];
        spawnSetup->base.color[3] = placement->base.color[3];
        spawnSetup->unk27 = 3;
        spawnSetup->unk28 = 0;
        spawnSetup->gameBit = state->triggerGameBit + placement->childGameBitOffset;
        spawnSetup->unk30 = -1;
        spawnSetup->rotX = (s8)(obj->anim.rotX >> 8);
        spawnSetup->unk2B = 2;
        spawnSetup->unk20 = 0;
        spawnSetup->unk1E = 0;
        spawnSetup->unk22 = -1;
        spawnSetup->unk29 = 0xff;
        spawnSetup->unk2E = -1;
        spawnSetup->unk24 = 0;
        spawnSetup->unk2C = 0;
        spawnSetup->unk34 = 0xFFFF;
        spawnSetup->unk1A = 0;
        spawnSetup->groupSlot = state->childGroupSlot;
        sharpClaw = Obj_SetupObject(&spawnSetup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
        if (sharpClaw != NULL)
        {
            ((GroundBaddieState*)sharpClaw->extra)->configFlags = ECSH_SHARPCLAW_DISABLE_CAMERA_TARGET;
        }
        state->spawnTimer = ECSH_COUNTDOWN_START;
        state->spawnTimerStep = 0;
    }
}

void ecsh_creator_init(GameObject* obj, EcshCreatorPlacement* placement)
{
    EcshCreatorState* state = obj->extra;
    obj->anim.rotX = (s16)((s32)placement->initialRotX << 8);
    obj->userData2 = 0;
    state->spawnTimer = ECSH_COUNTDOWN_START;
    state->spawnTimerStep = 0;
    obj->anim.renderAlpha = 0xff;
    obj->anim.alpha = 0xff;
    state->triggerGameBit = placement->triggerGameBit;
    state->childGroupSlot = ECSH_CHILD_GROUP_SLOT_BASE;
    state->childGroupSlot += placement->groupSlotOffset;
}

void ecsh_creator_release(void)
{
}

void ecsh_creator_initialise(void)
{
}
