/*
 * dll_1CE: hatch-door object. The lid coasts open under a clamped velocity
 * while idle; once a key object (seqId 0x18F or 0x1D6) is in range it counts
 * down, sets its placement gamebit, and - if the load isn't locked and the
 * placement's contents-spawn value matches gamebit 0x46D - spawns its
 * contents object (object id 0x246) seeded from the door's placement.
 *
 * The TU also hosts dimmagicbridge_* and explosion_* sibling exports (in
 * DIM/dll_01CC_dimmagicbridge.c / DIM/dll_01CA_dimexplosion.c); their forward
 * declarations and the descriptor that combines them live in this object's DLL.
 */
#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/DIM/dll_01CD_dimlevelcontrol.h"
#include "main/dll/dimmagicbridge_api.h"
#include "main/dll/dll1ceplacement_struct.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/dll/collectible_state.h"
#include "main/dll/dll_01CE_dll1ce.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/dll1cestate_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/explosion_state.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/object_descriptor.h"
#include "main/audio/sfx_ids.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/object_render.h"

/*
 * Per-object extra state for the dimwooddoor2 burnable door
 * (dimwooddoor2_getExtraSize == 0xC).
 */

STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);

/*
 * Per-object extra state for the dll_1CE hatch door
 * (dll_1CE_getExtraSize == 0xC).
 */

/*
 * Per-object extra state for the dimmagicbridge flame bridge
 * (dimmagicbridge_getExtraSize == 0x68). init/SeqFn here, dll_199/19A
 * variants in dimmagicbridge.c use their own layout.
 */

STATIC_ASSERT(sizeof(DimMagicBridgeState) == 0x68);

STATIC_ASSERT(sizeof(ExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, velocityX) == 0x24);

/*
 * Per-object extra state for the explosion effect
 * (explosion_getExtraSize == 0xA60). The flame pool (50 x 0x30 records)
 * and the debris pool (6 x 0x24 at 0x964) are walked with raw stride
 * pointers in update/render and stay untyped.
 */

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);

/* Key objects that unlock the hatch (docblock: "a key object (seqId 0x18F or 0x1D6)"). */
#define DLL1CE_SEQID_DIM_HUT_DOOR 0x334 /* retail "DIMHutDoor" (DLL 0x128) */
#define DLL1CE_KEY_SEQID_A 0x18f /* retail "DIMSnowHorn..." (DLL 0x256) */
#define DLL1CE_KEY_SEQID_B 0x1d6 /* retail "DIMCannonBa..." (DLL 0x1C6) */

/* Contents object spawned on unlock (retail "DIMBridgeCo...", DLL 0xED). */
#define DLL1CE_CONTENTS_OBJECT_ID    0x246
#define DLL1CE_CONTENTS_GATE_GAMEBIT 0x46d

void* gDll1CEResource;

int dll_1CE_getExtraSize(void)
{
    return 0xc;
}
int dll_1CE_getObjectTypeId(void)
{
    return 0x0;
}

void dll_1CE_free(void)
{
    if (gDll1CEResource != NULL)
    {
        Resource_Release(gDll1CEResource);
    }
    gDll1CEResource = NULL;
}

void dll_1CE_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dll_1CE_hitDetect(void)
{
}

/* dll_1CE_update: hatch-door logic - coast the lid open with clamped
 * velocity while idle, and once a key object is nearby, count down then
 * ring the gamebit and (if the load isn't locked) spawn the contents
 * object seeded from the door's transform. */
void dll_1CE_update(GameObject* obj)
{
    Dll1CEPlacement* placement = (Dll1CEPlacement*)obj->anim.placementData;
    Dll1CEState* state = obj->extra;
    ObjHitsPriorityState* hitState;
    if (obj->anim.alpha == 0)
        return;
    if (state->unlockCountdown <= 0)
    {
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        if (state->opened == 1)
        {
            state->openProgress = state->openVelocity * timeDelta + state->openProgress;
            if (state->openProgress > 82.0f)
            {
                state->openProgress = 82.0f;
                state->openVelocity = -0.1f;
            }
            else if (state->openProgress < -5.0f)
            {
                state->openProgress = -5.0f;
                state->openVelocity = 0.1f;
            }
        }
    }
    if (obj->anim.seqId == DLL1CE_SEQID_DIM_HUT_DOOR)
        return;
    {
        int offset;
        int i;
        ObjProximityList* proximityList;
        int count;
        int found = 0;
        offset = 0;
        proximityList = obj->anim.proximityList;
        count = proximityList->count;
        for (i = 0; i < count; i++)
        {
            GameObject* other =
                *(GameObject**)((u8*)proximityList + offset + offsetof(ObjProximityList, objects));
            if (other->anim.seqId == DLL1CE_KEY_SEQID_A ||
                other->anim.seqId == DLL1CE_KEY_SEQID_B)
            {
                found = 1;
                break;
            }
            offset += sizeof(proximityList->objects[0]);
        }
        if (!found)
            return;
    }
    {
        if ((state->unlockCountdown -= 1) > 0)
            return;
    }
    mainSetBits(placement->openedGameBit, 1);
    state->opened = 1;
    if ((u32)(s16)placement->contentsSpawnBitValue != mainGetBit(DLL1CE_CONTENTS_GATE_GAMEBIT))
        return;
    if (Obj_IsLoadingLocked() == 0)
        return;
    {
        CollectibleSetup* contentsSetup =
            (CollectibleSetup*)Obj_AllocObjectSetup(sizeof(CollectibleSetup), DLL1CE_CONTENTS_OBJECT_ID);
        contentsSetup->base.posX = placement->base.posX;
        contentsSetup->base.posY = 8.0f + placement->base.posY;
        contentsSetup->base.posZ = placement->base.posZ;
        contentsSetup->base.color[0] = placement->base.color[0];
        contentsSetup->base.color[1] = placement->base.color[1];
        contentsSetup->base.color[2] = placement->base.color[2];
        contentsSetup->base.color[3] = placement->base.color[3];
        contentsSetup->hideGameBit = 0x17f;
        contentsSetup->visibilityGameBit = -1;
        contentsSetup->counterGameBit = -1;
        contentsSetup->unkD = 5;
        contentsSetup->rotXByte = (u8)((s16)obj->anim.rotX >> 8);
        Obj_SetupObject(&contentsSetup->base, 5, obj->anim.mapEventSlot, -1, 0);
    }
}

void dll_1CE_init(GameObject* obj, Dll1CEPlacement* placement)
{
    Dll1CEState* state;
    ObjHitsPriorityState* hitState;
    obj->anim.rotX = (s16)(((s16)placement->rotX) << 8);
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    state = obj->extra;
    state->unlockCountdown = 1;
    if (mainGetBit(placement->openedGameBit) != 0)
    {
        state->unlockCountdown = 0;
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        obj->anim.alpha = 0;
    }
    state->openVelocity = -0.1f;
}

void dll_1CE_release(void)
{
}

void dll_1CE_initialise(void)
{
}

FbWGPipe GXWGFifo : (0xCC008000);

ObjectDescriptor dll_1CE = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_1CE_initialise,
    (ObjectDescriptorCallback)dll_1CE_release,
    0,
    (ObjectDescriptorCallback)dll_1CE_init,
    (ObjectDescriptorCallback)dll_1CE_update,
    (ObjectDescriptorCallback)dll_1CE_hitDetect,
    (ObjectDescriptorCallback)dll_1CE_render,
    (ObjectDescriptorCallback)dll_1CE_free,
    (ObjectDescriptorCallback)dll_1CE_getObjectTypeId,
    dll_1CE_getExtraSize,
};

/* descriptor/ptr table auto 0x80325600-0x80325670 */
ObjectDescriptor gDIMMagicBridgeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dimmagicbridge_initialise,
    (ObjectDescriptorCallback)dimmagicbridge_release,
    0,
    (ObjectDescriptorCallback)dimmagicbridge_init,
    (ObjectDescriptorCallback)dimmagicbridge_update,
    (ObjectDescriptorCallback)dimmagicbridge_hitDetect,
    (ObjectDescriptorCallback)dimmagicbridge_render,
    (ObjectDescriptorCallback)dimmagicbridge_free,
    (ObjectDescriptorCallback)dimmagicbridge_getObjectTypeId,
    dimmagicbridge_getExtraSize,
};
ObjectDescriptor gDIM_LevelControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dim_levelcontrol_init,
    (ObjectDescriptorCallback)dim_levelcontrol_update,
    0,
    (ObjectDescriptorCallback)dim_levelcontrol_render,
    (ObjectDescriptorCallback)dim_levelcontrol_free,
    0,
    dim_levelcontrol_getExtraSize,
};
