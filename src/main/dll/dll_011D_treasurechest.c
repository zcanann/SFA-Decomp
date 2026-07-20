/* DLL 0x011D - treasurechest (treasure chest interactive object). TU: 0x8018A8BC-0x8018ADB4. */
#include "main/dll/dll_011D_treasurechest.h"
#include "main/shader_api.h"
#include "main/dll/player_staff_api.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/resource.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/dll/dll_005A_staffcollisionfunc03.h"

STATIC_ASSERT(sizeof(TreasureChestSetup) == 0x24);
STATIC_ASSERT(offsetof(TreasureChestSetup, type) == 0x18);
STATIC_ASSERT(offsetof(TreasureChestSetup, hitboxKind) == 0x19);
STATIC_ASSERT(offsetof(TreasureChestSetup, triggerObjectId) == 0x1a);
STATIC_ASSERT(offsetof(TreasureChestSetup, dialogueId) == 0x1c);
STATIC_ASSERT(offsetof(TreasureChestSetup, openGameBit) == 0x1e);

#define TREASURECHEST_TARGET_OBJGROUP 4

/* anim-sequence event opcodes consumed by TreasureChest_SeqFn */
#define TREASURECHEST_SEQEV_DIALOGUE     1 /* show setup dialogue */
#define TREASURECHEST_SEQEV_HITFX_SET     2 /* enable hit effects */
#define TREASURECHEST_SEQEV_HITFX_CLEAR   3 /* disable hit effects */
#define TREASURECHEST_SEQEV_OPENED       4 /* hide + disable the chest */

int gTreasureChestHitEffectCooldown;
const StaffCollisionColorArgs gTreasureChestHitEffectColors = {8, 0xFF, 0xFF, 0x78};
StaffCollisionInterface** gTreasureChestStaffCollisionInterface;

int TreasureChest_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    TreasureChestSetup* setup;
    TreasureChestState* state;
    u8 eventId;

    setup = (TreasureChestSetup*)obj->anim.placementData;
    state = obj->extra;
    i = 0;
    while (i < animUpdate->eventCount)
    {
        eventId = animUpdate->eventIds[i];
        switch (eventId)
        {
        case TREASURECHEST_SEQEV_DIALOGUE:
            if (setup->dialogueId != 0)
            {
                (*gGameUIInterface)->showNpcDialogue(setup->dialogueId, 0xc8, 0x8c, 0);
            }
            break;
        case TREASURECHEST_SEQEV_HITFX_SET:
            state->hitEffectPending = 1;
            break;
        case TREASURECHEST_SEQEV_HITFX_CLEAR:
            state->hitEffectPending = 0;
            break;
        case TREASURECHEST_SEQEV_OPENED:
            obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject(obj);
            break;
        }
        i++;
    }
    return 0;
}

int TreasureChest_getExtraSize(void)
{
    return sizeof(TreasureChestState);
}

int TreasureChest_getObjectTypeId(void)
{
    return 0;
}

void TreasureChest_free(void)
{
    Resource_Release(gTreasureChestStaffCollisionInterface);
}

void TreasureChest_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void TreasureChest_hitDetect(GameObject* obj)
{
    TreasureChestState* state;
    TreasureChestSetup* setup;

    setup = (TreasureChestSetup*)obj->anim.placementData;
    state = obj->extra;
    if (state->hitEffectPending != 0)
    {
        objfx_spawnHitEffectBurst(obj, 0.6f, 2, (u8)(setup->hitboxKind + 6), 4, NULL);
    }
}

void TreasureChest_update(GameObject* obj)
{

    TreasureChestState* state;
    TreasureChestSetup* setup;
    u32 nearestObject;
    int hitResult;
    PartFxSpawnParams spawnParams;
    StaffCollisionColorArgs hitEffectColors;
    float nearestDist;
    u32 hitVolume;
    int hitPriority;
    int hitObject;

    state = obj->extra;
    setup = (TreasureChestSetup*)obj->anim.placementData;
    nearestDist = 20.0f;
    if (state->trigger != 0 && state->open != 0)
    {
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
        ObjAnim_SetCurrentMove((int)obj, 0, 0.99f, 0);
    }
    if (state->open == 0)
    {
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
        {
            obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
            playerPullOutStaff((GameObject*)(Obj_GetPlayerObject()), 1);
            nearestObject = ObjGroup_FindNearestObject(TREASURECHEST_TARGET_OBJGROUP, obj, &nearestDist);
            if (nearestObject != 0)
            {
                (*gObjectTriggerInterface)->setObjects((int)((GameObject*)nearestObject)->anim.seqId, 0, 0);
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, 0xffffffff);
            }
            else
            {
                (*gObjectTriggerInterface)->setObjects(setup->triggerObjectId, 0, 0);
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, 0xffffffff);
            }
            mainSetBits(setup->openGameBit, 1);
            state->open = 1;
            ObjHits_DisableObject(obj);
        }
        state->trigger = 0;
        hitEffectColors = gTreasureChestHitEffectColors;
        hitPriority = 0xffffffff;
        hitResult = ObjHits_GetPriorityHitWithPosition((GameObject*)obj, &hitObject, &hitPriority, &hitVolume,
                                                       &spawnParams.posX, &spawnParams.posY, &spawnParams.posZ);
        if ((hitResult != 0) && (hitResult != 0xe))
        {
            spawnParams.posX = spawnParams.posX + playerMapOffsetX;
            spawnParams.posZ = spawnParams.posZ + playerMapOffsetZ;
            spawnParams.scale = 1.0f;
            spawnParams.rotZ = 0;
            spawnParams.rotY = 0;
            spawnParams.rotX = 0;
            if (gTreasureChestHitEffectCooldown == 0)
            {
                (*gTreasureChestStaffCollisionInterface)->spawn(NULL, 1, &spawnParams, 0x401, -1,
                                                                &hitEffectColors);
                gTreasureChestHitEffectCooldown = 0x3c;
            }
        }
        if (gTreasureChestHitEffectCooldown != 0)
        {
            gTreasureChestHitEffectCooldown = gTreasureChestHitEffectCooldown + -1;
        }
    }
    return;
}

void TreasureChest_init(GameObject* obj)
{
    register TreasureChestState* state = obj->extra;
    register TreasureChestSetup* setup = (TreasureChestSetup*)obj->anim.placementData;

    obj->animEventCallback = TreasureChest_SeqFn;
    obj->anim.rotX = (s16)((s32)setup->type << 8);

    if (setup->openGameBit != -1)
    {
        state->open = mainGetBit(setup->openGameBit);
    }
    else
    {
        state->open = 0;
    }
    if (state->open != 0)
    {
        obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
        ObjHits_DisableObject(obj);
    }
    gTreasureChestStaffCollisionInterface = Resource_Acquire(90, 1);
    state->trigger = 1;
}

void TreasureChest_release(void)
{
}

void TreasureChest_initialise(void)
{
}

ObjectDescriptor gTreasureChestObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)TreasureChest_initialise,
    (ObjectDescriptorCallback)TreasureChest_release,
    0,
    (ObjectDescriptorCallback)TreasureChest_init,
    (ObjectDescriptorCallback)TreasureChest_update,
    (ObjectDescriptorCallback)TreasureChest_hitDetect,
    (ObjectDescriptorCallback)TreasureChest_render,
    (ObjectDescriptorCallback)TreasureChest_free,
    (ObjectDescriptorCallback)TreasureChest_getObjectTypeId,
    TreasureChest_getExtraSize,
};
