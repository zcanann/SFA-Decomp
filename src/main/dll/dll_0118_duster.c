/*
 * duster (DLL 0x118) - a drifting collectible "dust" object the player
 * gathers and deposits, plus the shared ObjectDescriptor table for the
 * sibling DLL objects compiled into this unit (magicplant, trickywarp,
 * trickyguard, staypoint, curvefish).
 *
 * Each duster activates from its placement game bit; once active it settles
 * to the nearest floor hit, drifts (driftDir / random heading), advances its
 * canned move, and reacts to priority hits. When the player is close and
 * facing it (fn_8029622C), it is either picked up (ObjMsg DUSTER_MSG_REQUEST_
 * PICKUP, gated by game bit 0xcc0) or deposited directly if the current
 * character's duster collection isn't full. Depositing (DUSTER_MSG_DEPOSIT)
 * sets the object's completeGameBit, bumps the collected count, spawns the
 * place fx and marks the duster complete. Game bits >= 0x6fe are treated as
 * already-complete markers (completeGameBit == activeGameBit); below that the
 * complete bit lives at activeGameBit + 0x64.
 */
#include "main/obj_placement.h"
#include "main/dll/dusterstate_types.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/dll_00FE_magicplant.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/gamebits.h"
#include "main/objhits.h"
extern int randomGetRange(int lo, int hi);
extern void* Obj_GetPlayerObject(void);
extern int ObjMsg_Pop();
extern u32 ObjMsg_SendToObject();
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern f32 Vec_xzDistance(f32* a, f32* b);
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z,
                                void* outHits, int e, int f);
extern int fn_8029622C(int obj);
extern void Sfx_PlayFromObject(int obj, u16 sfxId);
extern f32 lbl_803E38B0;
extern f32 gDusterObjHitDetectRadius;
extern f32 gDusterObjGravityVelYThreshold;
extern f32 gDusterObjGravityAccel;
extern f32 gDusterObjFloorSearchMaxDelta;
extern f32 lbl_803E38C4;
extern f32 gDusterObjLaunchVelocityX;
extern f32 gDusterObjDriftSpinRate;
extern f32 gDusterObjPickupRangeY;
extern f32 gDusterObjPickupRangeXZ;
extern f32 gDusterObjMoveStepScale;
extern f32 timeDelta;
extern void vecRotateZXY(void* angles, void* outVec);
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern int objBboxFn_800640cc(f32* from, f32* to, f32 radius, int mode, void* hit,
                              void* obj, int flags, int mask, int arg9, int arg10);

STATIC_ASSERT(sizeof(DusterStateFlags) == 1);
STATIC_ASSERT(sizeof(DusterState) == 0x20);
STATIC_ASSERT(offsetof(DusterState, moveStepScale) == 0x00);
STATIC_ASSERT(offsetof(DusterState, floorY) == 0x04);
STATIC_ASSERT(offsetof(DusterState, settleTimer) == 0x08);
STATIC_ASSERT(offsetof(DusterState, hitReactTimer) == 0x0a);
STATIC_ASSERT(offsetof(DusterState, completeGameBit) == 0x0c);
STATIC_ASSERT(offsetof(DusterState, activeGameBit) == 0x0e);
STATIC_ASSERT(offsetof(DusterState, heldObjectId) == 0x10);
STATIC_ASSERT(offsetof(DusterState, driftDir) == 0x18);
STATIC_ASSERT(offsetof(DusterState, hitReactActive) == 0x19);
STATIC_ASSERT(offsetof(DusterState, priorityHit) == 0x1a);
STATIC_ASSERT(offsetof(DusterState, active) == 0x1b);
STATIC_ASSERT(offsetof(DusterState, complete) == 0x1c);
STATIC_ASSERT(offsetof(DusterState, useLaunchVelocity) == 0x1d);
STATIC_ASSERT(offsetof(DusterState, flags) == 0x1e);

/* ObjMsg ids shared with the other collectible objects (magicgem/fuelcell) */
#define DUSTER_MSG_REQUEST_PICKUP 0x7000a
#define DUSTER_MSG_DEPOSIT 0x7000b

/* game bit guarding a single carried duster at a time */
#define GAMEBIT_DUSTER_CARRIED 0xcc0

int duster_getExtraSize(void) { return 0x20; }

int duster_SeqFn(u8* obj)
{
    DusterState* state = ((GameObject*)obj)->extra;
    state->flags.floorCached = 0;
    return 0;
}

void duster_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DusterState* state = ((GameObject*)obj)->extra;
    if (visible == 0 || state->active == 0 || state->complete != 0)
    {
        return;
    }
    ((void(*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E38B0);
}

void duster_hitDetect(int obj)
{
    DusterState* state;
    u8 hit[0x54];
    int hitResult;
    state = ((GameObject*)obj)->extra;
    hitResult = objBboxFn_800640cc((f32*)(obj + 128), (f32*)(obj + 12),
                           gDusterObjHitDetectRadius, 2, hit, (void*)obj, 8, -1, 255, 0);
    if (hitResult != 0)
    {
        state->priorityHit = 1;
    }
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
}

typedef struct DusterSetup
{
    u8 pad00[0x24];
    s16 activeGameBit;
} DusterSetup;

typedef struct DusterMapEventState
{
    u8 pad00[9];
    u8 collectedCount;
    u8 maxCollectedCount;
} DusterMapEventState;

typedef struct DusterLaunchRotation
{
    s16 yaw;
    s16 pitch;
    s16 roll;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} DusterLaunchRotation;

void duster_init(int obj, u8* params)
{
    DusterState* state;
    DusterSetup* setup;
    void* hitData;

    setup = (DusterSetup*)params;
    state = ((GameObject*)obj)->extra;
    state->settleTimer = randomGetRange(0, 0x32);
    state->moveStepScale = gDusterObjMoveStepScale;
    state->activeGameBit = setup->activeGameBit;
    if (state->activeGameBit >= 0x6fe)
    {
        state->active = 1;
        state->completeGameBit = state->activeGameBit;
    }
    else
    {
        state->active = GameBit_Get(state->activeGameBit);
        state->completeGameBit = state->activeGameBit + 0x64;
    }
    state->complete = GameBit_Get(state->completeGameBit);
    hitData = ((GameObject*)obj)->anim.hitReactState;
    if (hitData != NULL && state->active == 0)
    {
        *(s16*)((int)hitData + 0x60) = (s16)(*(s16*)((int)hitData + 0x60) | 1);
    }
    if ((state->complete != 0 || state->active == 0) && ((GameObject*)obj)->anim.hitReactState != NULL)
    {
        ObjHits_DisableObject(obj);
    }
    ObjMsg_AllocQueue((void*)obj, 1);
    ((GameObject*)obj)->animEventCallback = duster_SeqFn;
}

void duster_update(int obj)
{
    DusterState* state;
    DusterSetup* setup;
    int player;
    GameObject* playerObj;
    void* floorHits;
    int msg;
    int next;
    int floorHitCount;
    int i;
    int bestFloorIndex;
    f32 bestFloorDelta;
    f32 floorDelta;
    DusterLaunchRotation launch;
    DusterMapEventState* mapState;

    state = ((GameObject*)obj)->extra;
    setup = *(DusterSetup**)&((GameObject*)obj)->anim.placementData;
    player = (int)Obj_GetPlayerObject();
    playerObj = (GameObject*)player;

    while (ObjMsg_Pop(obj, &msg, 0, 0) != 0)
    {
        switch (msg)
        {
        case DUSTER_MSG_DEPOSIT:
            Sfx_PlayFromObject(obj, SFXen_generic_placeobj);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
            GameBit_Set(state->completeGameBit, 1);
            mapState = (DusterMapEventState*)(*gMapEventInterface)->getCurCharacterState();
            mapState->collectedCount =
                (mapState->maxCollectedCount < (next = mapState->collectedCount + 1))
                    ? mapState->maxCollectedCount
                    : next;
            state->complete = 1;
            break;
        }
    }

    if (state->active == 0 || state->complete == 1)
    {
        if (state->active == 0)
        {
            state->active = GameBit_Get(state->activeGameBit);
            state->settleTimer = 0;
        }
        return;
    }

    if (((GameObject*)obj)->anim.velocityY > gDusterObjGravityVelYThreshold)
    {
        ((GameObject*)obj)->anim.velocityY = gDusterObjGravityAccel * timeDelta + ((GameObject*)obj)->anim.velocityY;
    }

    state->priorityHit = 0;
    if (state->flags.floorCached == 0)
    {
        floorHitCount = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX,
                                             ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                                             &floorHits, 0, 0);
        bestFloorDelta = gDusterObjFloorSearchMaxDelta;
        bestFloorIndex = -1;
        for (i = 0; i < floorHitCount; i++)
        {
            floorDelta = **(f32**)((int)floorHits + i * 4) - ((GameObject*)obj)->anim.localPosY;
            if (floorDelta < *(f32*)&lbl_803E38C4)
            {
                floorDelta = -floorDelta;
            }
            if (floorDelta < bestFloorDelta)
            {
                bestFloorIndex = i;
                bestFloorDelta = floorDelta;
            }
        }
        if (bestFloorIndex != -1)
        {
            state->flags.floorCached = 1;
            state->floorY = **(f32**)((int)floorHits + bestFloorIndex * 4);
            ((GameObject*)obj)->anim.velocityY = lbl_803E38C4;
        }
        if (state->flags.floorCached == 0)
        {
            state->floorY = ((ObjPlacement*)setup)->posY;
            state->flags.floorCached = 1;
        }
    }

    if (((GameObject*)obj)->anim.localPosY < state->floorY)
    {
        ((GameObject*)obj)->anim.localPosY = state->floorY;
        ((GameObject*)obj)->anim.velocityY = lbl_803E38C4;
    }

    if (state->settleTimer == 0 && state->hitReactTimer == 0)
    {
        if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, state->moveStepScale, timeDelta, NULL) != 0
            ||
            state->priorityHit != 0)
        {
            Sfx_PlayFromObject(obj, SFXen_riverloop11);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x51f, NULL, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x51f, NULL, 2, -1, NULL);
            state->driftDir = randomGetRange(0, 4);
            if (state->useLaunchVelocity != 0)
            {
                ((GameObject*)obj)->anim.velocityX = gDusterObjLaunchVelocityX;
                launch.z = launch.y = launch.x = ((GameObject*)obj)->anim.velocityZ = lbl_803E38C4;
                launch.scale = lbl_803E38B0;
                launch.roll = 0;
                launch.pitch = 0;
                launch.yaw = ((GameObject*)obj)->anim.rotX;
                vecRotateZXY(&launch, (void*)(obj + 0x24));
            }
            else
            {
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityX = lbl_803E38C4;
            }
            if (state->hitReactActive != 0)
            {
                state->hitReactTimer = 0xfa;
            }
        }
        else
        {
            ((GameObject*)obj)->anim.localPosX += ((GameObject*)obj)->anim.velocityX * timeDelta;
            ((GameObject*)obj)->anim.localPosZ += ((GameObject*)obj)->anim.velocityZ * timeDelta;
        }

        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe)
        {
            state->hitReactActive = 1;
            Sfx_PlayFromObject(obj, SFXen_trpcls_c);
        }
    }
    else
    {
        if (state->settleTimer != 0)
        {
            state->settleTimer -= (s16)timeDelta;
            if (state->settleTimer <= 0)
            {
                state->settleTimer = 0;
            }
        }
        if (state->hitReactTimer != 0)
        {
            state->hitReactTimer -= (s16)timeDelta;
            if (state->hitReactTimer <= 0)
            {
                state->hitReactTimer = 0;
                state->hitReactActive = 0;
            }
        }
    }

    if (state->driftDir == 4)
    {
        if (state->priorityHit != 0)
        {
            ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX - 0x7fff);
            state->driftDir = 0;
        }
        ((GameObject*)obj)->anim.rotX = (s16)((f32) * (s16*)obj + gDusterObjDriftSpinRate * timeDelta);
    }

    floorDelta = playerObj->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    if (floorDelta < lbl_803E38C4)
    {
        floorDelta = -floorDelta;
    }
    if (floorDelta < gDusterObjPickupRangeY &&
        Vec_xzDistance(&playerObj->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX) < gDusterObjPickupRangeXZ &&
        fn_8029622C(player) != 0)
    {
        if (GameBit_Get(GAMEBIT_DUSTER_CARRIED) == 0)
        {
            state->heldObjectId = -1;
            ObjHits_DisableObject(obj);
            ObjMsg_SendToObject(player, DUSTER_MSG_REQUEST_PICKUP, obj, &state->heldObjectId);
            GameBit_Set(GAMEBIT_DUSTER_CARRIED, 1);
        }
        else
        {
            mapState = (DusterMapEventState*)(*gMapEventInterface)->getCurCharacterState();
            if (mapState->collectedCount < mapState->maxCollectedCount)
            {
                Sfx_PlayFromObject(obj, SFXen_generic_placeobj);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
                GameBit_Set(state->completeGameBit, 1);
                mapState = (DusterMapEventState*)(*gMapEventInterface)->getCurCharacterState();
                mapState->collectedCount =
                    (mapState->maxCollectedCount < (next = mapState->collectedCount + 1))
                        ? mapState->maxCollectedCount
                        : next;
                state->complete = 1;
                ((GameObject*)obj)->anim.alpha = 1;
            }
        }
        if (((GameObject*)obj)->anim.hitReactState != NULL)
        {
            ObjHits_DisableObject(obj);
        }
    }

    ((GameObject*)obj)->anim.localPosY += ((GameObject*)obj)->anim.velocityY;
}

void trickyguard_update(int* obj);

ObjectDescriptor gMagicPlantObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)MagicPlant_init,
    (ObjectDescriptorCallback)MagicPlant_update,
    0,
    (ObjectDescriptorCallback)MagicPlant_render,
    (ObjectDescriptorCallback)MagicPlant_free,
    (ObjectDescriptorCallback)MagicPlant_getObjectTypeId,
    MagicPlant_getExtraSize,
};

ObjectDescriptor gTrickyWarpObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_init,
    (ObjectDescriptorCallback)trickywarp_update,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_free,
    0,
    trickywarp_getExtraSize,
};

ObjectDescriptor gTrickyGuardObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickyguard_init,
    (ObjectDescriptorCallback)trickyguard_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gStayPointObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)StayPoint_init,
    (ObjectDescriptorCallback)StayPoint_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gDusterObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)duster_init,
    (ObjectDescriptorCallback)duster_update,
    (ObjectDescriptorCallback)duster_hitDetect,
    (ObjectDescriptorCallback)duster_render,
    0,
    0,
    duster_getExtraSize,
};

ObjectDescriptor gCurveFishObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)curvefish_init,
    (ObjectDescriptorCallback)curvefish_update,
    0,
    0,
    0,
    0,
    curvefish_getExtraSize,
};
