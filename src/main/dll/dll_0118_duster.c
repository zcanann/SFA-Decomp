#include "main/obj_placement.h"
#include "main/dll/dusterstate_types.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/cfprisonuncle.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"

extern u32 randomGetRange(int min, int max);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void* Obj_GetPlayerObject(void);
extern undefined8 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern int hitDetectFn_80065e50(int obj, void* outHits, int param_3, int param_4,
                                f32 x, f32 y, f32 z);
extern int fn_8029622C(int obj);
extern void Sfx_PlayFromObject(int obj, u16 sfxId);

extern f32 lbl_803E38B0;
extern f32 lbl_803E38B8;
extern f32 lbl_803E38BC;
extern f32 lbl_803E38C0;
extern f32 lbl_803E38C4;
extern f32 lbl_803E38C8;
extern f32 lbl_803E38CC;
extern f32 lbl_803E38D0;
extern f32 lbl_803E38D4;
extern f32 lbl_803E38E0;
extern f32 timeDelta;
extern void vecRotateZXY(void* angles, void* outVec);

void MagicPlant_update(int obj);

int MagicPlant_getExtraSize(void);
int trickywarp_getExtraSize(void);
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
extern void objRenderFn_8003b8f4(int obj, float arg);
extern int objBboxFn_800640cc(f32* from, f32* to, f32 radius, int mode, void* hit,
                              void* obj, int flags, int mask, int arg9, int arg10);
extern f32 lbl_803E38B4;

int duster_getExtraSize(void) { return 0x20; }
int curvefish_getExtraSize(void);

int duster_SeqFn(u8* obj)
{
    DusterState* state = ((GameObject*)obj)->extra;
    state->flags.floorCached = 0;
    return 0;
}

u32 MagicPlant_getObjectTypeId(MagicPlantObject* obj);

void StayPoint_init(u16* obj);

void MagicPlant_free(int obj, int param_2);

void MagicPlant_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

void trickywarp_free(int obj);

void trickywarp_init(s16* obj, u8* param_2);

void trickyguard_init(s16* obj, u8* param_2);

void duster_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DusterState* state = ((GameObject*)obj)->extra;
    if (visible == 0 || state->active == 0 || state->complete != 0)
    {
        return;
    }
    ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E38B0);
}

void duster_hitDetect(int param_1)
{
    int obj = param_1;
    DusterState* state;
    u8 hit[0x54];
    int r;
    state = ((GameObject*)obj)->extra;
    r = objBboxFn_800640cc((f32*)(obj + 128), (f32*)(obj + 12),
                           lbl_803E38B4, 2, hit, (void*)obj, 8, -1, 255, 0);
    if (r != 0)
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
    state->settleTimer = (s16)randomGetRange(0, 0x32);
    state->moveStepScale = lbl_803E38E0;
    state->activeGameBit = setup->activeGameBit;
    if (state->activeGameBit >= 0x6fe)
    {
        state->active = 1;
        state->completeGameBit = state->activeGameBit;
    }
    else
    {
        state->active = (u8)GameBit_Get(state->activeGameBit);
        state->completeGameBit = state->activeGameBit + 0x64;
    }
    state->complete = (u8)GameBit_Get(state->completeGameBit);
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
    ((GameObject*)obj)->animEventCallback = (void*)duster_SeqFn;
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
        if (msg == 0x7000b)
        {
            Sfx_PlayFromObject(obj, SFXen_generic_placeobj);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
            GameBit_Set(state->completeGameBit, 1);
            mapState = (DusterMapEventState*)(*gMapEventInterface)->getCurCharacterState();
            mapState->collectedCount =
                (mapState->maxCollectedCount >= (next = mapState->collectedCount + 1))
                    ? next
                    : mapState->maxCollectedCount;
            state->complete = 1;
        }
    }

    if (state->active == 0 || state->complete == 1)
    {
        if (state->active == 0)
        {
            state->active = (u8)GameBit_Get(state->activeGameBit);
            state->settleTimer = 0;
        }
        return;
    }

    if (((GameObject*)obj)->anim.velocityY > lbl_803E38B8)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E38BC * timeDelta + ((GameObject*)obj)->anim.velocityY;
    }

    state->priorityHit = 0;
    if (state->flags.floorCached == 0)
    {
        floorHitCount = hitDetectFn_80065e50(obj, &floorHits, 0, 0, ((GameObject*)obj)->anim.localPosX,
                                             ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ);
        bestFloorIndex = -1;
        bestFloorDelta = lbl_803E38C0;
        for (i = 0; i < floorHitCount; i++)
        {
            floorDelta = **(f32**)((int)floorHits + i * 4) - ((GameObject*)obj)->anim.localPosY;
            if (floorDelta < lbl_803E38C4)
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
            state->driftDir = (u8)randomGetRange(0, 4);
            if (state->useLaunchVelocity != 0)
            {
                ((GameObject*)obj)->anim.velocityX = lbl_803E38C8;
                launch.z = launch.y = launch.x = ((GameObject*)obj)->anim.velocityZ = lbl_803E38C4;
                launch.scale = lbl_803E38B0;
                launch.roll = 0;
                launch.pitch = 0;
                launch.yaw = *(s16*)obj;
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
            *(s16*)obj = (s16)(*(s16*)obj - 0x7fff);
            state->driftDir = 0;
        }
        *(s16*)obj = (s16)((f32) * (s16*)obj + lbl_803E38CC * timeDelta);
    }

    floorDelta = playerObj->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    if (floorDelta < lbl_803E38C4)
    {
        floorDelta = -floorDelta;
    }
    if (floorDelta < lbl_803E38D0 &&
        Vec_xzDistance(&playerObj->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX) < lbl_803E38D4 &&
        fn_8029622C(player) != 0)
    {
        if (GameBit_Get(0xcc0) == 0)
        {
            state->heldObjectId = -1;
            ObjHits_DisableObject(obj);
            ObjMsg_SendToObject(player, 0x7000a, obj, &state->heldObjectId);
            GameBit_Set(0xcc0, 1);
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
                    (mapState->maxCollectedCount >= (next = mapState->collectedCount + 1))
                        ? next
                        : mapState->maxCollectedCount;
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

void MagicPlant_init(int obj, MagicPlantSetup* setup);

void trickywarp_update(int param_1);

void curvefish_update(int obj);

void curvefish_init(int obj, u8* param_2);

void trickyguard_update(int* obj);

void StayPoint_update(int obj);

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
