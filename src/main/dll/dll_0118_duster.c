/*
 * duster (DLL 0x118) - a drifting collectible "dust" object the player
 * gathers and deposits.
 *
 * The ObjectDescriptors for the 0x00FE..0x0103 bundle (including
 * gDusterObjDescriptor) live in dll_0100_trickywarp.c, whose .data split
 * range (0x80321568..0x803216B8) owns them in retail.
 *
 * Each duster activates from its placement game bit; once active it settles
 * to the nearest floor hit, drifts (driftDir / random heading), advances its
 * canned move, and reacts to priority hits. When the player is close and
 * facing it (Obj_IsParentSlackClear), it is either picked up (ObjMsg DUSTER_MSG_REQUEST_
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
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_00FE_magicplant.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/gamebits.h"
#include "main/objhits.h"

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
#define DUSTER_MSG_DEPOSIT        0x7000b

/* game bit guarding a single carried duster at a time */
#define GAMEBIT_DUSTER_CARRIED 0xcc0

/* partfx spawned 3x on deposit/place completion (with place-object sfx) */
#define DUSTER_PARTFX_DEPOSIT 0x51a
/* partfx spawned 2x on bounce/collision during a move step (with river-loop sfx) */
#define DUSTER_PARTFX_BOUNCE 0x51f

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

extern int randomGetRange(int lo, int hi);
extern void* Obj_GetPlayerObject(void);
extern int ObjMsg_Pop();
extern u32 ObjMsg_SendToObject();
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern f32 Vec_xzDistance(f32* a, f32* b);
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, void* outHits, int e, int f);
extern int Obj_IsParentSlackClear(int obj);
extern void Sfx_PlayFromObject(int obj, u16 sfxId);
extern void vecRotateZXY(void* angles, void* outVec);
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern int objBboxFn_800640cc(f32* from, f32* to, f32 radius, int mode, void* hit, void* obj, int flags, int mask,
                              int arg9, int arg10);

int duster_SeqFn(u8* obj)
{
    DusterState* state = ((GameObject*)obj)->extra;
    state->flags.floorCached = 0;
    return 0;
}

int duster_getExtraSize(void)
{
    return 0x20;
}

void duster_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DusterState* state = ((GameObject*)obj)->extra;
    if (visible == 0 || state->active == 0 || state->complete != 0)
    {
        return;
    }
    ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E38B0);
}

void duster_hitDetect(GameObject* obj)
{
    DusterState* state;
    u8 hit[0x54];
    int hitResult;
    state = obj->extra;
    hitResult = objBboxFn_800640cc(&obj->anim.previousLocalPosX, &obj->anim.localPosX, gDusterObjHitDetectRadius, 2,
                                   hit, (void*)obj, 8, -1, 255, 0);
    if (hitResult != 0)
    {
        state->priorityHit = 1;
    }
    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosZ = obj->anim.localPosZ;
}

void duster_update(GameObject* obj)
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

    state = obj->extra;
    setup = *(DusterSetup**)&obj->anim.placementData;
    player = (int)Obj_GetPlayerObject();
    playerObj = (GameObject*)player;

    while (ObjMsg_Pop(obj, &msg, 0, 0) != 0)
    {
        switch (msg)
        {
        case DUSTER_MSG_DEPOSIT:
            ((void (*)(void*, u16))Sfx_PlayFromObject)(obj, SFXTRIG_sc_cam90_c);
            (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTFX_DEPOSIT, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTFX_DEPOSIT, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTFX_DEPOSIT, NULL, 1, -1, NULL);
            mainSetBits(state->completeGameBit, 1);
            mapState = (DusterMapEventState*)(*gMapEventInterface)->getCurCharacterState();
            mapState->collectedCount = (mapState->maxCollectedCount < (next = mapState->collectedCount + 1))
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
            state->active = mainGetBit(state->activeGameBit);
            state->settleTimer = 0;
        }
        return;
    }

    if (obj->anim.velocityY > gDusterObjGravityVelYThreshold)
    {
        obj->anim.velocityY = gDusterObjGravityAccel * timeDelta + obj->anim.velocityY;
    }

    state->priorityHit = 0;
    if (state->flags.floorCached == 0)
    {
        floorHitCount = hitDetectFn_80065e50((int)obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                             &floorHits, 0, 0);
        bestFloorDelta = gDusterObjFloorSearchMaxDelta;
        bestFloorIndex = -1;
        for (i = 0; i < floorHitCount; i++)
        {
            floorDelta = **(f32**)((int)floorHits + i * 4) - obj->anim.localPosY;
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
            obj->anim.velocityY = lbl_803E38C4;
        }
        if (state->flags.floorCached == 0)
        {
            state->floorY = ((ObjPlacement*)setup)->posY;
            state->flags.floorCached = 1;
        }
    }

    if (obj->anim.localPosY < state->floorY)
    {
        obj->anim.localPosY = state->floorY;
        obj->anim.velocityY = lbl_803E38C4;
    }

    if (state->settleTimer == 0 && state->hitReactTimer == 0)
    {
        if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, state->moveStepScale, timeDelta,
                                                                        NULL) != 0 ||
            state->priorityHit != 0)
        {
            ((void (*)(void*, u16))Sfx_PlayFromObject)(obj, SFXTRIG_en_lflsh3_c);
            (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTFX_BOUNCE, NULL, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTFX_BOUNCE, NULL, 2, -1, NULL);
            state->driftDir = randomGetRange(0, 4);
            if (state->useLaunchVelocity != 0)
            {
                obj->anim.velocityX = gDusterObjLaunchVelocityX;
                launch.z = launch.y = launch.x = obj->anim.velocityZ = lbl_803E38C4;
                launch.scale = lbl_803E38B0;
                launch.roll = 0;
                launch.pitch = 0;
                launch.yaw = obj->anim.rotX;
                vecRotateZXY(&launch, &obj->anim.velocityX);
            }
            else
            {
                obj->anim.velocityZ = obj->anim.velocityX = lbl_803E38C4;
            }
            if (state->hitReactActive != 0)
            {
                state->hitReactTimer = 0xfa;
            }
        }
        else
        {
            obj->anim.localPosX += obj->anim.velocityX * timeDelta;
            obj->anim.localPosZ += obj->anim.velocityZ * timeDelta;
        }

        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe)
        {
            state->hitReactActive = 1;
            ((void (*)(void*, u16))Sfx_PlayFromObject)(obj, SFXTRIG_dn_boar1_c_4d);
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
            obj->anim.rotX = (s16)(obj->anim.rotX - 0x7fff);
            state->driftDir = 0;
        }
        obj->anim.rotX = (s16)((f32) * (s16*)obj + gDusterObjDriftSpinRate * timeDelta);
    }

    floorDelta = playerObj->anim.localPosY - obj->anim.localPosY;
    if (floorDelta < lbl_803E38C4)
    {
        floorDelta = -floorDelta;
    }
    if (floorDelta < gDusterObjPickupRangeY &&
        Vec_xzDistance(&playerObj->anim.worldPosX, &obj->anim.worldPosX) < gDusterObjPickupRangeXZ &&
        Obj_IsParentSlackClear(player) != 0)
    {
        if (mainGetBit(GAMEBIT_DUSTER_CARRIED) == 0)
        {
            state->heldObjectId = -1;
            ObjHits_DisableObject((int)obj);
            ObjMsg_SendToObject(player, DUSTER_MSG_REQUEST_PICKUP, obj, &state->heldObjectId);
            mainSetBits(GAMEBIT_DUSTER_CARRIED, 1);
        }
        else
        {
            mapState = (DusterMapEventState*)(*gMapEventInterface)->getCurCharacterState();
            if (mapState->collectedCount < mapState->maxCollectedCount)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_sc_cam90_c);
                (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTFX_DEPOSIT, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTFX_DEPOSIT, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, DUSTER_PARTFX_DEPOSIT, NULL, 1, -1, NULL);
                mainSetBits(state->completeGameBit, 1);
                mapState = (DusterMapEventState*)(*gMapEventInterface)->getCurCharacterState();
                mapState->collectedCount = (mapState->maxCollectedCount < (next = mapState->collectedCount + 1))
                                               ? mapState->maxCollectedCount
                                               : next;
                state->complete = 1;
                obj->anim.alpha = 1;
            }
        }
        if (obj->anim.hitReactState != NULL)
        {
            ObjHits_DisableObject((int)obj);
        }
    }

    obj->anim.localPosY += obj->anim.velocityY;
}

void duster_init(GameObject* obj, u8* params)
{
    DusterState* state;
    DusterSetup* setup;
    void* hitData;

    setup = (DusterSetup*)params;
    state = (obj)->extra;
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
        state->active = mainGetBit(state->activeGameBit);
        state->completeGameBit = state->activeGameBit + 0x64;
    }
    state->complete = mainGetBit(state->completeGameBit);
    hitData = (obj)->anim.hitReactState;
    if (hitData != NULL && state->active == 0)
    {
        *(s16*)((int)hitData + 0x60) = (s16)(*(s16*)((int)hitData + 0x60) | 1);
    }
    if ((state->complete != 0 || state->active == 0) && (obj)->anim.hitReactState != NULL)
    {
        ObjHits_DisableObject((int)obj);
    }
    ObjMsg_AllocQueue((void*)obj, 1);
    (obj)->animEventCallback = duster_SeqFn;
}
