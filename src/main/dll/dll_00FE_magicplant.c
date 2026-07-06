/*
 * magicplant (DLL 0x00FE) - the swaying magic-plant object plus the
 * ObjectDescriptors for the sibling objects whose code lives in this
 * DLL (TrickyWarp, TrickyGuard, StayPoint, Duster, CurveFish).
 *
 * A magic plant holds a coloured gem (spawned as a magicgem object, dll_00FF).
 * The placement's gemColor byte picks the gem: 0 green / 1 red / 2 yellow /
 * 3 blue (gMagicPlantGemDefIds; live-verified in Dolphin by forcing each
 * variant and watching the regrown gem's colour). It runs off a map-event
 * timer: while waiting for its event (MAGICPLANT_MODE_WAIT_FOR_EVENT) it drives
 * its open/close anim from the event's remaining time, then becomes interactive
 * (MAGICPLANT_MODE_ACTIVE, MagicPlant_updateActive) where it idles, randomly
 * retriggers its sway, plays its ambient buzz loop sfx by player distance, and
 * spawns its gem once loading is locked (MagicPlant_spawnChild). Shooting it
 * pushes it into MAGICPLANT_MODE_HIT_REACT (delegated to fn_8017F334 in sibling
 * dll_00FD), which releases the gem (which drops to the floor, collected on touch) with a
 * particle burst and red
 * colour-fade; the fade-out/fade-in modes then ramp model alpha and it re-arms
 * for the next event. Live-verified end-to-end in Dolphin: ACTIVE -> HIT_REACT
 * clears the child pointer (gem released) -> FADE_OUT.
 */
#include "main/dll/dusterstate_types.h"
#include "main/game_object.h"
#include "main/dll/dll_00FE_magicplant.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objfx.h"
#include "main/dll/dll_00FD.h"
#include "main/mm.h"
#include "main/audio/sfx_trigger_ids.h"

/* the two object groups this plant joins */
#define MAGICPLANT_OBJGROUP_A 0x34
#define MAGICPLANT_OBJGROUP_B 0x3e

#define MAGICPLANT_HIT_BURST_FX 0x34e   /* particle effect spawned when the plant is hit */
#define MAGICPLANT_HIT_BURST_COUNT 0x14 /* 20 hit-burst particles */
#define MAGICPLANT_IDLE_TIMER_MIN 300   /* frames between idle-sway retriggers (lo..hi) */
#define MAGICPLANT_IDLE_TIMER_MAX 600
extern int randomGetRange(int lo, int hi);

extern void* Obj_GetPlayerObject(void);
extern void Obj_StartModelFadeIn(int obj, int frames);
extern int Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);
extern int ObjHits_GetPriorityHitWithPosition();
extern u64 ObjGroup_RemoveObject();
extern u32 ObjGroup_AddObject();
extern void ObjLink_DetachChild(int obj, int child);
extern void ObjLink_AttachChild(int parent, int child, u16 linkMode);
extern void ObjPath_GetPointWorldPosition(int obj, int pointIndex, float* outX, float* outY, float* outZ, int useInputPosition);
extern f32 Vec_distance(f32* a, f32* b);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern void Sfx_StopObjectChannel(u32 obj, u32 channel);
extern void Obj_SetModelColorFadeRecursive(int obj, int frames, int red, int green, int blue, int startAtHalf);
extern void Obj_ResetModelColorState(int obj);
extern void Obj_FreeObject(int obj);
extern int objIsFrozen(int obj);
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void* gCameraInterface;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E3858;
extern f32 lbl_803E385C;
extern f32 gMagicPlantHitReactAnimStep;
extern f32 gMagicPlantHitLightScale;
extern f32 gMagicPlantIdleAnimStep;
extern f32 lbl_803E3890;
extern f32 gMagicPlantBuzzStartDist;
extern f32 gMagicPlantBuzzStopDist;
extern f32 timeDelta;
extern u8 framesThisStep;
extern s16 gMagicPlantGemDefIds[4];

typedef struct MagicPlantChildSetup
{
    u8 pad00[4];
    u8 mapByte4;
    u8 mapByte5;
    u8 mapByte6;
    u8 yawByte;
    f32 x;
    f32 y;
    f32 z;
    u8 pad14[6];
    u8 field1A; /* init 0x14 */
    u8 pad1B;
    s16 field1C; /* init -1 */
    u8 pad1E[6];
    s16 field24; /* init -1 */
    u8 pad26[6];
    s16 field2C; /* init -1 */
} MagicPlantChildSetup;

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

void MagicPlant_updateActive(int obj, MagicPlantSetup* setupParam, MagicPlantState* stateParam)
{
    int hitObj;
    int hitB;
    int hitA;
    f32 hitPos[3];
    u8 lightPos[0x0c];
    int hitKind;
    int i;
    int player;
    GameObject* playerObj;
    f32 distance;

    player = (int)Obj_GetPlayerObject();
    playerObj = (GameObject*)player;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;

    hitKind = ObjHits_GetPriorityHitWithPosition(obj, &hitA, &hitB, &hitObj, &hitPos[0], &hitPos[1], &hitPos[2]);
    if ((hitKind != 0) && (hitObj != 0))
    {
        switch (hitKind)
        {
        case 0x10:
            Obj_StartModelFadeIn(obj, 300);
            break;
        case 0:
            break;
        default:
            Sfx_PlayFromObject(obj, SFXTRIG_ladderslide16);
            stateParam->mode = MAGICPLANT_MODE_HIT_REACT;
            stateParam->animStepScale = gMagicPlantHitReactAnimStep;
            ObjAnim_SetCurrentMove(obj, MAGICPLANT_MOVE_HIT, lbl_803E385C, 0);

            i = MAGICPLANT_HIT_BURST_COUNT;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, MAGICPLANT_HIT_BURST_FX, NULL, 2, -1, NULL);
                i--;
            }
            while (i != 0);

            hitPos[0] += playerMapOffsetX;
            hitPos[2] += playerMapOffsetZ;
            objLightFn_8009a1dc((void*)obj, gMagicPlantHitLightScale, lightPos, 1, 0);
            Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1); /* red hit-flash (200,0,0) over 15 frames */
            break;
        }
    }

    if (stateParam->mode == MAGICPLANT_MODE_ACTIVE)
    {
        if (((GameObject*)obj)->anim.currentMove == MAGICPLANT_MOVE_SWAY_FAST)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E3858)
            {
                stateParam->animStepScale = gMagicPlantIdleAnimStep;
                ObjAnim_SetCurrentMove(obj, MAGICPLANT_MOVE_IDLE, lbl_803E385C, 0);
            }
            else
            {
                stateParam->animStepScale = lbl_803E3890;
            }
        }
        else
        {
            if ((stateParam->idleTimer -= framesThisStep) <= 0)
            {
                stateParam->idleTimer = randomGetRange(MAGICPLANT_IDLE_TIMER_MIN, MAGICPLANT_IDLE_TIMER_MAX);
            }
            else if (((GameObject*)obj)->anim.currentMove != MAGICPLANT_MOVE_IDLE)
            {
                stateParam->animStepScale = gMagicPlantIdleAnimStep;
                ObjAnim_SetCurrentMove(obj, MAGICPLANT_MOVE_IDLE, lbl_803E3890 * (f32)(int)randomGetRange(0, 99), 0);
            }
        }
    }

    distance = Vec_distance(&((GameObject*)obj)->anim.worldPosX, &playerObj->anim.worldPosX);
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x40) == 0)
    {
        if (distance < gMagicPlantBuzzStartDist)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_neonbuzzlp16);
        }
    }
    else if (distance > gMagicPlantBuzzStopDist)
    {
        Sfx_StopObjectChannel(obj, 0x40);
    }
}

#pragma dont_inline on
void MagicPlant_spawnChild(int obj, int objectId)
{
    MagicPlantChildSetup* setup;
    u32 childObj;
    u8* mapData;
    MagicPlantState* state;

    mapData = *(u8**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if ((u8)Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(sizeof(MagicPlantChildSetup), objectId);
        setup->field1A = 0x14;
        setup->field2C = -1;
        setup->field1C = -1;
        setup->x = ((GameObject*)obj)->anim.localPosX;
        setup->y = ((GameObject*)obj)->anim.localPosY;
        setup->z = ((GameObject*)obj)->anim.localPosZ;
        setup->field24 = -1;
        setup->mapByte4 = mapData[0x04];
        setup->mapByte6 = mapData[0x06];
        setup->mapByte5 = mapData[0x05];
        setup->yawByte = (u8)(mapData[0x07] - 0xf);
        childObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                   ((GameObject*)obj)->anim.parent);
        if (childObj != 0)
        {
            ObjLink_AttachChild(obj, childObj, 0);
            state->childObject = childObj;
        }
        else
        {
            mm_free(setup);
            state->childObject = 0;
        }
    }
}
#pragma dont_inline reset

void MagicPlant_update(int obj)
{
    s32 alpha;
    MagicPlantObject* plant;
    MagicPlantSetup* setup;
    MagicPlantState* state;
    int hitObj;
    int hitB;
    int hitA;
    f32 hitPos[3];
    u8 lightPos[0x0c];
    int hitKind;
    f32 progress;
    f32 resetProgress;
    int divisor;

    plant = (MagicPlantObject*)obj;
    setup = (MagicPlantSetup*)plant->objAnim.placementData;
    state = plant->state;

    if ((state->childObject != 0) && (plant->childLinkActive == 0))
    {
        state->childObject = 0;
        Obj_FreeObject(obj);
        return;
    }

    *(u8*)&plant->objAnim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    if (objIsFrozen(obj) != 0)
    {
        hitKind = ObjHits_GetPriorityHitWithPosition(obj, &hitObj, &hitA, &hitB, &hitPos[0], &hitPos[1], &hitPos[2]);
        if ((hitKind != 0) && (hitKind != 0x10))
        {
            hitPos[0] += playerMapOffsetX;
            hitPos[2] += playerMapOffsetZ;
            objLightFn_8009a1dc((void*)obj, gMagicPlantHitLightScale, lightPos, 1, 0);
            Sfx_PlayFromObject(obj, SFXTRIG_barrel_bounce1);
            Obj_ResetModelColorState(obj);
        }
        return;
    }

    switch (state->mode)
    {
    case MAGICPLANT_MODE_WAIT_FOR_EVENT:
        if ((*gMapEventInterface)->shouldNotSaveTime(setup->eventId) != 0)
        {
            MagicPlant_spawnChild(obj, gMagicPlantGemDefIds[setup->gemColor & 3]);
            state->mode = MAGICPLANT_MODE_ACTIVE;
            state->idleTimer = randomGetRange(MAGICPLANT_IDLE_TIMER_MIN, MAGICPLANT_IDLE_TIMER_MAX);
        }
        else
        {
            progress = (*gMapEventInterface)->getTime(setup->eventId);
            divisor = setup->eventDuration;
            if (divisor < 100)
            {
                divisor = 100;
            }
            progress /= divisor;
            if (progress > 1.0f)
            {
                progress = 1.0f;
            }
            else if (progress < 0.0f)
            {
                progress = 0.0f;
            }
            state->animProgress = 1.0f - progress;
        }
        if (plant->objAnim.currentMove != MAGICPLANT_MOVE_CLOSED)
        {
            ObjAnim_SetCurrentMove(obj, MAGICPLANT_MOVE_CLOSED, state->animProgress, 0);
        }
        ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj, state->animProgress);
        break;

    case MAGICPLANT_MODE_ACTIVE:
        MagicPlant_updateActive(obj, setup, state);
        break;

    case MAGICPLANT_MODE_HIT_REACT:
        fn_8017F334(obj, setup, state);
        break;

    case MAGICPLANT_MODE_FADE_OUT:
        if (plant->objAnim.currentMoveProgress >= lbl_803E3858)
        {
            alpha = plant->objAnim.alpha;
            alpha -= framesThisStep * 2;
            if (alpha < 0)
            {
                alpha = 0;
                state->mode = MAGICPLANT_MODE_FADE_IN;
                resetProgress = lbl_803E385C;
                state->animProgress = resetProgress;
                state->animStepScale = resetProgress;
                ObjAnim_SetCurrentMove(obj, MAGICPLANT_MOVE_CLOSED, resetProgress, 0);
                ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj, lbl_803E385C);
            }
            plant->objAnim.alpha = alpha;
        }
        ((ObjHitsPriorityState*)plant->objAnim.hitReactState)->flags &= ~1;
        break;

    case MAGICPLANT_MODE_FADE_IN:
        alpha = plant->objAnim.alpha;
        alpha += framesThisStep;
        if (alpha >= 0xff)
        {
            alpha = 0xff;
            state->mode = MAGICPLANT_MODE_WAIT_FOR_EVENT;
            (*gMapEventInterface)->addTime(setup->eventId, setup->eventDuration);
        }
        plant->objAnim.alpha = alpha;
        ((ObjHitsPriorityState*)plant->objAnim.hitReactState)->flags |= 1;
        break;
    }

    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, state->animStepScale, timeDelta, NULL);
}

int MagicPlant_getExtraSize(void) { return MAGICPLANT_EXTRA_STATE_BYTES; }

int MagicPlant_SeqFn(u8* obj)
{
    (*(void (***)(u8*))gCameraInterface)[0x13](obj);
    return 0;
}

u32 MagicPlant_getObjectTypeId(MagicPlantObject* obj)
{
    MagicPlantSetup* setup = (MagicPlantSetup*)obj->objAnim.placementData;

    return (setup->modelIndex << MAGICPLANT_OBJECT_TYPE_MODEL_SHIFT) | MAGICPLANT_OBJECT_TYPE_BASE;
}

void MagicPlant_free(int obj, int freeChildren)
{
    MagicPlantObject* plant;
    MagicPlantState* state;

    plant = (MagicPlantObject*)obj;
    state = plant->state;
    ObjGroup_RemoveObject(obj, MAGICPLANT_OBJGROUP_A);
    ObjGroup_RemoveObject(obj, MAGICPLANT_OBJGROUP_B);
    if (plant->childLinkActive != 0)
    {
        ObjLink_DetachChild(obj, state->childObject);
        if (freeChildren == 0)
        {
            Obj_FreeObject(state->childObject);
        }
    }
}

void MagicPlant_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    MagicPlantObject* plant;
    MagicPlantState* state;
    void* child;

    plant = (MagicPlantObject*)obj;
    state = plant->state;
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E3858);
        child = (void*)state->childObject;
        if (child != NULL)
        {
            if (*(void**)((char*)child + 0xc4) != NULL)
            {
                ObjPath_GetPointWorldPosition(obj, 0, (float*)((char*)child + 0xc), (float*)((char*)child + 0x10),
                                              (float*)((char*)child + 0x14), 0);
            }
        }
    }
}

void MagicPlant_init(int obj, MagicPlantSetup* setup)
{
    MagicPlantObject* plant;
    ObjAnimComponent* objAnim;
    MagicPlantState* state;
    s32 noSaveTime;
    f32 progress;
    int divisor;

    plant = (MagicPlantObject*)obj;
    objAnim = &plant->objAnim;
    state = plant->state;
    ObjGroup_AddObject(obj, MAGICPLANT_OBJGROUP_A);
    ObjGroup_AddObject(obj, MAGICPLANT_OBJGROUP_B);
    noSaveTime = (*gMapEventInterface)->shouldNotSaveTime(setup->eventId);
    if (noSaveTime == 0)
    {
        progress = (*gMapEventInterface)->getTime(setup->eventId);
        divisor = setup->eventDuration;
        if (divisor < 100) divisor = 100;
        progress /= divisor;
        if (progress > lbl_803E3858)
        {
            progress = lbl_803E3858;
        }
        else if (progress < lbl_803E385C)
        {
            progress = lbl_803E385C;
        }
        state->animProgress = *(f32*)&lbl_803E3858 - progress;
    }
    else
    {
        state->animProgress = lbl_803E3858;
    }
    state->mode = MAGICPLANT_MODE_WAIT_FOR_EVENT;
    state->animStepScale = lbl_803E385C;
    ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj, state->animProgress);
    objAnim->rotX = (s16)((u32)setup->yawByte << 8);
    plant->objectFlags |= MAGICPLANT_OBJECT_FLAGS_CHILD_EFFECTS;
    objAnim->bankIndex = setup->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0x810;
    }
    plant->seqCallback = MagicPlant_SeqFn;
}

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
