#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/cfprisonuncle.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objfx.h"





extern u32 randomGetRange(int min, int max);
extern void mm_free(void* ptr);
extern void* Obj_GetPlayerObject(void);
extern void Obj_StartModelFadeIn(int obj, int frames);
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int extraSize, int objectId);
extern int Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 ObjPath_GetPointWorldPosition();
extern f32 Vec_distance(f32 * a, f32 * b);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern void Sfx_PlayFromObject(int obj, u16 sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void Obj_SetModelColorFadeRecursive(int obj, int frames, int red, int green, int blue, int startAtHalf);
extern void Obj_ResetModelColorState(int obj);
extern void Obj_FreeObject(int obj);
extern int objIsFrozen(int obj);

extern EffectInterface** gPartfxInterface;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E3858;
extern f32 lbl_803E385C;
extern f32 lbl_803E3884;
extern f32 lbl_803E3888;
extern f32 lbl_803E388C;
extern f32 lbl_803E3890;
extern f32 lbl_803E3894;
extern f32 lbl_803E3898;
extern f32 timeDelta;
extern u8 framesThisStep;
extern s16 lbl_803DBD98[4];

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
    u8 field1A;
    u8 pad1B;
    s16 field1C;
    u8 pad1E[6];
    s16 field24;
    u8 pad26[6];
    s16 field2C;
} MagicPlantChildSetup;

extern void fn_8017F334(int obj, MagicPlantSetup* setup, MagicPlantState* state);

/*
 * --INFO--
 *
 * Function: fn_8017F4F4
 * EN v1.0 Address: 0x8017F4F4
 * EN v1.0 Size: 760b
 * EN v1.1 Address: 0x8017F548
 * EN v1.1 Size: 836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8017F4F4(int obj, MagicPlantSetup* setupParam, MagicPlantState* stateParam)
{
    int hitObj;
    int hitB;
    int hitA;
    f32 hitPos[3];
    u8 lightPos[0x0c];
    int hitKind;
    int i;
    s16 timer;
    int player;
    f32 distance;

    player = (int)Obj_GetPlayerObject();
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;

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
            Sfx_PlayFromObject(obj, 0x5c);
            stateParam->mode = MAGICPLANT_MODE_HIT_REACT;
            stateParam->animStepScale = lbl_803E3884;
            ObjAnim_SetCurrentMove(obj, 3, lbl_803E385C, 0);

            i = 0x14;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x34e, NULL, 2, -1, NULL);
                i--;
            }
            while (i != 0);

            hitPos[0] += playerMapOffsetX;
            hitPos[2] += playerMapOffsetZ;
            objLightFn_8009a1dc((void*)obj, lbl_803E3888, lightPos, 1, 0);
            Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
            break;
        }
    }

    if (stateParam->mode == MAGICPLANT_MODE_ACTIVE)
    {
        if (((GameObject*)obj)->anim.currentMove == 1)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E3858)
            {
                stateParam->animStepScale = lbl_803E388C;
                ObjAnim_SetCurrentMove(obj, 4, lbl_803E385C, 0);
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
                stateParam->idleTimer = (s16)randomGetRange(300, 600);
            }
            else if (((GameObject*)obj)->anim.currentMove != 4)
            {
                stateParam->animStepScale = lbl_803E388C;
                ObjAnim_SetCurrentMove(obj, 4, lbl_803E3890 * (f32)(int)randomGetRange(0, 99), 0);
            }
        }
    }

    distance = Vec_distance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18));
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x40) == 0)
    {
        if (distance < lbl_803E3894)
        {
            Sfx_PlayFromObject(obj, 0x5d);
        }
    }
    else if (distance > lbl_803E3898)
    {
        Sfx_StopObjectChannel(obj, 0x40);
    }
}

/*
 * --INFO--
 *
 * Function: fn_8017F7B8
 * EN v1.0 Address: 0x8017F7B8
 * EN v1.0 Size: 272b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
void fn_8017F7B8(int obj, int objectId)
{
    MagicPlantChildSetup* setup;
    u32 childObj;
    u8* mapData;
    MagicPlantState* state;

    mapData = *(u8**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if ((u8)Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(0x30, objectId);
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
    return;
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: FUN_8017f7ec
 * EN v1.0 Address: 0x8017F7EC
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8017F88C
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: MagicPlant_update
 * EN v1.0 Address: 0x8017FA10
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017FA4C
 * EN v1.1 Size: 708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void MagicPlant_update(int obj)
{
    MagicPlantObject* plant;
    MagicPlantSetup* setup;
    MagicPlantState* state;
    int hitObj;
    int hitB;
    int hitA;
    f32 hitPos[3];
    u8 lightPos[0x0c];
    int hitKind;
    s32 alpha;
    f32 progress;
    f32 fz;
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

    plant->objAnim.resetHitboxMode |= 8;
    if (objIsFrozen(obj) != 0)
    {
        hitKind = ObjHits_GetPriorityHitWithPosition(obj, &hitObj, &hitA, &hitB, &hitPos[0], &hitPos[1], &hitPos[2]);
        if ((hitKind != 0) && (hitKind != 0x10))
        {
            hitPos[0] += playerMapOffsetX;
            hitPos[2] += playerMapOffsetZ;
            objLightFn_8009a1dc((void*)obj, lbl_803E3888, lightPos, 1, 0);
            Sfx_PlayFromObject(obj, 0x47b);
            Obj_ResetModelColorState(obj);
        }
        return;
    }

    switch (state->mode)
    {
    case MAGICPLANT_MODE_WAIT_FOR_EVENT:
        if ((*gMapEventInterface)->isTimedEventActive(setup->eventId) != 0)
        {
            fn_8017F7B8(obj, lbl_803DBD98[setup->variant & 3]);
            state->mode = MAGICPLANT_MODE_ACTIVE;
            state->idleTimer = (s16)randomGetRange(300, 600);
        }
        else
        {
            progress = (*gMapEventInterface)->getTimedEventProgress(setup->eventId);
            divisor = setup->eventDuration;
            if (divisor < 100)
            {
                divisor = 100;
            }
            progress /= (f32)divisor;
            if (progress > lbl_803E3858)
            {
                progress = lbl_803E3858;
            }
            else if (progress < lbl_803E385C)
            {
                progress = lbl_803E385C;
            }
            state->animProgress = lbl_803E3858 - progress;
        }
        if (plant->objAnim.currentMove != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0, state->animProgress, 0);
        }
        ObjAnim_SetMoveProgress(state->animProgress, (ObjAnimComponent*)obj);
        break;

    case MAGICPLANT_MODE_ACTIVE:
        fn_8017F4F4(obj, setup, state);
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
                fz = lbl_803E385C;
                state->animProgress = fz;
                state->animStepScale = fz;
                ObjAnim_SetCurrentMove(obj, 0, fz, 0);
                ObjAnim_SetMoveProgress(lbl_803E385C, (ObjAnimComponent*)obj);
            }
            plant->objAnim.alpha = (u8)alpha;
        }
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
        break;

    case MAGICPLANT_MODE_FADE_IN:
        alpha = plant->objAnim.alpha;
        alpha += framesThisStep;
        if (alpha >= 0xff)
        {
            alpha = 0xff;
            state->mode = MAGICPLANT_MODE_WAIT_FOR_EVENT;
            (*gMapEventInterface)->startTimedEvent(setup->eventId, (f32)setup->eventDuration);
        }
        plant->objAnim.alpha = (u8)alpha;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags |= 1;
        break;

    case MAGICPLANT_MODE_HIT_REACT:
        fn_8017F334(obj, setup, state);
        break;
    }

    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, state->animStepScale, timeDelta, NULL);
}

/*
 * --INFO--
 *
 * Function: FUN_8017fa14
 * EN v1.0 Address: 0x8017FA14
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x8017FD10
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801804a0
 * EN v1.0 Address: 0x801804A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801802DC
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801804a4
 * EN v1.0 Address: 0x801804A4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80180464
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801804d8
 * EN v1.0 Address: 0x801804D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801804A0
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801804dc
 * EN v1.0 Address: 0x801804DC
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x80180528
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801811c8
 * EN v1.0 Address: 0x801811C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80181204
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801811cc
 * EN v1.0 Address: 0x801811CC
 * EN v1.0 Size: 2244b
 * EN v1.1 Address: 0x80181328
 * EN v1.1 Size: 1672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* 8b "li r3, N; blr" returners. */
int MagicPlant_getExtraSize(void) { return 0x10; }
int trickywarp_getExtraSize(void);
int duster_getExtraSize(void);
int curvefish_getExtraSize(void);

typedef struct DusterStateFlags
{
    u8 floorCached : 1;
    u8 pad : 7;
} DusterStateFlags;

typedef struct DusterState
{
    f32 moveStepScale;
    f32 floorY;
    s16 settleTimer;
    s16 hitReactTimer;
    s16 completeGameBit;
    s16 activeGameBit;
    s16 heldObjectId;
    u8 pad12[6];
    u8 driftDir;
    u8 hitReactActive;
    u8 priorityHit;
    u8 active;
    u8 complete;
    u8 useLaunchVelocity;
    DusterStateFlags flags;
    u8 pad1F;
} DusterState;

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

#pragma scheduling off
#pragma peephole off

/* gCameraInterface: vtable pointer used for state-machine dispatches. */
extern void* gCameraInterface;

/* MagicPlant_SeqFn: vtable[0x13]() with obj passed through implicitly, return 0. */
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

/* obj->u16_X |= MASK */
void StayPoint_init(u16* obj);

extern void objRenderFn_8003b8f4(int obj, float arg);

void MagicPlant_free(int obj, int param_2)
{
    MagicPlantObject* plant;
    MagicPlantState* state;

    plant = (MagicPlantObject*)obj;
    state = plant->state;
    ObjGroup_RemoveObject(obj, 0x34);
    ObjGroup_RemoveObject(obj, 0x3e);
    if (plant->childLinkActive != 0)
    {
        ObjLink_DetachChild(obj, state->childObject);
        if (param_2 == 0)
        {
            Obj_FreeObject(state->childObject);
        }
    }
}

void MagicPlant_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    MagicPlantObject* plant;
    MagicPlantState* state;
    void* s0;
    s32 v;

    plant = (MagicPlantObject*)obj;
    state = plant->state;
    v = visible;
    if (v != 0)
    {
        objRenderFn_8003b8f4(obj, lbl_803E3858);
        s0 = (void*)state->childObject;
        if (s0 != NULL)
        {
            if (*(void**)((char*)s0 + 0xc4) != NULL)
            {
                ObjPath_GetPointWorldPosition(obj, 0, (float*)((char*)s0 + 0xc), (float*)((char*)s0 + 0x10),
                                              (float*)((char*)s0 + 0x14), 0);
            }
        }
    }
}

void trickywarp_free(int obj);




void trickywarp_init(s16* obj, u8* param_2);

void trickyguard_init(s16* obj, u8* param_2);

void duster_render(int obj, int p2, int p3, int p4, int p5, s8 visible);


void duster_hitDetect(int param_1);




void duster_init(int obj, u8* params);

void duster_update(int obj);


void MagicPlant_init(int obj, MagicPlantSetup* setup)
{
    MagicPlantObject* plant;
    ObjAnimComponent* objAnim;
    MagicPlantState* state;
    s32 r;
    f32 t;
    int divisor;

    plant = (MagicPlantObject*)obj;
    objAnim = &plant->objAnim;
    state = plant->state;
    ObjGroup_AddObject(obj, 52);
    ObjGroup_AddObject(obj, 62);
    r = (*gMapEventInterface)->isTimedEventActive(setup->eventId);
    if (r == 0)
    {
        t = (*gMapEventInterface)->getTimedEventProgress(setup->eventId);
        divisor = setup->eventDuration;
        if (divisor < 100) divisor = 100;
        t /= (f32)divisor;
        if (t > lbl_803E3858)
        {
            t = lbl_803E3858;
        }
        else if (t < lbl_803E385C)
        {
            t = lbl_803E385C;
        }
        state->animProgress = lbl_803E3858 - t;
    }
    else
    {
        state->animProgress = lbl_803E3858;
    }
    state->mode = MAGICPLANT_MODE_WAIT_FOR_EVENT;
    state->animStepScale = lbl_803E385C;
    ObjAnim_SetMoveProgress((double)state->animProgress, (ObjAnimComponent*)obj);
    objAnim->rotX = (s16)((u32)setup->yawByte << 8);
    plant->objectFlags |= MAGICPLANT_OBJECT_FLAGS_CHILD_EFFECTS;
    objAnim->bankIndex = (s8)setup->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0x810;
    }
    plant->seqCallback = (void*)MagicPlant_SeqFn;
}

extern f32 lbl_803E3928;



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
