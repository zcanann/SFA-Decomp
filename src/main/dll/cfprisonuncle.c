#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/cfprisonuncle.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objfx.h"

typedef struct TrickyguardPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} TrickyguardPlacement;


typedef struct CurvefishState
{
    u8 pad0[0xA - 0x0];
    s16 unkA;
    u8 padC[0x10 - 0xC];
    s16 unk10;
    u8 pad12[0x108 - 0x12];
    u8 unk108;
    u8 pad109[0x110 - 0x109];
    f32 unk110;
    u8 pad114[0x120 - 0x114];
} CurvefishState;


extern u32 randomGetRange(int min, int max);
extern void mm_free(void* ptr);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void* getTrickyObject(void);
extern void* Obj_GetPlayerObject(void);
extern void Obj_StartModelFadeIn(int obj, int frames);
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int extraSize, int objectId);
extern int Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined8 ObjHits_DisableObject();
extern int ObjHits_IsObjectEnabled();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 ObjPath_GetPointWorldPosition();
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern f32 Vec_distance(f32 * a, f32 * b);
extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern f32 getXZDistance(f32 * a, f32 * b);
extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern int hitDetectFn_80065e50(int obj, void* outHits, int param_3, int param_4,
                                f32 x, f32 y, f32 z);
extern int Objfsa_GetWalkGroupIndexAtPoint(f32* pos, int param_2);
extern int getPatchGroup(f32* pos, int patchGroup);
extern int cMenuGetSelectedItem(void);
extern int fn_80138F84(int tricky);
extern int fn_8029622C(int obj);
extern int fn_80296448(int obj);
extern int fn_800DA980(int curveState, int firstNode, int secondNode, int thirdNode);
extern int Curve_AdvanceAlongPath(int curveState, f32 step);
extern int curveFn_800da23c(int curveState, int node);
extern void fn_801816F8(int obj, int param_2, u8* state);
extern uint countLeadingZeros();
extern int Sfx_IsPlayingFromObject(int obj, u16 sfxId);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern void Sfx_PlayFromObject(int obj, u16 sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void Obj_SetModelColorFadeRecursive(int obj, int frames, int red, int green, int blue, int startAtHalf);
extern void Obj_ResetModelColorState(int obj);
extern void Obj_FreeObject(int obj);
extern int objIsFrozen(int obj);
extern void objRenderFn_80041018(int* obj);

extern int lbl_803DBDA0;
extern EffectInterface** gPartfxInterface;
extern f64 DOUBLE_803e44f8;
extern f64 DOUBLE_803e4500;
extern f64 DOUBLE_803e4570;
extern f64 DOUBLE_803e45b0;
extern f64 DOUBLE_803e45b8;
extern f32 lbl_803DC074;
extern f32 lbl_803DBDA4;
extern f32 lbl_803DBDA8;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DCA0C;
extern f32 lbl_803DCA10;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E44EC;
extern f32 lbl_803E44F0;
extern f32 lbl_803E44F4;
extern f32 lbl_803E4508;
extern f32 lbl_803E450C;
extern f32 lbl_803E4510;
extern f32 lbl_803E4518;
extern f32 lbl_803E451C;
extern f32 lbl_803E4524;
extern f32 lbl_803E4528;
extern f32 lbl_803E452C;
extern f32 lbl_803E4530;
extern f32 lbl_803E4538;
extern f32 lbl_803E4540;
extern f32 lbl_803E4548;
extern f32 lbl_803E4550;
extern f32 lbl_803E4554;
extern f32 lbl_803E4558;
extern f32 lbl_803E455C;
extern f32 lbl_803E4560;
extern f32 lbl_803E4564;
extern f32 lbl_803E4568;
extern f32 lbl_803E456C;
extern f32 lbl_803E4578;
extern f32 lbl_803E4584;
extern f32 lbl_803E4588;
extern f32 lbl_803E458C;
extern f32 lbl_803E4590;
extern f32 lbl_803E4594;
extern f32 lbl_803E4598;
extern f32 lbl_803E459C;
extern f32 lbl_803E45A0;
extern f32 lbl_803E45A4;
extern f32 lbl_803E45A8;
extern f32 lbl_803E45AC;
extern f32 lbl_803E45C0;
extern f32 lbl_803E45D0;
extern f32 lbl_803E38A0;
extern f32 lbl_803E38A8;
extern f32 lbl_803E38B0;
extern f32 lbl_803E38B8;
extern f32 lbl_803E38BC;
extern f32 lbl_803E38C0;
extern f32 lbl_803E38C4;
extern f32 lbl_803E38C8;
extern f32 lbl_803E38CC;
extern f32 lbl_803E38D0;
extern f32 lbl_803E38D4;
extern f64 lbl_803E38D8;
extern f32 lbl_803E38E0;
extern u32 lbl_803E38E8;
extern f32 lbl_803E38EC;
extern f32 lbl_803E38F0;
extern f32 lbl_803E38F4;
extern f32 lbl_803E38F8;
extern f32 lbl_803E38FC;
extern f32 lbl_803E3900;
extern f32 lbl_803E3904;
extern f32 lbl_803E3908;
extern f32 lbl_803E390C;
extern f32 lbl_803E3910;
extern f32 lbl_803E3914;
extern f64 lbl_803E3918;
extern f64 lbl_803E3920;
extern f32 lbl_803E3934;
extern f32 lbl_803E3938;
extern f32 lbl_803E3858;
extern f32 lbl_803E385C;
extern f64 lbl_803E3860;
extern f64 lbl_803E3868;
extern f32 lbl_803E3884;
extern f32 lbl_803E3888;
extern f32 lbl_803E388C;
extern f32 lbl_803E3890;
extern f32 lbl_803E3894;
extern f32 lbl_803E3898;
extern f32 timeDelta;
extern u8 framesThisStep;
extern s16 lbl_803DBD98[4];
extern int ViewFrustum_IsSphereVisible(f32* pos, f32 radius);
extern void vecRotateZXY(void* angles, void* outVec);

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
int trickywarp_getExtraSize(void) { return 0x64; }
int duster_getExtraSize(void) { return 0x20; }
int curvefish_getExtraSize(void) { return 0x120; }

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
int duster_SeqFn(u8* obj)
{
    DusterState* state = ((GameObject*)obj)->extra;
    state->flags.floorCached = 0;
    return 0;
}

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
void StayPoint_init(u16* obj)
{
    u32 v;
    v = ((GameObject*)obj)->objectFlags;
    v |= 0x4000;
    ((GameObject*)obj)->objectFlags = (u16)v;
}

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

void trickywarp_free(int obj)
{
    TrickyWarpState* state = ((GameObject*)obj)->extra;
    if (state->active != 0)
    {
        ObjGroup_RemoveObject(obj, 0x4b);
    }
}

typedef struct TrickyWarpCurveEntry
{
    u8 pad00[3];
    u8 entryPatchGroup;
    u8 linkPatchGroups[4];
    u8 pad08[0xc];
    u32 nodeId;
    s8 action;
    s8 type;
} TrickyWarpCurveEntry;

typedef struct TrickyWarpCurveNode
{
    u8 pad00[4];
    u8 linkPatchGroups[4];
    u8 pad08[0x28];
    s16 requiredGameBit;
    s16 forbiddenGameBit;
} TrickyWarpCurveNode;

int fn_8017FFD0(int obj, TrickyWarpState* state)
{
    int curveCount;
    TrickyWarpCurveEntry** curveEntries;
    int i;
    int linkIndex;
    TrickyWarpCurveEntry* entry;
    TrickyWarpCurveNode* node;
    int n;
    int playerObj;
    int playerPatchGroup;

    if (GameBit_Get(0x4e5) == 0)
    {
        return 0;
    }
    if (getTrickyObject() == NULL)
    {
        return 0;
    }
    if (state->patchGroup == 0)
    {
        state->patchGroup = (u8)Objfsa_GetWalkGroupIndexAtPoint(&((GameObject*)obj)->anim.localPosX, 0);
        if (state->patchGroup != 0)
        {
            curveEntries = (TrickyWarpCurveEntry**)(*gRomCurveInterface)->getCurves(&curveCount);
            n = 0;
            for (i = 0; i < curveCount; i++)
            {
                entry = curveEntries[i];
                if (entry->type == '$' && entry->entryPatchGroup == 0)
                {
                    for (linkIndex = 0; linkIndex < 4; linkIndex++)
                    {
                        if (entry->linkPatchGroups[linkIndex] == state->patchGroup)
                        {
                            state->curveNodeIds[n] = entry->nodeId;
                            n++;
                            break;
                        }
                    }
                }
            }
        }
        else
        {
            return 0;
        }
    }
    if (ViewFrustum_IsSphereVisible(&((GameObject*)obj)->anim.localPosX, lbl_803E38A0) != 0)
    {
        return 0;
    }
    playerObj = (int)Obj_GetPlayerObject();
    playerPatchGroup = Objfsa_GetWalkGroupIndexAtPoint((f32*)(playerObj + 0xc), 0);
    if (playerPatchGroup != 0)
    {
        if (playerPatchGroup == state->patchGroup)
        {
            return 1;
        }
        for (i = 0; i < 0x18; i++)
        {
            if (state->curveNodeIds[i] == 0)
            {
                break;
            }
            node = (TrickyWarpCurveNode*)(*gRomCurveInterface)->getById(state->curveNodeIds[i]);
            if (node != NULL)
            {
                if (node->requiredGameBit == -1 || GameBit_Get(node->requiredGameBit) != 0)
                {
                    if (node->forbiddenGameBit == -1 || GameBit_Get(node->forbiddenGameBit) == 0)
                    {
                        if (node->linkPatchGroups[0] == playerPatchGroup)
                        {
                            return 1;
                        }
                        if (node->linkPatchGroups[1] == playerPatchGroup)
                        {
                            return 1;
                        }
                        if (node->linkPatchGroups[2] == playerPatchGroup)
                        {
                            return 1;
                        }
                        if (node->linkPatchGroups[3] == playerPatchGroup)
                        {
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return getPatchGroup((f32*)(playerObj + 0xc), state->patchGroup);
}

void trickywarp_init(s16* obj, u8* param_2)
{
    u32 v;
    v = ((GameObject*)obj)->objectFlags;
    v |= 0x4000;
    ((GameObject*)obj)->objectFlags = (u16)v;
    *obj = (s16)((u32)param_2[0x1a] << 8);
}

void trickyguard_init(s16* obj, u8* param_2)
{
    u32 v;
    *obj = (s16)((u32)param_2[0x18] << 8);
    v = ((GameObject*)obj)->objectFlags;
    v |= 0x4000;
    ((GameObject*)obj)->objectFlags = (u16)v;
}

void duster_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DusterState* state = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        if (state->active != 0)
        {
            if (state->complete == 0)
            {
                ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E38B0);
            }
        }
    }
}

extern int objBboxFn_800640cc(f32* from, f32* to, f32 radius, int mode, void* hit,
                              void* obj, int flags, int mask, int arg9, int arg10);
extern f32 lbl_803E38B4;

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

    while (ObjMsg_Pop(obj, &msg, 0, 0) != 0)
    {
        if (msg == 0x7000b)
        {
            Sfx_PlayFromObject(obj, SFXen_generic_placeobj);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
            GameBit_Set(state->completeGameBit, 1);
            mapState = (DusterMapEventState*)(*gMapEventInterface)->getState(*gMapEventInterface);
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

    floorDelta = *(f32*)(player + 0x10) - ((GameObject*)obj)->anim.localPosY;
    if (floorDelta < lbl_803E38C4)
    {
        floorDelta = -floorDelta;
    }
    if (floorDelta < lbl_803E38D0 &&
        Vec_xzDistance((f32*)(player + 0x18), (f32*)(obj + 0x18)) < lbl_803E38D4 &&
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
            mapState = (DusterMapEventState*)(*gMapEventInterface)->getState(*gMapEventInterface);
            if (mapState->collectedCount < mapState->maxCollectedCount)
            {
                Sfx_PlayFromObject(obj, SFXen_generic_placeobj);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x51a, NULL, 1, -1, NULL);
                GameBit_Set(state->completeGameBit, 1);
                mapState = (DusterMapEventState*)(*gMapEventInterface)->getState(*gMapEventInterface);
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

typedef struct CurveFishSetup
{
    u8 pad00[8];
    f32 spawnX;
    f32 spawnY;
    f32 spawnZ;
    u8 pad14[5];
    u8 speedChange;
    u8 pad1A[6];
    u16 waitFrames;
    u8 targetYOffset;
    u8 playerRadius;
} CurveFishSetup;

typedef struct CurveFishState
{
    u8 pad00[0x10];
    int hasRouteEdge;
    u8 pad14[0x54];
    f32 targetX;
    f32 targetY;
    f32 targetZ;
    u8 pad74[0x30];
    int routeCursor;
    u8 padA8[0x60];
    u8 mode;
    u8 pad109[3];
    f32 animTimer;
    f32 maxSpeed;
    f32 speed;
    f32 moveStepScale;
    f32 phaseTimer;
} CurveFishState;

void trickywarp_update(int param_1)
{
    int obj = param_1;
    TrickyWarpState* state;
    int r;
    state = ((GameObject*)obj)->extra;
    r = fn_8017FFD0(obj, state);
    if (r != 0)
    {
        if (state->active == 0)
        {
            state->active = 1;
            ObjGroup_AddObject(obj, 0x4b);
        }
    }
    else
    {
        if (state->active != 0)
        {
            state->active = 0;
            ObjGroup_RemoveObject(obj, 0x4b);
        }
    }
}

void curvefish_update(int obj)
{
    CurveFishState* state;
    CurveFishSetup* setup;
    CurveFishSetup* setup2;
    void* player;
    u32 curveQuery;
    int firstNode;
    int secondNode;
    int thirdNode;
    int nextNode;
    f32 maxHitSpeed;
    f32 speedThreshold;
    f32 distLimit;
    f32 distance;
    int i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 mag;
    s16 targetYaw;
    int yawDelta;

    state = ((GameObject*)obj)->extra;
    setup = *(CurveFishSetup**)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    setup2 = *(CurveFishSetup**)&((GameObject*)obj)->anim.placementData;
    curveQuery = lbl_803E38E8;

    state->phaseTimer += timeDelta;

    switch (state->mode)
    {
    case 0:
        {
            f32 waitTime = lbl_803E38EC * (f32)(u32)
            setup->waitFrames;
            if (state->phaseTimer >= waitTime)
            {
                state->phaseTimer -= waitTime;
                state->mode = 1;
            }
            else
            {
                return;
            }
        }
    /* fall through */
    case 1:
        ((GameObject*)obj)->anim.localPosX = setup2->spawnX;
        ((GameObject*)obj)->anim.localPosY = setup2->spawnY;
        ((GameObject*)obj)->anim.localPosZ = setup2->spawnZ;

        firstNode = (int)(*gRomCurveInterface)->getById(
            (*gRomCurveInterface)->find((int*)&curveQuery, 1, -1, ((GameObject*)obj)->anim.localPosX,
                                        ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ));
        secondNode = (int)(*gRomCurveInterface)->getById(
            ((int (*)(int, int))(*gRomCurveInterface)->slot54)(firstNode, 0));
        thirdNode = (int)(*gRomCurveInterface)->getById(
            ((int (*)(int, int))(*gRomCurveInterface)->slot54)(secondNode, 0));

        if (fn_800DA980((int)state, firstNode, secondNode, thirdNode) != 0)
        {
            return;
        }
        state->mode = 2;
        state->speed = lbl_803E38F0;
    /* fall through */
    case 2:
        if (state->phaseTimer <= lbl_803E38EC)
        {
            ((GameObject*)obj)->anim.alpha =
                (u8)(int)(lbl_803E38F4 * (state->phaseTimer / lbl_803E38EC));
            return;
        }
        ((GameObject*)obj)->anim.alpha = 0xff;
        state->mode = 3;
        break;
    case 3:
        break;
    default:
        return;
    }

    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
    {
        state->speed = lbl_803E38F8 * state->maxSpeed;
    }
    else if (fn_80296448((int)player) != 0 &&
        getXZDistance(&((GameObject*)player)->anim.localPosX, (f32*)(obj + 0xc)) <
        (f32)(u32)
            setup->playerRadius * (f32)(u32)
    setup->playerRadius
    )
    {
        state->speed +=
            ((lbl_803E38F8 * (f32)(u32)
        setup2->speedChange
        )
        *timeDelta
        )
        /
        lbl_803E38FC;
        maxHitSpeed = lbl_803E38F8 * state->maxSpeed;
        if (state->speed > maxHitSpeed)
        {
            state->speed = maxHitSpeed;
        }
    }
    else
    {
        state->speed += ((f32)(int)
        randomGetRange(-(int)setup2->speedChange,
                       (int)setup2->speedChange << 1) *
            timeDelta
        )
        /
        lbl_803E38FC;
        if (state->speed < lbl_803E38F0)
        {
            state->speed = lbl_803E38F0;
        }
        else if (state->speed > state->maxSpeed)
        {
            state->speed = state->maxSpeed;
        }
    }

    speedThreshold = state->maxSpeed * lbl_803E3900;
    if (state->speed < speedThreshold)
    {
        if (((GameObject*)obj)->anim.currentMove == 0 && state->animTimer > lbl_803E3904)
        {
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E38F0, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x3c);
            state->animTimer = lbl_803E38F0;
        }
        state->moveStepScale = lbl_803E3908;
    }
    else if (state->speed > lbl_803E390C * state->maxSpeed * lbl_803E3900)
    {
        if (((GameObject*)obj)->anim.currentMove == 0 && state->animTimer > lbl_803E3910)
        {
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E38F0, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x3c);
            state->animTimer = lbl_803E38F0;
        }
        state->moveStepScale = lbl_803E3914;
    }
    else
    {
        if (((GameObject*)obj)->anim.currentMove == 1 && state->animTimer > lbl_803E3910)
        {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E38F0, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x3c);
            state->animTimer = lbl_803E38F0;
        }
        state->moveStepScale = (lbl_803E3914 * state->speed) / state->maxSpeed;
    }

    if (state->speed != lbl_803E38F0)
    {
        distLimit = state->speed * timeDelta;
        distLimit *= distLimit;
        distance = getXZDistance(&state->targetX, (f32*)(obj + 0xc));
        i = 0;
        while (distance < distLimit && i < 5)
        {
            Curve_AdvanceAlongPath((int)state, lbl_803E38F8);
            distance = getXZDistance(&state->targetX, (f32*)(obj + 0xc));
            i++;
        }

        if (state->hasRouteEdge != 0)
        {
            nextNode = ((int (*)(int, int))(*gRomCurveInterface)->slot54)(state->routeCursor, 0);
            if (curveFn_800da23c((int)state, (int)(*gRomCurveInterface)->getById(nextNode)) != 0)
            {
                state->mode = 0;
                state->phaseTimer = lbl_803E38F0;
                ((GameObject*)obj)->anim.alpha = 0;
                return;
            }
        }

        dx = state->targetX - ((GameObject*)obj)->anim.localPosX;
        dy = (state->targetY + (f32)(u32)
        setup->targetYOffset
        )
        -((GameObject*)obj)->anim.localPosY;
        dz = state->targetZ - ((GameObject*)obj)->anim.localPosZ;
        mag = sqrtf(dx * dx + dy * dy + dz * dz);
        dx /= mag;
        dy /= mag;
        dz /= mag;

        ((GameObject*)obj)->anim.localPosX += dx * state->speed;
        ((GameObject*)obj)->anim.localPosY += dy * state->speed;
        ((GameObject*)obj)->anim.localPosZ += dz * state->speed;

        targetYaw = getAngle(dx, dz);
        yawDelta = (s16)targetYaw - ((u16) * (s16*)obj);
        if (yawDelta > 0x8000)
        {
            yawDelta -= 0xffff;
        }
        if (yawDelta < -0x8000)
        {
            yawDelta += 0xffff;
        }
        if (yawDelta > 0x180)
        {
            *(s16*)obj += 0x180;
        }
        else if (yawDelta < -0x180)
        {
            *(s16*)obj -= 0x180;
        }
        else
        {
            *(s16*)obj = targetYaw;
        }
    }

    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, state->moveStepScale, timeDelta, NULL);
    state->animTimer += timeDelta;
}

void curvefish_init(int obj, u8* param_2)
{
    int state;
    u32 v;
    state = *(int*)&((GameObject*)obj)->extra;
    v = ((GameObject*)obj)->objectFlags;
    v |= 0x6000;
    ((GameObject*)obj)->objectFlags = (u16)v;
    ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4) *
        ((f32)(u32)
    param_2[0x18] / lbl_803E3928
    )
    ;
    ((CurvefishState*)state)->unk108 = 1;
    ((CurvefishState*)state)->unk110 = (f32)(u32)
    param_2[0x19] / lbl_803E3928;
}

typedef struct DusterHitEffectPos
{
    u8 pad00[0xc];
    f32 x;
    f32 y;
    f32 z;
} DusterHitEffectPos;

void fn_801814D0(int obj, int param_2, u8* state)
{
    int hitWork[4];
    DusterHitEffectPos effectPos;
    int hitType;
    int* objects;
    int i;
    int* ret;
    f32 objY;
    f32 groupObjY;
    f32 f;

    hitType = ObjHits_GetPriorityHitWithPosition(obj, &hitWork[3], &hitWork[2], &hitWork[1],
                                                 &effectPos.x, &effectPos.y, &effectPos.z);
    if (hitType != 0)
    {
        if (hitType == 0x10)
        {
            Obj_StartModelFadeIn(obj, 0x12c);
        }
        else
        {
            effectPos.x += playerMapOffsetX;
            effectPos.z += playerMapOffsetZ;
            if (state[0x20] != 0)
            {
                if (hitType != 5)
                {
                    objLightFn_8009a1dc((void*)obj, lbl_803E3934, &effectPos, 4, 0);
                    if (Sfx_IsPlayingFromObject(0, 0x37e) == 0)
                    {
                        Sfx_PlayFromObject(obj, 0x37e);
                    }
                    return;
                }
                ret = (int*)ObjGroup_GetObjects(0x10, &hitWork[0]);
                i = 0;
                objects = ret;
                for (; i < hitWork[0]; i++)
                {
                    if (ObjHits_IsObjectEnabled(*objects) != 0)
                    {
                        groupObjY = *(f32*)(*objects + 0x10);
                        objY = ((GameObject*)obj)->anim.localPosY;
                        if (groupObjY > objY && groupObjY < objY + lbl_803DBDA8)
                        {
                            if (Vec_xzDistance((f32*)(*objects + 0x18), (f32*)(obj + 0x18)) < lbl_803DBDA4)
                            {
                                ObjHits_RecordObjectHit(*objects, hitWork[3], 5, 1, 0);
                            }
                        }
                    }
                    objects++;
                }
            }
            objLightFn_8009a1dc((void*)obj, lbl_803E3934, &effectPos, 1, 0);
            Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
            if (Sfx_IsPlayingFromObject(0, (u16) * (s16*)(state + 0x10)) == 0)
            {
                Sfx_PlayFromObject(obj, (u16) * (s16*)(state + 0x10));
            }
            *(s16*)(state + 0xa) = 0x32;
            state[9] = 0;
            fn_801816F8(obj, param_2, state);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
            f = lbl_803E3938;
            ((GameObject*)obj)->anim.velocityX = lbl_803E3938;
            ((GameObject*)obj)->anim.velocityZ = f;
            ObjHits_ClearHitVolumes(obj);
            if (lbl_803DBDA0 != 0)
            {
                ObjHits_DisableObject(obj);
            }
        }
    }
}

void trickyguard_update(int* obj)
{
    int* tricky;
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
    if (((TrickyguardPlacement*)def)->unk1A != -1)
    {
        if ((u32)GameBit_Get(((TrickyguardPlacement*)def)->unk1A) == 0) return;
    }
    tricky = (int*)getTrickyObject();
    if (tricky == NULL) return;
    if ((u8)((int (*)(int*))(**(int***)((char*)tricky + 0x68))[0x11])(tricky) != 0) return;
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x04) != 0)
    {
        ((void (*)(int*, int*, int, int))(**(int***)((char*)tricky + 0x68))[0xa])(tricky, obj, 1, 3);
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x08);
    objRenderFn_80041018(obj);
}

typedef struct StayPointSetup
{
    u8 pad00[0x1e];
    s16 activeGameBit;
    s16 requiredGameBit;
} StayPointSetup;

void StayPoint_update(int obj)
{
    StayPointSetup* setup;
    void* tricky;
    int isCurrentStayPoint;

    setup = *(StayPointSetup**)&((GameObject*)obj)->anim.placementData;
    tricky = getTrickyObject();
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
    if (tricky != NULL)
    {
        isCurrentStayPoint = (obj - fn_80138F84((int)tricky) == 0);
        if (isCurrentStayPoint == 0 && setup->activeGameBit != -1)
        {
            GameBit_Set(setup->activeGameBit, 0);
        }
        if (setup->requiredGameBit == -1 || GameBit_Get(setup->requiredGameBit) != 0)
        {
            if (isCurrentStayPoint != 0 &&
                vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, (f32*)((int)tricky + 0x18)) < lbl_803E38A8)
            {
                if (setup->activeGameBit != -1)
                {
                    GameBit_Set(setup->activeGameBit, 1);
                }
                return;
            }
            if (cMenuGetSelectedItem() == -1)
            {
                *(u8*)(*(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x40) + 0x11) = 0;
            }
            else
            {
                *(u8*)(*(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x40) + 0x11) = 0x10;
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (
                u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~8);
            if (((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0) && *(void**)(obj + 0x74) != NULL)
            {
                objRenderFn_80041018((int*)obj);
            }
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
            {
                ((void (*)(void*, int, int, int))(*(int*)(*(int*)(*(int*)((int)tricky + 0x68)) + 0x28)))(
                    tricky, obj, 1, 3);
            }
        }
    }
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
