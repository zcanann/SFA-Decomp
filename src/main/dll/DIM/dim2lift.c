/*
 * dim2lift - DIM2 boss (Icicle) lift-combat and baddie-animation
 * callbacks. The DIMbossHitDetect_* functions choose/run the boss move
 * based on player distance/angle/phase (lift-impact, tonsil-slam,
 * breath-burst, blue-white-capture, etc.); the DIMbossAnim_* functions
 * advance the current move and reset to idle. Also holds the DIM2icicle
 * state-light helpers used by the capture effect.
 */
#include "main/audio/sfx_ids.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/dll/DIM/DIM2lift.h"
#include "main/dll/baddie_state.h"
#include "main/sfa_shared_decls.h"

#define MODEL_LIGHT_KIND_POINT 2

extern int randomGetRange(int lo, int hi);
extern void Obj_FreeObject(int obj);
extern u32 ObjMsg_SendToObject();

extern f32 lbl_803E4BD8;
extern f32 lbl_803E4C24;
extern int Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);
extern void** gPlayerInterface;
extern f32 lbl_803E4C00;
extern int lbl_80325AA0[6];
extern int* gBaddieControlInterface;
extern int lbl_80325960[16];
extern f32 gDim2LiftMoveSpeedByDir[16];
extern f32 lbl_803E4C04;
extern u32 gDIMbossSequenceFlags;
extern int lbl_803DBF30;
extern f32 lbl_803E4BC4;
extern f32 lbl_803E4BC8;
extern f32 lbl_803E4BCC;
extern f32 lbl_803E4BD0;
extern f32 lbl_803E4BE8;
extern f32 lbl_803E4BEC;
extern f32 lbl_803E4BC0;
extern f32 lbl_803E4BD4;
extern f32 lbl_803E4C08;
extern f32 lbl_803E4C0C;
extern f32 lbl_803E4C10;
extern f32 lbl_803E4C14;
extern f32 lbl_803E4C18;
extern f32 lbl_803E4C1C;
extern f32 lbl_803E4C20;
extern f32 lbl_803E4BBC;
extern s16 gDim2LiftFarMoveChoices[30];
extern s16 gDim2LiftFarFlankMoveChoices[4];
extern u8 gDIMbossAnimController[];

#pragma scheduling off
#pragma peephole off
typedef struct DIM2icicleBlueWhiteEffectPlacement {
    ObjPlacement base;
    u8 pad18[0x1E - 0x18];
    s16 gameBit;
    s16 gameBit2;
    u8 pad22[0x24 - 0x22];
} DIM2icicleBlueWhiteEffectPlacement;

STATIC_ASSERT(sizeof(DIM2icicleBlueWhiteEffectPlacement) == 0x24);

void DIM2icicle_createStateLight(int obj, u8 isGreen)
{
    extern int objCreateLight(int, int);
    extern void modelLightStruct_setLightKind(int, int);
    extern void modelLightStruct_setPosition(int, f32, f32, f32);
    extern void modelLightStruct_setDiffuseColor(int, int, int, int, int);
    extern void modelLightStruct_setSpecularColor(int, int, int, int, int);
    extern void modelLightStruct_setupGlow(int, int, int, int, int, int, f32);
    extern void modelLightStruct_setDistanceAttenuation(int, f32, f32);
    extern void lightSetField4D(int, int);
    extern void modelLightStruct_setEnabled(int, int, f32);
    extern void modelLightStruct_setDiffuseTargetColor(int, int, int, int, int);
    extern void modelLightStruct_setSpecularTargetColor(int, int, int, int, int);
    extern void modelLightStruct_startColorFade(int, int, int);
    extern void modelLightStruct_setAffectsAabbLightSelection(int, int);
    extern void modelLightStruct_setGlowProjectionRadius(int, f32);
    extern f32 lbl_803E4C28;
    extern f32 lbl_803E4C2C;
    extern f32 lbl_803E4C30;
    int* lightSlot = (int*)*(int*)&((GroundBaddieState*)*(int*)&((GameObject*)obj)->extra)->control;

    if (*(void**)lightSlot != NULL) return;

    lightSlot[0] = objCreateLight(0, 1);
    if (*(void**)lightSlot == NULL) return;

    modelLightStruct_setLightKind(lightSlot[0], MODEL_LIGHT_KIND_POINT);
    modelLightStruct_setPosition(lightSlot[0], ((f32*)lightSlot)[0x16], ((f32*)lightSlot)[0x17],
                                 ((f32*)lightSlot)[0x18]);

    if (isGreen != 0)
    {
        modelLightStruct_setDiffuseColor(lightSlot[0], 0, 255, 0, 255);
        modelLightStruct_setSpecularColor(lightSlot[0], 0, 255, 0, 255);
        modelLightStruct_setupGlow(lightSlot[0], 0, 0, 255, 0, 192, lbl_803E4C28);
    }
    else
    {
        modelLightStruct_setDiffuseColor(lightSlot[0], 255, 0, 0, 255);
        modelLightStruct_setSpecularColor(lightSlot[0], 255, 0, 0, 255);
        modelLightStruct_setupGlow(lightSlot[0], 0, 255, 0, 0, 192, lbl_803E4C2C);
    }

    modelLightStruct_setDistanceAttenuation(lightSlot[0], lbl_803E4C2C, lbl_803E4C30);
    lightSetField4D(lightSlot[0], 1);
    modelLightStruct_setEnabled(lightSlot[0], 1, lbl_803E4BD8);
    modelLightStruct_setDiffuseTargetColor(lightSlot[0], 64, 0, 0, 64);
    modelLightStruct_setSpecularTargetColor(lightSlot[0], 64, 0, 0, 64);
    modelLightStruct_startColorFade(lightSlot[0], 2, 40);
    modelLightStruct_setAffectsAabbLightSelection(lightSlot[0], 1);
    modelLightStruct_setGlowProjectionRadius(lightSlot[0], lbl_803E4BBC);
}

#pragma scheduling on
#pragma peephole on
int DIMbossAnim_hasMoveDone(int unused, int* p) { return *(s8*)&((BaddieState*)p)->moveDone != 0; }

#pragma scheduling off
#pragma peephole off
int DIMbossHitDetect_applyForwardMove(int* obj, u8* state, f32 weight)
{
    if (*(s8*)&((BaddieState*)state)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E4BD8, 0);
        ((BaddieState*)state)->moveDone = 0;
    }
    ((BaddieState*)state)->moveSpeed = lbl_803E4C24;
    ((void(*)(int*, u8*, f32, int))((void**)*gPlayerInterface)[8])(obj, state, weight, 1);
    ((void(*)(int*, u8*, f32, int))((void**)*gPlayerInterface)[12])(obj, state, weight, 4);
    return 0;
}

void DIM2icicle_spawnBlueWhiteEffect(DIMbossEffectMarker* source, f32* velocity)
{
    GameObject* spawnedObj;
    DIM2icicleBlueWhiteEffectPlacement* setup;
    if ((u8)Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(36, 656);
        setup->base.posX = source->x;
        setup->base.posY = source->y;
        setup->base.posZ = source->z;
        setup->base.color[0] = 1;
        setup->base.color[1] = 1;
        setup->base.color[2] = 255;
        setup->base.color[3] = 255;
        setup->gameBit = -1;
        setup->gameBit2 = -1;
        spawnedObj = (GameObject*)Obj_SetupObject(setup, 5, -1, -1, 0);
        if (spawnedObj != NULL)
        {
            spawnedObj->anim.velocityX = velocity[0];
            spawnedObj->anim.velocityY = velocity[1];
            spawnedObj->anim.velocityZ = velocity[2];
        }
    }
}

int DIMbossHitDetect_resetIdleMove(int* obj, u8* state)
{
    if (*(s8*)&((BaddieState*)state)->moveJustStartedA != 0)
    {
        f32 fz;
        if (*(s8*)&((BaddieState*)state)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E4BD8, 0);
            ((BaddieState*)state)->moveDone = 0;
        }
        fz = lbl_803E4BD8;
        ((BaddieState*)state)->animSpeedA = fz;
        ((BaddieState*)state)->animSpeedB = fz;
        ((GameObject*)obj)->anim.activeMove = -1;
    }
    return 0;
}

#pragma scheduling on
#pragma peephole on
int DIMbossAnim_selectTargetControlMode(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    switch (((GroundBaddieState*)state)->targetState)
    {
    case 1: return 5;
    case 2: return 6;
    case 4: return 4;
    case 0: return 2;
    case 3: return 2;
    default: return 2;
    }
}

#pragma scheduling off
#pragma peephole off
int DIMbossAnim_finishDefeat(int obj, int p2)
{
    extern void* Obj_GetPlayerObject(void);
    int state;

    Obj_GetPlayerObject();
    state = *(int*)&((GameObject*)obj)->extra;

    if ((s32)(s8)((BaddieState*)p2)->moveJustStartedB != 0)
    {
        *(int*)&((BaddieState*)p2)->targetObj = 0;
        ((BaddieState*)p2)->physicsActive = 0;
        ((BaddieState*)p2)->hasTarget = 0;
        ObjHits_DisableObject(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x80);
        ObjMsg_SendToObject(Obj_GetPlayerObject(), 0xE0000, obj, 0);
        GameBit_Set(((GroundBaddieState*)state)->gameBitB, 0);
        GameBit_Set(((GroundBaddieState*)state)->gameBitA, 1);
        if (((GameObject*)obj)->anim.placementData == NULL)
        {
            Obj_FreeObject(obj);
            return 0;
        }
    }
    return 0;
}

int DIMbossHitDetect_liftImpact(int obj, int p2)
{
    f32 zeroProgress;

    extern f32 lbl_803E4BF0;
    extern f32 lbl_803E4BF4;
    extern f32 lbl_803E4BF8;
    extern f32 lbl_803E4BFC;

    ((BaddieState*)p2)->moveSpeed = lbl_803E4BF0;
    zeroProgress = lbl_803E4BD8;
    ((BaddieState*)p2)->animSpeedA = zeroProgress;
    ((BaddieState*)p2)->animSpeedB = zeroProgress;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);

    if ((s32)(s8)((BaddieState*)p2)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 15, lbl_803E4BD8, 0);
        ((BaddieState*)p2)->moveDone = 0;
    }

    if ((*(int*)&((BaddieState*)p2)->eventFlags & BADDIE_EVENT_FOOTSTEP) != 0)
    {
        gDIMbossSequenceFlags |= 0x4004;
        Sfx_PlayFromObject(obj, SFXwmap_swoosh);
        Camera_EnableViewYOffset();
        CameraShake_Start(lbl_803E4BC8, lbl_803E4BF4, lbl_803E4BF8);
        doRumble(lbl_803E4BFC);
        GameBit_Set(619, 1);
    }
    return 0;
}

int DIMbossAnim_returnToIdleWhenDone(int obj, int runtime)
{
    if (*(s8*)&((BaddieState*)runtime)->moveDone != 0)
    {
        (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, runtime, 0);
    }
    return 0;
}

int DIMbossHitDetect_chooseIdleTaunt(int obj, int runtime)
{
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        f32 v;
        ((GameObject*)obj)->anim.activeMove = -1;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4C00;
        if ((int)randomGetRange(0, 1) != 0)
        {
            if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove(obj, 0xd, lbl_803E4BD8, 0);
                ((BaddieState*)runtime)->moveDone = 0;
            }
        }
        else
        {
            if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove(obj, 0xc, lbl_803E4BD8, 0);
                ((BaddieState*)runtime)->moveDone = 0;
            }
        }
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 0, lbl_80325AA0);
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 7, 1, lbl_80325AA0);
    return 0;
}

int DIMbossHitDetect_trackTargetMove(int obj, int runtime, f32 hitAmount)
{
    u16 dirSector;
    s16 unused;
    s16 distance;
    ((BaddieState*)runtime)->animSpeedA = lbl_803E4BD8;
    if (*(s8*)&((BaddieState*)runtime)->moveDone != 0 || *(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0 || ((
        GameObject*)obj)->anim.currentMove == 1)
    {
        (*(int (**)(int, int, int, u16*, s16*, s16*))(*(int*)gBaddieControlInterface + 0x14))(
            obj, *(int*)&((BaddieState*)runtime)->targetObj, 0x10, &dirSector, &unused, &distance);
        ObjAnim_SetCurrentMove(obj, lbl_80325960[dirSector], lbl_803E4BD8, 0);
        ((BaddieState*)runtime)->moveSpeed = gDim2LiftMoveSpeedByDir[dirSector];
        ((BaddieState*)runtime)->moveDone = 0;
    }
    (*(int (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x20))(obj, runtime, hitAmount, 8);
    return 0;
}

int DIMbossHitDetect_lungeAttack(int obj, int runtime, f32 hitAmount)
{
    ObjHits_SetHitVolumeSlot(obj, 9, 1, -1);
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        f32 v;
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4C04;
        if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E4BD8, 0);
            ((BaddieState*)runtime)->moveDone = 0;
        }
        ((GameObject*)obj)->anim.activeMove = -1;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 1, lbl_80325AA0);
    (*(int (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x30))(obj, runtime, hitAmount, 0xf0);
    return 0;
}

int DIMbossHitDetect_liftSlam(int obj, int runtime)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        f32 v;
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_2000;
        Camera_EnableViewYOffset();
        CameraShake_Start(lbl_803E4BC4, lbl_803E4BC8, lbl_803E4BCC);
        doRumble(lbl_803E4BD0);
        ((GameObject*)obj)->anim.activeMove = -1;
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4BE8;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
        if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xe, v, 0);
            ((BaddieState*)runtime)->moveDone = 0;
        }
        if (((GroundBaddieState*)state)->targetState == 1)
        {
            *(f32*)(*(int*)&((GroundBaddieState*)state)->control + 0xa8) = lbl_803E4BEC;
        }
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 1, &lbl_803DBF30);
    return 0;
}

int DIMbossHitDetect_tonsilSlam(int obj, int runtime)
{
    f32 v;
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E4BC0)
    {
        gDIMbossSequenceFlags &= ~DIMBOSS_SEQUENCE_FLAG_0020;
    }
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        gDIMbossSequenceFlags |= (u64)DIMBOSS_SEQUENCE_FLAGS_TONSIL_IMPACT;
        Camera_EnableViewYOffset();
        CameraShake_Start(lbl_803E4BC4, lbl_803E4BC8, lbl_803E4BCC);
        doRumble(lbl_803E4BD0);
        ((GameObject*)obj)->anim.activeMove = -1;
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4BD4 * (f32)(*(s8*)&((BaddieState*)runtime)->hitPoints + 1);
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
        if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x15, v, 0);
            ((BaddieState*)runtime)->moveDone = 0;
        }
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 0, &lbl_803DBF30);
    return 0;
}

int DIMbossHitDetect_breathBurst(int obj, int runtime, f32 arg)
{
    f32 h;
    f32 v;
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4C08;
        if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x12, lbl_803E4BD8, 0);
            ((BaddieState*)runtime)->moveDone = 0;
        }
        ((GameObject*)obj)->anim.activeMove = -1;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
    }
    h = ((GameObject*)obj)->anim.currentMoveProgress;
    if (h > lbl_803E4C0C || *(s8*)&((BaddieState*)runtime)->moveDone != 0)
    {
        return 8;
    }
    if (h > lbl_803E4C10)
    {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_BREATH_BURST;
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 5, lbl_80325AA0);
    (*(int (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x30))(obj, runtime, arg, 0xf0);
    return 0;
}

int DIMbossHitDetect_blueWhiteCapture(int obj, int runtime, f32 arg)
{
    f32 h;
    f32 v;
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4C14;
        if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x11, lbl_803E4BD8, 0);
            ((BaddieState*)runtime)->moveDone = 0;
        }
        ((GameObject*)obj)->anim.activeMove = -1;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
    }
    h = ((GameObject*)obj)->anim.currentMoveProgress;
    if (h > lbl_803E4C18)
    {
        gDIMbossSequenceFlags &= ~(u64)DIMBOSS_SEQUENCE_FLAG_0040;
    }
    else if (h > lbl_803E4C1C)
    {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0040;
    }
    if (*(int*)&((BaddieState*)runtime)->eventFlags & 1)
    {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_CAPTURE_BLUE_WHITE_VELOCITY;
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 3, lbl_80325AA0);
    (*(int (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x30))(obj, runtime, arg, 0xf0);
    return 0;
}

int DIMbossHitDetect_blueWhiteEventCapture(int obj, int runtime, f32 arg)
{
    f32 h;
    f32 v;
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        ((BaddieState*)runtime)->moveSpeed = lbl_803E4C00;
        if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x11, lbl_803E4BD8, 0);
            ((BaddieState*)runtime)->moveDone = 0;
        }
        ((GameObject*)obj)->anim.activeMove = -1;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
    }
    h = ((GameObject*)obj)->anim.currentMoveProgress;
    if (h > lbl_803E4C18)
    {
        gDIMbossSequenceFlags &= ~(u64)DIMBOSS_SEQUENCE_FLAG_0040;
    }
    else if (h > lbl_803E4C20)
    {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0040;
    }
    if (*(int*)&((BaddieState*)runtime)->eventFlags & BADDIE_EVENT_LANDING)
    {
        gDIMbossSequenceFlags |= (u64)DIMBOSS_SEQUENCE_FLAG_CAPTURE_BLUE_WHITE_VELOCITY;
        *(int*)&((BaddieState*)runtime)->eventFlags &= ~BADDIE_EVENT_LANDING;
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(obj, runtime, 0, 3, lbl_80325AA0);
    (*(int (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x30))(obj, runtime, arg, 0xf0);
    return 0;
}

int DIMbossHitDetect_randomSwipe(int obj, int runtime, f32 arg)
{
    int t;
    f32 v;
    ObjHits_SetHitVolumeSlot(obj, 9, 1, -1);
    if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
    {
        ((GameObject*)obj)->anim.activeMove = -1;
        v = lbl_803E4BD8;
        ((BaddieState*)runtime)->animSpeedA = v;
        ((BaddieState*)runtime)->animSpeedB = v;
        if ((int)randomGetRange(0, 1) != 0)
        {
            if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove(obj, 0xb, lbl_803E4BD8, 0);
                ((BaddieState*)runtime)->moveDone = 0;
            }
            ((BaddieState*)runtime)->moveSpeed = lbl_803E4C00;
        }
        else
        {
            if (*(s8*)&((BaddieState*)runtime)->moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove(obj, 0x10, lbl_803E4BD8, 0);
                ((BaddieState*)runtime)->moveDone = 0;
            }
            ((BaddieState*)runtime)->moveSpeed = lbl_803E4C04;
        }
    }
    t = *(int*)&((BaddieState*)runtime)->eventFlags;
    if (t & BADDIE_EVENT_LANDING)
    {
        *(int*)&((BaddieState*)runtime)->eventFlags = t & ~BADDIE_EVENT_LANDING;
        gDIMbossSequenceFlags |= (DIMBOSS_SEQUENCE_FLAG_0001 | DIMBOSS_SEQUENCE_FLAG_0004);
    }
    (*(int (**)(int, int, int, int, void*))(*(int*)gPlayerInterface + 0x34))(
        obj, runtime, 0, randomGetRange(0, 1), lbl_80325AA0);
    (*(int (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x30))(obj, runtime, arg, 0xf0);
    return 0;
}

int DIMbossAnim_updatePlayerHitReaction(int obj, int runtime)
{
    u16 dirSector;
    s16 unused;
    u16 distance;
    int state;
    s16 mode;
    state = *(int*)&((GameObject*)obj)->extra;
    if (*(s8*)&((BaddieState*)runtime)->moveDone != 0 || *(s8*)&((BaddieState*)runtime)->moveJustStartedB != 0)
    {
        (*(int (**)(int, int, int, u16*, s16*, u16*))(*(int*)gBaddieControlInterface + 0x14))(
            obj, *(int*)&((BaddieState*)runtime)->targetObj, 0x10, &dirSector, &unused, &distance);
        ((BaddieState*)runtime)->moveDone = 0;
        if (distance < 90)
        {
            if (distance > 30 && ((u16)(dirSector - 3) <= 1 || dirSector == 11 || dirSector == 12))
            {
                (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, runtime, 2);
            }
            else
            {
                (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, runtime, 9);
            }
        }
        else
        {
            if (dirSector == 0 || dirSector == 15)
            {
                ((BaddieState*)runtime)->moveDone = 0;
                if (distance > 240 && (((u8)(*(u8 (**)(int, int, f32))(*(int*)gBaddieControlInterface + 0x18))(
                    obj, runtime, lbl_803E4BBC)) & 1))
                {
                    (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(
                        obj, runtime, gDim2LiftFarMoveChoices[randomGetRange(0, 5)]);
                }
                else if (((GroundBaddieState*)state)->flags400 & 4)
                {
                    (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(
                        obj, runtime, gDim2LiftFarFlankMoveChoices[randomGetRange(0, 1)]);
                }
                else
                {
                    (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, runtime, 3);
                }
            }
            else
            {
                (*(int (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, runtime, 2);
            }
        }
    }
    mode = ((BaddieState*)runtime)->controlMode;
    if (mode != 1 && mode != 4 && mode != 5)
    {
        gDIMbossAnimController[0x611] |= 1;
    }
    else
    {
        gDIMbossAnimController[0x611] &= ~1;
    }
    DIM2icicle_updateHitResponse(obj, runtime);
    return 0;
}

f32 gDim2LiftMoveSpeedByDir[16] = {
    0.007f, 0.025f, 0.029f, 0.05f,
    0.011f, 0.014f, 0.016f, 0.018f,
    0.018f, 0.016f, 0.014f, 0.011f,
    0.05f, 0.029f, 0.025f, 0.007f,
};
