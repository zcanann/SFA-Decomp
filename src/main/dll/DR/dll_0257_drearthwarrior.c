/*
 * dll_0257_drearthwarrior - the EarthWarrior, a large rideable creature
 * (DLL 0x257, object type 0x43). Once tamed it can be mounted and steered:
 * while ridden (sub.unk98E == 2) DR_EarthWarrior_update feeds player stick
 * and button input into the shared BaddieState (fn_802BE6E8) and drives an
 * on-screen air/stamina meter (gGameUIInterface air-meter calls); otherwise
 * the movement inputs are zeroed and it idles.
 *
 * Per-object data lives in the extra block (DR_EarthWarrior_getExtraSize ==
 * 0x14fc, EarthWarriorState); its combat/locomotion sub-block hangs off
 * state+0xb58 (EarthWarriorSub). Behavior runs through a 4-entry state
 * handler table (DR_EarthWarrior_stateHandler00..03, installed by
 * DR_EarthWarrior_initialise) dispatched from fn_802BE6E8 via
 * gPlayerInterface, plus the animEventCallback fn_802BDBE8 which translates
 * animation events into hit-shape and path-control updates. fn_802BCA10
 * drives the head/neck look-at bone angles; a tail sim model chain
 * (tailSimHandle) trails the body.
 */
#include "main/dll/DR/dr_802bbc10_shared.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/dll/baddie_state.h"

typedef struct DREarthWarriorPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0xB18 - 0x1C];
    f32 unkB18;
    f32 unkB1C;
    f32 unkB20;
    u8 padB24[0xB28 - 0xB24];
} DREarthWarriorPlacement;


typedef struct DREarthWarriorState
{
    s32 unk0;
    u8 pad4[0x9FD - 0x4];
    u8 unk9FD;
    u8 pad9FE[0xB54 - 0x9FE];
    s32 helperObj;
    u8 padB58[0xF50 - 0xB58];
    s32 unkF50;
    u8 padF54[0xF58 - 0xF54];
    s32 unkF58;
    u8 padF5C[0xFA8 - 0xF5C];
    s32 unkFA8;
    s32 unkFAC;
    s32 unkFB0;
    s32 unkFB4;
    s32 unkFB8;
    u8 padFBC[0xFCC - 0xFBC];
    s32 unkFCC;
    s16 unkFD0;
    u8 padFD2[0xFDC - 0xFD2];
    s16 unkFDC;
    u8 padFDE[0xFEC - 0xFDE];
    s32 unkFEC;
    u8 padFF0[0x1338 - 0xFF0];
    f32 unk1338;
    u8 pad133C[0x1384 - 0x133C];
    f32 unk1384;
    f32 unk1388;
    f32 unk138C;
    u8 pad1390[0x1428 - 0x1390];
    u8 unk1428;
    u8 unk1429;
    u8 unk142A;
    u8 unk142B;
    u8 unk142C;
    u8 pad142D[0x1444 - 0x142D];
    f32 unk1444;
    u8 pad1448[0x14DE - 0x1448];
    s16 unk14DE;
    u8 pad14E0[0x14E2 - 0x14E0];
    s16 airMeterCapacity;
    u8 pad14E4[0x14E6 - 0x14E4];
    u8 unk14E6;
    u8 pad14E7[0x14E8 - 0x14E7];
    u8 unk14E8;
    u8 pad14E9[0x14ED - 0x14E9];
    u8 unk14ED;
    u8 pad14EE[0x14F4 - 0x14EE];
    s8 unk14F4;
    u8 unk14F5;
    u8 pad14F6[0x14F8 - 0x14F6];
    s32 tailSimHandle;
} DREarthWarriorState;


/* Combat sub-block of the EarthWarrior state (state+0xb58). */
typedef struct EarthWarriorSub
{
    u8 pad000[0x264];
    u8 unk264;
    u8 pad265[0xfb];
    int unk360;
    u8 pad364[0x8c];
    u8 flags3F0; /* ByteFlags: b40 leap, b80 airborne */
    u8 flags3F1;
    u8 flags3F2;
    u8 pad3F3[5];
    int moveTable; /* config row pointer */
    int unk3FC;
    int configRow; /* config row pointer */
    f32 unk404;
    f32 unk408;
    u8 pad40C[4];
    f32 unk410;
    u8 pad414[0xc];
    f32 unk420;
    u8 pad424[4];
    f32 unk428;
    f32 unk42C;
    f32 unk430;
    f32 unk434;
    f32 unk438;
    u8 pad43C[0x14];
    int unk450;
    int unk454;
    int unk458;
    int unk45C;
    int unk460;
    u8 pad464[0xc];
    f32 unk470;
    int unk474;
    s16 unk478; /* yaw latch */
    u8 pad47A[2];
    int unk47C;
    int unk480;
    s16 currentYaw; /* current yaw */
    u8 pad486[2];
    int frameCounter;
    int unk48C;
    u8 pad490[4];
    int savedYaw;
    u8 pad498[0x3a];
    s16 unk4D2;
    s16 unk4D4;
    s16 unk4D6;
    u8 pad4D8[0x308];
    f32 unk7E0;
    u8 pad7E4[0x48];
    f32 unk82C;
    f32 unk830;
    f32 unk834;
    u8 pad838[8];
    f32 unk840;
    f32 unk844;
    u8 pad848[0x10];
    int unk858;
    u8 pad85C[0x4a];
    u8 unk8A6;
    u8 unk8A7;
    u8 pad8A8[8];
    u8 attackStage;
    u8 pad8B1[0x1b];
    s8 attackPhase; /* attack phase */
    u8 pad8CD[3];
    u8 unk8D0;
    u8 unk8D1;
    u8 unk8D2;
    u8 unk8D3;
    u8 unk8D4;
    u8 pad8D5[3];
    u16 flags8D8;
    u8 pad8DA[6];
    f32 unk8E0;
    f32 unk8E4;
    f32 unk8E8;
    f32 unk8EC;
    u8 pad8F0[0x90];
    int unk980;
    u8 pad984[2];
    s16 unk986;
    u8 pad988[2];
    s16 health; /* 0x98a */
    u16 flags98C;
    u8 unk98E; /* 2 = stunned/ridden */
    u8 pad98F;
    u8 unk990;
    u8 pad991;
    u8 unk992;
    u8 unk993;
    u8 flags994; /* ByteFlags: b01/b02/b80 */
    u8 unk995;
    u8 pad996[6];
    s8 unk99C;
    u8 unk99D;
    u8 pad99E[2];
    int unk9A0; /* spawned helper object */
} EarthWarriorSub;

STATIC_ASSERT(sizeof(EarthWarriorSub) == 0x9a4);

/* DR_EarthWarrior_getExtraSize == 0x14fc; BaddieState head + family tail. */
typedef struct EarthWarriorState
{
    BaddieState baddie;
    u8 pad35C[0x9fd - 0x35c];
    u8 unk9FD;
    u8 pad9FE[0xb54 - 0x9fe];
    int unkB54;
    EarthWarriorSub sub; /* 0xb58 */
} EarthWarriorState;

STATIC_ASSERT(sizeof(EarthWarriorState) == 0x14fc);
STATIC_ASSERT(offsetof(EarthWarriorState, sub) == 0xb58);

#define EARTHWARRIOR_YAW_STEP 0xb6      /* per-tick yaw increment */
#define EARTHWARRIOR_FRAME_THRESHOLD 0x96 /* frameCounter charge threshold */

typedef struct
{
    s16 v[5];
} EWPathRange;

typedef struct
{
    f32 m[4][4];
} EWColorTbl;

extern f32 lbl_803E8314;
extern f32 lbl_803E8318;
extern f32 lbl_803E831C;
extern f32 lbl_803E8320;
extern f32 lbl_803E8324;
extern f32 lbl_803E8328;
extern f32 lbl_803E832C;
extern f32 lbl_803E8330;
extern f32 lbl_803E8334;
extern f32 lbl_803E833C;
extern f32 lbl_803E8340;
extern f32 lbl_803E8344;
extern f32 lbl_803E8348;
extern f32 lbl_803E834C;
extern f32 lbl_803E8350;
extern f32 lbl_803E8358;
extern f32 lbl_803E835C;
extern f32 lbl_803E8368;
extern f32 lbl_803E836C;
extern f32 lbl_803E8370;
extern f32 lbl_803E8374;
extern f32 lbl_803E8378;
extern f32 lbl_803E837C;
extern f32 lbl_803E8380;
extern f32 lbl_803E8384;
extern f32 lbl_803E8388;
extern f32 lbl_803E838C;
extern f32 lbl_803E8394;
extern f32 GXIndTexMtxScale1024;
extern f32 oneOverTimeDelta;
extern int lbl_803E82D8;
extern u8 gDREarthWarriorInitData[];
extern u8 gDREarthWarriorRowIndices[];
extern EWPathRange lbl_802C2CA8;
extern EWPathRange lbl_802C2CB4;
extern EWColorTbl gDREarthWarriorColors;
extern char lbl_803DC768;

extern void setAButtonIcon(int icon);
extern void dll_2E_func09(int p, void* a, void* b, int c);
extern void fn_80113F94(int p, f32 f);
extern void objAudioFn_8006edcc(int obj, int a, int b, int c, int d, f32 v, f32 lim);
extern int objGetFlagsE5_2(int obj);
extern void Obj_SpawnHitLightAndFade(int obj, void* pos, f32 v);
extern void doRumble(f32 v);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern void storeZeroToFloatParam(int p);
extern void s16toFloat(int p, int v);
extern void fn_802BC788(void);
extern s16* objModelGetVecFn_800395d8(int obj, int idx);

void fn_802BCA10(int obj, int q, int p2);

int DR_EarthWarrior_defaultStateHandler(void) { return 0x0; }

void DR_EarthWarrior_func21(void)
{
}

int DR_EarthWarrior_func20(void) { return 0x0; }

int DR_EarthWarrior_func16(void) { return 0x0; }

int DR_EarthWarrior_render2(void) { return 0x0; }

int DR_EarthWarrior_setScale(void) { return 0x0; }

int DR_EarthWarrior_getExtraSize(void) { return 0x14fc; }

int DR_EarthWarrior_getObjectTypeId(void) { return 0x43; }

void DR_EarthWarrior_func15(int obj, f32* x, f32* y, f32* z)
{
    *x = ((GameObject*)obj)->anim.localPosX;
    *y = ((GameObject*)obj)->anim.localPosY;
    *z = ((GameObject*)obj)->anim.localPosZ;
}

int DR_EarthWarrior_stateHandler00(int obj)
{
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    inner->sub.flags98C |= 0x20;
    return 2;
}

void DR_EarthWarrior_modelMtxFn(int obj, f32* x, f32* y, f32* z)
{
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    *x = inner->sub.unk8E0;
    *y = inner->sub.unk8E4;
    *z = inner->sub.unk8E8;
}

int DR_EarthWarrior_func11(int obj)
{
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    if (inner->sub.unk993 != 0)
    {
        return 1;
    }
    return 2;
}

int DR_EarthWarrior_func14(int obj)
{
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    if (inner->sub.unk992 != 0)
    {
        return 2;
    }
    return 1;
}

void DR_EarthWarrior_func18(int obj, f32* a, int* b)
{
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    *a = (f32)(s32)inner->sub.unk4D4;
    *b = inner->sub.unk4D6;
}

void DR_EarthWarrior_release(void)
{
    if (lbl_803DE4D0 != NULL)
    {
        Resource_Release(lbl_803DE4D0);
        lbl_803DE4D0 = NULL;
    }
}

int DR_EarthWarrior_stateHandler03(int obj, int p2)
{
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    f32 fz;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    fz = lbl_803E8304;
    ((BaddieState*)p2)->animSpeedC = fz;
    ((BaddieState*)p2)->animSpeedB = fz;
    ((BaddieState*)p2)->animSpeedA = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
    {
        if (((ByteFlags*)&inner->sub.flags994)->b80)
        {
            ObjAnim_SetCurrentMove(obj, 7, fz, 0);
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, 8, fz, 0);
        }
        ((BaddieState*)p2)->moveSpeed = GX_F32_256;
    }
    if (*(s8*)&((BaddieState*)p2)->moveDone != 0)
    {
        if (inner->sub.unk98E == 2)
        {
            inner->sub.health -= 1;
            if (inner->sub.health <= 0)
            {
                inner->sub.unk8EC = lbl_803DC76C;
                Camera_EnableViewYOffset();
                CameraShake_SetAllMagnitudes(lbl_803E8338);
                playerAddHealth((int)Obj_GetPlayerObject(), -1);
                inner->sub.health = 0;
            }
            return inner->sub.unk980 + 1;
        }
    }
    return 0;
}

void DR_EarthWarrior_initialise(void)
{
    ((void**)gDREarthWarriorStateHandlers)[0] = (void*)DR_EarthWarrior_stateHandler00;
    ((void**)gDREarthWarriorStateHandlers)[1] = (void*)DR_EarthWarrior_stateHandler01;
    ((void**)gDREarthWarriorStateHandlers)[2] = (void*)DR_EarthWarrior_stateHandler02;
    ((void**)gDREarthWarriorStateHandlers)[3] = (void*)DR_EarthWarrior_stateHandler03;
    gDREarthWarriorDefaultStateHandler = (void*)DR_EarthWarrior_defaultStateHandler;
    if (lbl_803DE4D0 == NULL)
    {
        lbl_803DE4D0 = Resource_Acquire(0x5a, 1);
    }
}

f32 DR_EarthWarrior_func19(int obj, f32* out)
{
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    f32 v = lbl_803E8360 * inner->baddie.animSpeedC + lbl_803E8354;
    *out = -((v < lbl_803E8354) ? lbl_803E8354 : ((v > lbl_803E8364) ? lbl_803E8364 : v));
    return lbl_803E8304;
}

void DR_EarthWarrior_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    EarthWarriorState* inner = ((GameObject*)p1)->extra;
    if (vis == -1)
    {
        objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E8338);
        ObjPath_GetPointWorldPosition(p1, 0xb, (char*)(char*)inner + 0x1438, (char*)(char*)inner + 0x143c,
                                      (char*)(char*)inner + 0x1440, 0);
        ObjPath_GetPointWorldPositionArray(p1, 3, 4, (char*)(char*)inner + 0xb18);
    }
    else if (vis != 0)
    {
        objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E8338);
        ObjPath_GetPointWorldPosition(p1, 0xb, (char*)(char*)inner + 0x1438, (char*)(char*)inner + 0x143c,
                                      (char*)(char*)inner + 0x1440, 0);
        ObjPath_GetPointWorldPositionArray(p1, 3, 4, (char*)(char*)inner + 0xb18);
        dll_2E_func06(p1, (char*)(char*)inner + 0x3ec, 0);
    }
}

void DR_EarthWarrior_free(int obj)
{
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    if (*(void* *)&inner->sub.unk9A0 != NULL)
    {
        ObjModelChain_Free((ObjModelChain*)inner->sub.unk9A0);
    }
    ObjGroup_RemoveObject(obj, 0xa);
    if (((ByteFlags*)&inner->sub.flags994)->b02)
    {
        (*gGameUIInterface)->airMeterSetShutdown();
    }
    if (*(void* *)&inner->unkB54 != NULL)
    {
        ObjLink_DetachChild(obj, inner->unkB54);
        Obj_FreeObject(inner->unkB54);
    }
}

void DR_EarthWarrior_func23(int obj, int mode)
{
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    switch (mode)
    {
    case 1:
        inner->sub.health += 4;
        objAudioFn_800393f8(obj, (char*)(char*)inner + 0x3bc, 0x291, 0x1000, -1, 1);
        inner->sub.unk8EC = lbl_803E82E8;
        *(f32*)((char*)lbl_8033527C + 0x24) = inner->sub.unk8EC;
        break;
    default:
        break;
    }
}

void DR_EarthWarrior_func17(int obj, int param)
{
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    inner->sub.unk98E = (u8)param;
    if (param == 0)
    {
        GameBit_Set(0x7bc, 0);
        GameBit_Set(0x7d4, 1);
        inner->unk9FD &= ~1;
        ((ByteFlags*)&inner->sub.flags994)->b02 = 0;
        (*gGameUIInterface)->airMeterSetShutdown();
    }
    else
    {
        EarthWarriorState* inner2 = ((GameObject*)obj)->extra;
        int p = *(int*)&((GameObject*)obj)->anim.placementData;
        ((ByteFlags*)&inner2->sub.flags994)->b02 = 1;
        (*gGameUIInterface)->initAirMeter(((DREarthWarriorPlacement*)p)->unk1A, 0x5cf);
        (*gGameUIInterface)->runAirMeter(inner2->sub.health);
        GameBit_Set(0x7bc, 1);
        GameBit_Set(0x7d4, 0);
    }
}

void DR_EarthWarrior_func22(int obj, f32 scale)
{
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 lp0, lp1, lp2;
    int mtx = (int)ObjPath_GetPointModelMtx(obj, 2);
    ObjPath_GetPointLocalPosition(obj, 2, &lp0, &lp1, &lp2);
    v.mat[1] = lp0;
    v.mat[2] = lp1;
    v.mat[3] = lp2;
    v.angles[0] = 0;
    v.angles[1] = 0;
    v.angles[2] = 0;
    v.mat[0] = scale / ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    setMatrixFromObjectPos(lbl_803DB170, v.angles);
    mtx44_mult(lbl_803DB170, (void*)mtx, lbl_803DB170);
    fn_8003B950((int)lbl_803DB170);
}

int fn_802BDBE8(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    int i;
    f32 fz;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    if (dll_2E_func07(obj, (int)(u8*)animUpdate, (void*)((int)((char*)inner + 0x3ec)), 0, 0) != 0)
    {
        return 1;
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        int eventId = animUpdate->eventIds[i];
        switch (eventId)
        {
        case 0xa:
            break;
        case 0xe:
        case 0xf:
            inner->unk9FD |= 1;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->shapeFlags &= ~0x20;
            break;
        case 0x10:
            inner->unk9FD &= ~1;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->shapeFlags |= 0x20;
            break;
        }
    }
    *(u32*)&inner->sub.unk360 |= 0x800000LL;
    (*gPathControlInterface)->attachObject((void*)obj, (u8*)&inner->baddie + 4);
    fz = lbl_803E8304;
    inner->baddie.animSpeedC = fz;
    inner->baddie.animSpeedB = fz;
    inner->baddie.animSpeedA = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    return 0;
}

void fn_802BE6E8(int obj, int t, int p3)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    int q;
    int slot;
    Obj_GetPlayerObject();
    q = inner + 0xb58;
    slot = (int)Camera_GetCurrentViewSlot();
    ((EarthWarriorState*)inner)->baddie.hitPoints = 0;
    *(int*)((char*)inner + 0) &= ~0x8000;
    if (*(u8*)((char*)inner + 0x14e6) == 2)
    {
        ((EarthWarriorState*)inner)->baddie.moveInputX = (f32)(s8)padGetStickX(0);
        ((EarthWarriorState*)inner)->baddie.moveInputZ = (f32)(s8)padGetStickY(0);
        *(int*)&((EarthWarriorState*)inner)->baddie.unk31C = getButtonsJustPressed(0);
        *(int*)&((EarthWarriorState*)inner)->baddie.unk318 = getButtonsHeld(0);
        ((EarthWarriorState*)inner)->baddie.cameraYaw = *(s16*)slot;
    }
    else
    {
        f32 v = lbl_803E8304;
        ((EarthWarriorState*)inner)->baddie.moveInputX = v;
        ((EarthWarriorState*)inner)->baddie.moveInputZ = v;
        *(int*)&((EarthWarriorState*)inner)->baddie.unk31C = 0;
        *(int*)&((EarthWarriorState*)inner)->baddie.unk318 = 0;
        ((EarthWarriorState*)inner)->baddie.cameraYaw = 0;
    }
    *(int*)((char*)inner + 0) |= 0x1000000;
    fn_802B0EA4(obj, q, inner);
    (*(void (*)(int, int, f32, f32, int, void*))(*(int*)(*gPlayerInterface + 0x8)))(
        obj, inner, timeDelta, timeDelta, (int)gDREarthWarriorStateHandlers, &gDREarthWarriorDefaultStateHandler);
    ((GameObject*)obj)->anim.rotY = (s16)(
        ((GameObject*)obj)->anim.rotY + (((EarthWarriorState*)inner)->baddie.spawnRotY >> 2));
    ((GameObject*)obj)->anim.rotZ = (s16)(
        ((GameObject*)obj)->anim.rotZ + (((EarthWarriorState*)inner)->baddie.spawnRotZ >> 2));
    if (((ByteFlags*)((char*)inner + 0x14ec))->b02)
    {
        (*gGameUIInterface)->runAirMeter(*(s16*)((char*)inner + 0x14e2));
    }
    fn_802B1BF8(obj, q, inner, timeDelta);
    fn_802B1B28(obj, timeDelta);
    (*gPathControlInterface)->update((void*)obj, (void*)(inner + 4), timeDelta);
    (*gPathControlInterface)->apply((void*)obj, (void*)(inner + 4));
    (*gPathControlInterface)->advance((void*)obj, (void*)(inner + 4), timeDelta);
    ((GameObject*)obj)->anim.rotX = ((EarthWarriorSub*)q)->unk478;
}

int fn_802BC830(int obj, int p2, int p3)
{
    *(u32*)&((EarthWarriorSub*)p2)->unk360 |= 0x1000000LL;
    ((BaddieState*)p3)->moveSpeed = lbl_803E82EC;
    if (((GameObject*)obj)->anim.currentMoveProgress > GXInit_ClearColor &&
        ((GameObject*)obj)->anim.currentMoveProgress < GXInit_BlackColor &&
        ((BaddieState*)p3)->animSpeedC > *(f32*)((char*)((EarthWarriorSub*)p2)->configRow + 0x1c) - GXInit_WhiteColor &&
        *(f32*)((char*)p3 + 0x298) > lbl_803E82FC &&
        ((EarthWarriorSub*)p2)->frameCounter >= EARTHWARRIOR_FRAME_THRESHOLD)
    {
        ((ByteFlags*)&((EarthWarriorSub*)p2)->flags3F0)->b40 = 1;
        ((ByteFlags*)&((EarthWarriorSub*)p2)->flags3F0)->b80 = 0;
        ((EarthWarriorSub*)p2)->unk8A6 = ((EarthWarriorSub*)p2)->unk8A7;
        ((BaddieState*)p3)->moveSpeed = lbl_803E8300;
        ObjAnim_SetCurrentMove(obj, *(s16*)((char*)((EarthWarriorSub*)p2)->moveTable + 0x3a), lbl_803E8304, 0);
        ObjAnim_SetCurrentEventStepFrames((struct ObjAnimComponent*)obj, 0x10);
        ((EarthWarriorSub*)p2)->unk858 = ((EarthWarriorSub*)p2)->currentYaw;
        ((EarthWarriorSub*)p2)->unk844 = (lbl_803E8308 + (*(f32*)((char*)((EarthWarriorSub*)p2)->configRow + 0x14) + ((
            BaddieState*)p3)->animSpeedC)) / lbl_803E830C;
        ((EarthWarriorSub*)p2)->unk478 = ((EarthWarriorSub*)p2)->currentYaw;
        ((EarthWarriorSub*)p2)->currentYaw += 0x8000;
        ((BaddieState*)p3)->animSpeedC = -((BaddieState*)p3)->animSpeedC;
        ((BaddieState*)p3)->animSpeedA = -((BaddieState*)p3)->animSpeedA;
    }
    if (((ByteFlags*)&((EarthWarriorSub*)p2)->flags3F0)->b80 != 0)
    {
        if (((BaddieState*)p3)->animSpeedC <= *(f32*)((char*)((EarthWarriorSub*)p2)->configRow + 0x10) &&
            ((BaddieState*)p3)->animSpeedA <= *(f32*)((char*)((EarthWarriorSub*)p2)->configRow + 0x10))
        {
            ((EarthWarriorSub*)p2)->savedYaw = ((EarthWarriorSub*)p2)->currentYaw;
            ((ByteFlags*)&((EarthWarriorSub*)p2)->flags3F0)->b40 = 0;
            ((ByteFlags*)&((EarthWarriorSub*)p2)->flags3F0)->b80 = 0;
            return 1;
        }
        ((EarthWarriorSub*)p2)->unk408 = lbl_803E8304;
        ((EarthWarriorSub*)p2)->unk438 = ((EarthWarriorSub*)p2)->unk830;
        ((EarthWarriorSub*)p2)->flags8D8 |= 8;
    }
    return 0;
}

#pragma opt_common_subs off
void fn_802BCA10(int obj, int q, int p2)
{
    s16* vec0;
    s16* vec9;
    int v;
    int d;
    v = ((EarthWarriorSub*)q)->unk480 << 1;
    if (v < -0x41)
    {
        d = -0x41;
    }
    else if (v > 0x41)
    {
        d = 0x41;
    }
    else
    {
        d = v;
    }
    d = d * EARTHWARRIOR_YAW_STEP - (u16)((EarthWarriorSub*)q)->unk4D4;
    if (d > 0x8000)
    {
        d -= 0xffff;
    }
    if (d < -0x8000)
    {
        d += 0xffff;
    }
    d = (int)((f32)d * lbl_803E8324);
    if (d < -0x16c)
    {
        d = -0x16c;
    }
    else if (d > 0x16c)
    {
        d = 0x16c;
    }
    ((EarthWarriorSub*)q)->unk4D4 = (f32)d * timeDelta + (f32)(s32)((EarthWarriorSub*)q)->unk4D4;
    ((EarthWarriorSub*)q)->unk4D2 = ((EarthWarriorSub*)q)->unk4D4 / 2;
    {
        f32 ph = (f32)(s32)((BaddieState*)p2)->spawnRotY / lbl_803E8328;
        f32 t;
        if (ph < lbl_803E8334)
        {
            t = lbl_803E8334;
        }
        else if (ph > lbl_803E8338)
        {
            t = lbl_803E8338;
        }
        else
        {
            t = ph;
        }
        d = (int)(lbl_803E832C * (lbl_803E8330 * -t)) - (u16)((EarthWarriorSub*)q)->unk4D6;
    }
    if (d > 0x8000)
    {
        d -= 0xffff;
    }
    if (d < -0x8000)
    {
        d += 0xffff;
    }
    ((EarthWarriorSub*)q)->unk4D6 += d;
    vec0 = objModelGetVecFn_800395d8(obj, 0);
    vec9 = objModelGetVecFn_800395d8(obj, 9);
    objModelGetVecFn_800395d8(obj, 4);
    objModelGetVecFn_800395d8(obj, 5);
    if (vec0 != NULL)
    {
        s16 sv;
        vec0[0] = -((EarthWarriorSub*)q)->unk4D6;
        vec0[1] = ((EarthWarriorSub*)q)->unk4D4 / 2;
        sv = vec0[1];
        if (sv < -4000)
        {
            sv = -4000;
        }
        else if (sv > 4000)
        {
            sv = 4000;
        }
        vec0[1] = sv;
        vec0[2] = 0;
    }
    if (vec9 != NULL)
    {
        s16 sv;
        int t;
        vec9[1] = ((EarthWarriorSub*)q)->unk4D2;
        sv = vec9[1];
        if (sv < -3000)
        {
            sv = -3000;
        }
        else if (sv > 3000)
        {
            sv = 3000;
        }
        vec9[1] = sv;
        t = ((EarthWarriorSub*)q)->unk4D2;
        if (t < 0)
        {
            t = -t;
        }
        vec9[0] = (s16)(t >> 1);
    }
}
#pragma opt_common_subs reset

int DR_EarthWarrior_stateHandler02(int obj, int p2)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    int q = inner + 0xb58;
#define hitState ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)
    ((ByteFlags*)&((EarthWarriorSub*)q)->flags3F1)->b04 = 0;
    ((ByteFlags*)&((EarthWarriorSub*)q)->flags3F1)->b08 = 0;
    ((ByteFlags*)&((EarthWarriorSub*)q)->flags3F2)->b10 = 0;
    if (*(s8*)&((EarthWarriorState*)p2)->baddie.moveJustStartedA != 0)
    {
        ((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b80 = 0;
        ((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b40 = 0;
        *(u8*)&((EarthWarriorSub*)q)->attackPhase = 0;
        ((ByteFlags*)&((EarthWarriorSub*)q)->flags3F2)->b10 = 1;
    }
    if (!((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b80 && !((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b40 &&
        !((ByteFlags*)((char*)inner + 0x14ec))->b01 && (*(int*)&((EarthWarriorState*)p2)->baddie.unk31C & 0x100))
    {
        buttonDisable(0, 0x100);
        ((ByteFlags*)((char*)inner + 0x14ec))->b01 = 1;
        hitState->suppressOutgoingHits = 0;
        ObjAnim_SetCurrentMove(obj, 0x14, lbl_803E8304, 0);
        ((EarthWarriorState*)p2)->baddie.moveDone = 0;
        Sfx_PlayFromObject(obj, 0x121);
    }
    *(int*)p2 |= 0x800000;
    *(s16*)((char*)p2 + 0x278) = 0;
    ((EarthWarriorSub*)q)->unk404 = lbl_803E82E8;
    if (*(s8*)&((EarthWarriorState*)p2)->baddie.moveJustStartedA != 0)
    {
        ((EarthWarriorSub*)q)->currentYaw += ((EarthWarriorSub*)q)->unk48C * EARTHWARRIOR_YAW_STEP;
        ((EarthWarriorSub*)q)->frameCounter = 0;
        ((EarthWarriorSub*)q)->unk48C = 0;
    }
    {
        f32 ph = (((BaddieState*)p2)->inputMagnitude - lbl_803E8308) / lbl_803E82FC;
        f32 a = ((EarthWarriorSub*)q)->unk404 - lbl_803E833C;
        f32 t = (ph < lbl_803E8304) ? lbl_803E8304 : ((ph > lbl_803E8338) ? lbl_803E8338 : ph);
        ((EarthWarriorSub*)q)->unk408 = a * (t * ((EarthWarriorSub*)q)->unk840);
    }
    if (((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b40)
    {
        s16 sv;
        *(u32*)&((EarthWarriorSub*)q)->unk360 |= 0x1000000LL;
        ((EarthWarriorState*)p2)->baddie.moveSpeed = lbl_803E8300;
        sv = (s16)(int)(
            lbl_803E8320 * ((GameObject*)obj)->anim.currentMoveProgress + (f32)(s32)((EarthWarriorSub*)q)->unk858);
        ((EarthWarriorSub*)q)->unk478 = sv;
        ((EarthWarriorSub*)q)->savedYaw = sv;
        if (*(s8*)&((EarthWarriorState*)p2)->baddie.moveDone != 0)
        {
            s16 sw;
            ((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b40 = 0;
            sw = ((EarthWarriorSub*)q)->currentYaw;
            ((EarthWarriorSub*)q)->unk478 = sw;
            ((EarthWarriorSub*)q)->savedYaw = sw;
            *(u8*)&((EarthWarriorSub*)q)->attackPhase = 0xc;
            ((ByteFlags*)&((EarthWarriorSub*)q)->flags3F1)->b04 = 1;
            ((ByteFlags*)&((EarthWarriorSub*)q)->flags3F1)->b08 = 1;
        }
        ((EarthWarriorState*)p2)->baddie.animSpeedC = ((EarthWarriorSub*)q)->unk844 * timeDelta + ((EarthWarriorState*)
            p2)->baddie.animSpeedC;
        ((EarthWarriorSub*)q)->unk408 = lbl_803E8304;
        if (((GameObject*)obj)->anim.currentMoveProgress > GXInit_ClearColor && ((GameObject*)obj)->anim.
            currentMoveProgress < lbl_803E8318)
        {
            ((EarthWarriorSub*)q)->flags8D8 |= 8;
        }
    }
    else if (((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b80)
    {
        if (fn_802BC830(obj, q, p2) != 0)
        {
            return 2;
        }
    }
    else if (((ByteFlags*)((char*)inner + 0x14ec))->b01)
    {
        ((EarthWarriorState*)p2)->baddie.moveSpeed = GX_F32_256;
        if (*(s8*)&((EarthWarriorState*)p2)->baddie.moveDone != 0)
        {
            ((ByteFlags*)((char*)inner + 0x14ec))->b01 = 0;
            ((ByteFlags*)&((EarthWarriorSub*)q)->flags3F1)->b08 = 1;
            hitState->suppressOutgoingHits = 0;
        }
        {
            f32 m1 = lbl_803E8314;
            f32 m2;
            ((EarthWarriorSub*)q)->unk428 *= m1;
            m2 = lbl_803E8318;
            ((EarthWarriorSub*)q)->unk42C *= m2;
            ((EarthWarriorSub*)q)->unk430 *= m1;
            ((EarthWarriorSub*)q)->unk434 *= m2;
        }
        ((EarthWarriorSub*)q)->unk408 *= lbl_803E831C;
        {
            f32 lim = *(f32*)(((EarthWarriorSub*)q)->configRow + 0xc);
            if (((EarthWarriorSub*)q)->unk408 < lim)
            {
                ((EarthWarriorSub*)q)->unk408 = lim;
            }
        }
        hitState->hitVolumePriority = 0x15;
        hitState->hitVolumeId = 2;
    }
    if (!((ByteFlags*)((char*)inner + 0x14ec))->b01 && !((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b40 &&
        !((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b80 &&
        ((EarthWarriorState*)p2)->baddie.animSpeedC > lbl_803E8340 + *(f32*)(((EarthWarriorSub*)q)->configRow + 0x14) &&
        (((EarthWarriorSub*)q)->unk470 < lbl_803E8344 || ((EarthWarriorSub*)q)->frameCounter >= EARTHWARRIOR_FRAME_THRESHOLD))
    {
        ((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b80 = 1;
        *(u32*)&((EarthWarriorSub*)q)->unk360 |= 0x1000000LL;
        ((EarthWarriorSub*)q)->unk844 = ((EarthWarriorState*)p2)->baddie.animSpeedA;
        ObjAnim_SetCurrentMove(obj, *(s16*)(((EarthWarriorSub*)q)->moveTable + 0x3c), lbl_803E8304, 0);
        ((EarthWarriorState*)p2)->baddie.moveSpeed = lbl_803E82EC;
    }
    if (!((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b80 && !((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b40)
    {
        if (((EarthWarriorSub*)q)->frameCounter < EARTHWARRIOR_FRAME_THRESHOLD)
        {
            f32 v = interpolate((f32)(s32)((EarthWarriorSub*)q)->unk47C, lbl_803E8338 / ((EarthWarriorSub*)q)->unk428,
                                timeDelta);
            f32 cap = timeDelta * (((EarthWarriorSub*)q)->unk42C * ((EarthWarriorSub*)q)->unk420);
            if (v > cap)
            {
                v = cap;
            }
            if (((EarthWarriorSub*)q)->unk480 < 0)
            {
                v = -v;
            }
            ((EarthWarriorSub*)q)->unk478 = (s16)(int)(lbl_803E8348 * v + (f32)(s32)((EarthWarriorSub*)q)->unk478);
        }
        if (((EarthWarriorSub*)q)->frameCounter < EARTHWARRIOR_FRAME_THRESHOLD)
        {
            f32 v = interpolate((f32)(s32)((EarthWarriorSub*)q)->frameCounter,
                                lbl_803E8338 / ((EarthWarriorSub*)q)->unk430, timeDelta);
            f32 cap = ((EarthWarriorSub*)q)->unk434 * timeDelta;
            if (v > cap)
            {
                v = cap;
            }
            if (((EarthWarriorSub*)q)->unk48C < 0)
            {
                v = -v;
            }
            ((EarthWarriorSub*)q)->currentYaw = (s16)(int)(
                lbl_803E8348 * v + (f32)(s32)((EarthWarriorSub*)q)->currentYaw);
        }
        else if (((EarthWarriorState*)p2)->baddie.animSpeedC <= *(f32*)(((EarthWarriorSub*)q)->configRow + 0x4) &&
            ((EarthWarriorState*)p2)->baddie.animSpeedA <= *(f32*)(((EarthWarriorSub*)q)->configRow + 0xc))
        {
            ((EarthWarriorSub*)q)->currentYaw += ((EarthWarriorSub*)q)->unk48C * EARTHWARRIOR_YAW_STEP;
        }
    }
    if (!((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b40 && !((ByteFlags*)&((EarthWarriorSub*)q)->flags3F1)->b04)
    {
        f32 v = interpolate(((EarthWarriorSub*)q)->unk408 - ((EarthWarriorState*)p2)->baddie.animSpeedC,
                            ((EarthWarriorSub*)q)->unk438, timeDelta);
        f32 r = lbl_803E834C * timeDelta;
        r = (v < r) ? r : ((v > GXInit_ClearColor * timeDelta) ? GXInit_ClearColor * timeDelta : v);
        if (((EarthWarriorSub*)q)->frameCounter >= EARTHWARRIOR_FRAME_THRESHOLD && r > lbl_803E8304)
        {
            r = lbl_803E8314 * -r;
        }
        ((EarthWarriorState*)p2)->baddie.animSpeedC += r;
        {
            f32 vv = ((EarthWarriorState*)p2)->baddie.animSpeedC;
            f32 t = **(f32**)&((EarthWarriorSub*)q)->configRow;
            t = (vv < t) ? t : ((vv > ((EarthWarriorSub*)q)->unk404) ? ((EarthWarriorSub*)q)->unk404 : vv);
            ((EarthWarriorState*)p2)->baddie.animSpeedC = t;
        }
        ((EarthWarriorState*)p2)->baddie.animSpeedB = lbl_803E8304;
    }
    else
    {
        f32 vv = ((EarthWarriorState*)p2)->baddie.animSpeedC;
        f32 h = ((EarthWarriorSub*)q)->unk404;
        f32 t = -h;
        t = (vv < t) ? t : ((vv > h) ? h : vv);
        ((EarthWarriorState*)p2)->baddie.animSpeedC = t;
    }
    ((EarthWarriorState*)p2)->baddie.animSpeedA += interpolate(
        ((EarthWarriorState*)p2)->baddie.animSpeedC - ((EarthWarriorState*)p2)->baddie.animSpeedA,
        ((EarthWarriorSub*)q)->unk82C, timeDelta);
    if (!((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b80 && !((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b40 &&
        !((ByteFlags*)((char*)inner + 0x14ec))->b01)
    {
        int skip = 0;
        f32 blend;
        int i2;
        if (((ByteFlags*)&((EarthWarriorSub*)q)->flags3F1)->b08)
        {
            skip = 1;
            blend = lbl_803E8304;
        }
        else
        {
            blend = ((GameObject*)obj)->anim.currentMoveProgress;
        }
        i2 = (((EarthWarriorSub*)q)->attackPhase / 4) << 1;
        ((EarthWarriorSub*)q)->attackStage = (i2 >> 1) + 1;
        if (((EarthWarriorSub*)q)->attackStage > 4)
        {
            ((EarthWarriorSub*)q)->attackStage = 4;
        }
        if (((EarthWarriorSub*)q)->attackStage > 3)
        {
            ((EarthWarriorSub*)q)->unk8A6 = 0xa;
        }
        else
        {
            ((EarthWarriorSub*)q)->unk8A6 = 8;
        }
        {
            f32 v294 = ((EarthWarriorState*)p2)->baddie.animSpeedC;
            int tbl = ((EarthWarriorSub*)q)->configRow;
            if (v294 < *(f32*)(tbl + i2 * 4))
            {
                if (((EarthWarriorSub*)q)->attackPhase == 4)
                {
                    if (((EarthWarriorState*)p2)->baddie.animSpeedA < *(f32*)(tbl + 0x10) && ((BaddieState*)p2)->
                        inputMagnitude < lbl_803E8308)
                    {
                        return 2;
                    }
                }
                else
                {
                    ((EarthWarriorSub*)q)->attackPhase -= 4;
                }
            }
            else if (v294 >= *(f32*)(tbl + i2 * 4 + 4))
            {
                if (((EarthWarriorSub*)q)->attackPhase < 0x14)
                {
                    if (((EarthWarriorSub*)q)->attackPhase == 0)
                    {
                        blend = lbl_803E8350;
                    }
                    if (v294 < ((EarthWarriorSub*)q)->unk404)
                    {
                        *(u8*)&((EarthWarriorSub*)q)->attackPhase += 4;
                    }
                }
            }
        }
        if ((skip != 0 || ((EarthWarriorSub*)q)->unk3FC != ((EarthWarriorSub*)q)->moveTable ||
                ((GameObject*)obj)->anim.currentMove != *(s16*)(((EarthWarriorSub*)q)->moveTable + ((EarthWarriorSub*)q)
                    ->attackPhase * 2)) &&
            (ObjAnim_GetCurrentEventCountdown((ObjAnimComponent*)obj) == 0 || ((ByteFlags*)&((EarthWarriorSub*)q)->
                flags3F2)->b10 != 0))
        {
            if (((GameObject*)obj)->anim.currentMove == 0x14)
            {
                blend = lbl_803E8350;
            }
            ObjAnim_SetCurrentMove(
                obj, *(s16*)(((EarthWarriorSub*)q)->moveTable + ((EarthWarriorSub*)q)->attackPhase * 2), blend, 0);
        }
    }
    if (!((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b80 && !((ByteFlags*)&((EarthWarriorSub*)q)->flags3F0)->b40 &&
        !((ByteFlags*)((char*)inner + 0x14ec))->b01)
    {
        if (((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(
            (int)obj, ((EarthWarriorState*)p2)->baddie.animSpeedC, (f32*)((int)p2 + 0x2a0)) == 0)
        {
            ((EarthWarriorState*)p2)->baddie.moveSpeed = lbl_803E8354;
        }
    }
    fn_802BCA10(obj, q, p2);
    return 0;
}
#undef hitState

int DR_EarthWarrior_stateHandler01(int obj, int p2)
{
    extern int ObjAnim_GetCurrentEventCountdown(ObjAnimComponent* objAnim);
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    EarthWarriorSub* q = &inner->sub;
    int s;
    if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
    {
        ((BaddieState*)p2)->animSpeedC = lbl_803E8304;
    }
    ((BaddieState*)p2)->animSpeedA -= interpolate(((BaddieState*)p2)->animSpeedA, q->unk82C, timeDelta);
    if (((BaddieState*)p2)->animSpeedA <= *(f32*)((char*)lbl_8033527C + 0x8))
    {
        ((BaddieState*)p2)->animSpeedA = lbl_803E8304;
    }
    {
        f32 z = lbl_803E8304;
        ((BaddieState*)p2)->animSpeedB = z;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityZ = z;
    }
    if (!((ByteFlags*)&q->flags3F0)->b80 && !((ByteFlags*)&q->flags3F0)->b40 &&
        !((ByteFlags*)&inner->sub.flags994)->b01 && (*(int*)&((BaddieState*)p2)->unk31C & 0x100))
    {
        buttonDisable(0, 0x100);
        ((ByteFlags*)&inner->sub.flags994)->b01 = 1;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->suppressOutgoingHits = 0;
        ObjAnim_SetCurrentMove(obj, 0x14, lbl_803E8304, 0);
        ((BaddieState*)p2)->moveDone = 0;
        return 3;
    }
    if (*(f32*)&((EarthWarriorState*)p2)->baddie.trackedObj >= lbl_803E8358 && ((BaddieState*)p2)->inputMagnitude >=
        lbl_803E8358 &&
        ((BaddieState*)p2)->animSpeedC >= *(f32*)(q->configRow + 0x4))
    {
        return 3;
    }
    s = *(s16*)q->moveTable;
    *(s16*)((char*)p2 + 0x278) = 0;
    q->unk404 = lbl_803E82E8;
    {
        f32 ph = (((BaddieState*)p2)->inputMagnitude - lbl_803E8308) / lbl_803E82FC;
        f32 a = q->unk404 - lbl_803E833C;
        f32 t = (ph < lbl_803E8304) ? lbl_803E8304 : ((ph > lbl_803E8338) ? lbl_803E8338 : ph);
        q->unk408 = a * (t * q->unk840);
    }
    ((BaddieState*)p2)->animSpeedC += interpolate(q->unk408 - ((BaddieState*)p2)->animSpeedC, q->unk438, timeDelta);
    if (*(s8*)&((BaddieState*)p2)->moveJustStartedA != 0)
    {
        q->unk47C = 0;
        q->unk480 = 0;
        q->frameCounter = 0;
        q->unk48C = 0;
        q->unk8A6 = 8;
        q->attackStage = 0;
        ((BaddieState*)p2)->velSmoothTime = lbl_803E835C;
        ((BaddieState*)p2)->moveSpeed = lbl_803E8354;
    }
    if (((GameObject*)obj)->anim.currentMove == *(s16*)(q->moveTable + 0x30) ||
        ((GameObject*)obj)->anim.currentMove == *(s16*)(q->moveTable + 0x32))
    {
        if (*(s8*)&((BaddieState*)p2)->moveDone != 0 && ObjAnim_GetCurrentEventCountdown((ObjAnimComponent*)obj) == 0 &&
            !((ByteFlags*)&inner->sub.flags994)->b01)
        {
            ObjAnim_SetCurrentMove(obj, s, lbl_803E8304, 0);
            ((BaddieState*)p2)->moveSpeed = lbl_803E8354;
        }
    }
    else if (!((ByteFlags*)&inner->sub.flags994)->b01)
    {
        ObjAnim_SetCurrentMove(obj, s, lbl_803E8304, 0);
        ((BaddieState*)p2)->moveSpeed = lbl_803E8354;
    }
    {
        f32 v = interpolate((f32)(s32)q->unk47C, lbl_803E8338 / q->unk428, timeDelta);
        f32 cap = timeDelta * (q->unk42C * q->unk420);
        if (v >= cap)
        {
            v = cap;
        }
        if (q->unk480 < 0)
        {
            v = -v;
        }
        q->unk478 = (s16)(int)(lbl_803E8348 * v + (f32)(s32)q->unk478);
    }
    {
        f32 v = interpolate((f32)(s32)q->frameCounter, lbl_803E8338 / q->unk430, timeDelta);
        f32 cap = q->unk434 * timeDelta;
        if (v >= cap)
        {
            v = cap;
        }
        if (q->unk48C < 0)
        {
            v = -v;
        }
        q->currentYaw = (s16)(int)(lbl_803E8348 * v + (f32)(s32)q->currentYaw);
    }
    fn_802BCA10(obj, (int)q, p2);
    return 0;
}

void DR_EarthWarrior_hitDetect(int obj)
{
    f32 hz;
    f32 hy;
    f32 hx;
    void* hitObj;
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } v;
    EWColorTbl rows;
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    rows = gDREarthWarriorColors;
    if (!(((GameObject*)obj)->objectFlags & 0x1000))
    {
        if (hitState->contactFlags != 0)
        {
            int i = hitState->contactHitVolume;
            i = (i < 0) ? 0 : ((i > 0x23) ? 0x23 : i);
            v.mat[0] = lbl_803E8338;
            v.angles[2] = 0;
            v.angles[1] = 0;
            v.angles[0] = 0;
            v.mat[1] = hitState->contactPosX;
            v.mat[2] = hitState->contactPosY;
            v.mat[3] = hitState->contactPosZ;
            (*(void (*)(int, int, void*, int, int, void*))(*(int*)(*(int*)lbl_803DE4D0 + 0x4)))(
                0, 1, &v, 0x401, -1, rows.m[gDREarthWarriorRowIndices[i]]);
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->suppressOutgoingHits = 1;
            doRumble(lbl_803E8330);
        }
        if (hitState->lastHitObject != 0)
        {
            doRumble(lbl_803E8330);
        }
        ((GameObject*)obj)->anim.rotX = inner->sub.unk478;
        if (inner->baddie.controlMode != 3)
        {
            int hit = ObjHits_GetPriorityHitWithPosition(obj, &hitObj, 0, 0, &hx, &hy, &hz);
            if (hit != 0)
            {
                if (objGetFlagsE5_2(obj) != 0 && inner->sub.unk98E == 2)
                {
                    return;
                }
                Obj_SpawnHitLightAndFade(obj, &hx, lbl_803E8368);
                if (hit == 0x1a)
                {
                    return;
                }
                if (hitObj == Obj_GetPlayerObject())
                {
                    return;
                }
                if (((GameObject*)hitObj)->anim.seqId == 0x23)
                {
                    return;
                }
                objAudioFn_800393f8(obj, (void*)((int)((char*)inner + 0x3bc)), 0x28e, 0x1000, -1, 1);
                {
                    s16 d = ((GameObject*)obj)->anim.rotX - (u16)((GameObject*)hitObj)->anim.rotX;
                    if (d > 0x8000)
                    {
                        d = (s16)(d - 0xffff);
                    }
                    if (d < -0x8000)
                    {
                        d = (s16)(d + 0xffff);
                    }
                    if (d > 0x4000 || d < -0x4000)
                    {
                        ((ByteFlags*)&inner->sub.flags994)->b80 = 0;
                    }
                    else
                    {
                        ((ByteFlags*)&inner->sub.flags994)->b80 = 1;
                    }
                }
                inner->sub.unk980 = inner->baddie.controlMode;
                (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, (int)inner, 3);
            }
        }
        if (*(int*)inner & 0x800000)
        {
            if ((*(u8*)((char*)(char*)inner + 0x262) != 0 || (*(s8*)((char*)(char*)inner + 0x264) & 0xf0)) &&
                inner->sub.unk410 <= lbl_803E8304 && inner->baddie.animSpeedA > lbl_803E836C)
            {
                doRumble((f32)(int)randomGetRange(2, 5));
                inner->sub.unk410 = lbl_803E8370;
                Sfx_PlayFromObject(obj, 0x404);
            }
            if (*(u8*)((char*)(char*)inner + 0x262) != 0 || (hitState->flags & 8))
            {
                f32 spd;
                f32 vcos;
                f32 vsin;
                spd = sqrtf(
                    ((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)->anim.
                    velocityZ * ((GameObject*)obj)->anim.velocityZ);
                ((GameObject*)obj)->anim.velocityX = oneOverTimeDelta * (((GameObject*)obj)->anim.worldPosX - ((
                    GameObject*)obj)->anim.previousWorldPosX);
                ((GameObject*)obj)->anim.velocityZ = oneOverTimeDelta * (((GameObject*)obj)->anim.worldPosZ - ((
                    GameObject*)obj)->anim.previousWorldPosZ);
                vcos = mathSinf((lbl_803E8374 * (f32)(s32)inner->sub.currentYaw) / lbl_803E8320);
                vsin = mathCosf((lbl_803E8374 * (f32)(s32)inner->sub.currentYaw) / lbl_803E8320);
                inner->baddie.animSpeedA = -((GameObject*)obj)->anim.velocityZ * vsin - ((GameObject*)obj)->anim.
                    velocityX * vcos;
                inner->baddie.animSpeedA *= lbl_803E8314;
                {
                    f32 vv = inner->baddie.animSpeedA;
                    f32 t = lbl_803E8378;
                    t = (vv < t) ? t : ((vv > inner->sub.unk404) ? inner->sub.unk404 : vv);
                    inner->baddie.animSpeedA = t;
                }
                {
                    f32 vv = inner->baddie.animSpeedA;
                    f32 t = lbl_803E8304;
                    t = (vv < t) ? t : ((vv > spd) ? spd : vv);
                    inner->baddie.animSpeedA = t;
                }
                if (!((ByteFlags*)&inner->sub.flags3F0)->b40)
                {
                    inner->baddie.animSpeedC = inner->baddie.animSpeedA;
                }
            }
            *(int*)inner &= ~0x800000;
        }
        inner->sub.unk410 -= timeDelta;
        if (inner->sub.unk410 < lbl_803E8304)
        {
            inner->sub.unk410 = *(f32 *)&lbl_803E8304;
        }
        if ((void*)inner != NULL)
        {
            ObjModelChain_AdvancePhase((ObjModelChain*)inner->sub.unk9A0);
        }
    }
}

void DR_EarthWarrior_update(int obj)
{
    EarthWarriorState* inner = ((GameObject*)obj)->extra;
#define hitState ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)
    Obj_GetPlayerObject();
    hitState->hitVolumePriority = 0;
    hitState->hitVolumeId = 0;
    if (*(void* *)&inner->unkB54 == NULL && Obj_IsLoadingLocked() != 0)
    {
        int setup = Obj_AllocObjectSetup(0x18, 0x6f5);
        int newObj = Obj_SetupObject(setup, 4, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                     *(int*)&((GameObject*)obj)->anim.parent);
        ObjLink_AttachChild(obj, newObj, 2);
        inner->unkB54 = newObj;
    }
    inner->sub.unk986 = 5;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
    if (inner->sub.unk98E == 2)
    {
        setAButtonIcon(0x13);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        hitState->lateralResponseWeight = 0xf4;
        hitState->axialResponseWeight = 0xf4;
        fn_802BE6E8(obj, (int)timeDelta, -1);
    }
    else
    {
        f32 z;
        hitState->lateralResponseWeight = 0;
        hitState->axialResponseWeight = 0;
        z = lbl_803E8304;
        inner->baddie.animSpeedC = z;
        inner->baddie.animSpeedB = z;
        inner->baddie.animSpeedA = z;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityY = z;
        ((GameObject*)obj)->anim.velocityZ = z;
        fn_802BE6E8(obj, framesThisStep, -1);
    }
    characterDoEyeAnims(obj, (int)((char*)inner + 0x38c));
    objAnimFn_80038f38(obj, (int)((char*)inner + 0x3bc));
    dll_2E_func03(obj, (int)((char*)inner + 0x3ec));
    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1)
    {
        ((ByteFlags*)&inner->sub.flags994)->b10 = 1;
        if ((*gGameUIInterface)->isEventReady(0xc1) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
            buttonDisable(0, 0x100);
            inner->sub.health += 4;
            GameBit_Set(0xc1, GameBit_Get(0xc1) - 1);
        }
        else if (inner->sub.unk99C != -1)
        {
            if ((*gGameUIInterface)->isCurrentTriggerClear() == 0)
            {
                if (((ByteFlags*)&inner->sub.flags994)->b08 == 0)
                {
                    (*gObjectTriggerInterface)->runSequence(
                        inner->sub.unk99C, (void*)obj, -1);
                    buttonDisable(0, 0x100);
                }
                else
                {
                    ((ByteFlags*)&inner->sub.flags994)->b10 = 1;
                }
            }
        }
    }
    *(s8*)((char*)(char*)inner + 0x264) |= 0x10;
    {
        f32 saved = ((GameObject*)obj)->anim.velocityY;
        u8 mode;
        ((GameObject*)obj)->anim.velocityY = lbl_803E8304;
        *(int*)&inner->baddie.eventFlags &= ~7;
        mode = inner->sub.unk8A6;
        objAudioFn_8006edcc(obj, *(int*)&inner->baddie.eventFlags, mode, (int)((char*)inner + 0xb18),
                            (int)((char*)inner + 0x4), inner->baddie.animSpeedA,
                            (mode == 8) ? lbl_803E837C : lbl_803E8380);
        ((GameObject*)obj)->anim.velocityY = saved;
    }
    if (inner->sub.flags8D8 & 8)
    {
        f32 vecA[3];
        struct
        {
            s16 angles[4];
            f32 mat[4];
        } w;
        int p;
        int i;
        int j;
        f32 c8338;
        f32 c835c;
        vecA[0] = lbl_803E833C * ((GameObject*)obj)->anim.velocityX;
        vecA[1] = lbl_803E8304;
        vecA[2] = lbl_803E833C * ((GameObject*)obj)->anim.velocityZ;
        for (i = 0, p = (int)inner, c835c = lbl_803E835C, c8338 = lbl_803E8338; i < 4; i++)
        {
            w.mat[1] = c835c * ((GameObject*)obj)->anim.velocityX + *(f32*)((char*)p + 0xb18);
            w.mat[2] = *(f32*)((char*)p + 0xb1c);
            w.mat[3] = c835c * ((GameObject*)obj)->anim.velocityZ + *(f32*)((char*)p + 0xb20);
            w.mat[0] = c8338;
            w.angles[0] = 2;
            for (j = 2; j != 0; j--)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7e6, &w, 0x200001, -1, vecA);
            }
            p += 0xc;
        }
        inner->sub.flags8D8 &= ~8;
    }
#undef hitState
}

#pragma opt_propagation off
void DR_EarthWarrior_init(int obj, int p2)
{
    register u8* base = gDREarthWarriorInitData;
    int inner = *(int*)&((GameObject*)obj)->extra;
    int stk;
    EWPathRange r2;
    EWPathRange r1;
    u8* pathState;
    stk = lbl_803E82D8;
    r2 = lbl_802C2CA8;
    r1 = lbl_802C2CB4;
    ((GameObject*)obj)->anim.rotX = (s16)(*(s8*)((char*)p2 + 0x18) << 8);
    ((GameObject*)obj)->animEventCallback = (void*)fn_802BDBE8;
    ObjGroup_AddObject(obj, 0xa);
    ((DREarthWarriorState*)inner)->unk14E8 = *(u8*)((char*)p2 + 0x19);
    ((DREarthWarriorState*)inner)->unk14DE = 5;
    ((DREarthWarriorState*)inner)->unk14F4 = -1;
    (*(void (*)(int, int, int, int))(*(int*)(*gPlayerInterface + 0x4)))(obj, inner, 4, 1);
    *(int*)inner |= 0x4000;
    ((EarthWarriorState*)inner)->baddie.gravity = lbl_803E8384;
    pathState = (u8*)&((EarthWarriorState*)inner)->baddie + 4;
    (*gPathControlInterface)->init(pathState, 0, 0x48683, 1);
    (*gPathControlInterface)->setup(pathState, 4, base + 0xc, base + 0x3c, &stk);
    (*gPathControlInterface)->setLocalPointCollision(pathState, 1, base + 0x4c, base + 0x64, 8);
    pathState[0x264] = 0x28;
    (*gPathControlInterface)->attachObject((void*)obj, pathState);
    ObjHits_EnableObject(obj);
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->trackContactMask = 9;
    dll_2E_func05(obj, inner + 0x3ec, -0x2000, 0x31c7, 2);
    dll_2E_func09(inner + 0x3ec, &r1, &r2, 2);
    fn_80113F94(inner + 0x3ec, lbl_803E8388);
    ((DREarthWarriorState*)inner)->unk9FD |= 2;
    ((DREarthWarriorState*)inner)->unk1444 = lbl_803E82E8;
    ((DREarthWarriorState*)inner)->airMeterCapacity = *(s16*)((char*)p2 + 0x1a);
    ((DREarthWarriorState*)inner)->unkF50 = (int)(base + 0xd8);
    ((DREarthWarriorState*)inner)->unkF58 = (int)(base + 0x84);
    {
        f32 v = lbl_803E8338;
        ((DREarthWarriorState*)inner)->unk138C = v;
        ((DREarthWarriorState*)inner)->unk1384 = v;
    }
    ((DREarthWarriorState*)inner)->unk1388 = lbl_803E838C;
    ((DREarthWarriorState*)inner)->unkFA8 = (int)(base + 0x118);
    ((DREarthWarriorState*)inner)->unk1428 = 0x29;
    ((DREarthWarriorState*)inner)->unkFAC = (int)(base + 0x1bc);
    ((DREarthWarriorState*)inner)->unk1429 = 0x29;
    ((DREarthWarriorState*)inner)->unkFB0 = (int)(base + 0x260);
    ((DREarthWarriorState*)inner)->unk142A = 0x2e;
    ((DREarthWarriorState*)inner)->unkFB4 = (int)(base + 0x1bc);
    ((DREarthWarriorState*)inner)->unk142B = 0x29;
    ((DREarthWarriorState*)inner)->unkFB8 = (int)(base + 0x260);
    ((DREarthWarriorState*)inner)->unk142C = 0x2e;
    ((DREarthWarriorState*)inner)->unk1338 = GXIndTexMtxScale1024;
    {
        s16 h = ((GameObject*)obj)->anim.rotX;
        ((DREarthWarriorState*)inner)->unkFEC = h;
        ((DREarthWarriorState*)inner)->unkFCC = h;
        ((DREarthWarriorState*)inner)->unkFDC = h;
        ((DREarthWarriorState*)inner)->unkFD0 = h;
    }
    ((ByteFlags*)((char*)inner + 0x14ec))->b08 = 0;
    *(u8*)&((DREarthWarriorState*)inner)->unk14F4 = 2;
    storeZeroToFloatParam(inner + 0x14f0);
    s16toFloat(inner + 0x14f0, 0x1e);
    ((ByteFlags*)((char*)inner + 0x14ec))->b02 = 0;
    ((DREarthWarriorState*)inner)->unk14F5 = 1;
    ((DREarthWarriorState*)inner)->helperObj = 0;
    if (GameBit_Get(0x9ec) != 0)
    {
        ((DREarthWarriorState*)inner)->unk14ED = 1;
    }
    ((DREarthWarriorState*)inner)->tailSimHandle = (s32)ObjModelChain_Alloc(&lbl_803DC768, 1);
    ObjModelChain_SetOrigin((ObjModelChain*)((DREarthWarriorState*)inner)->tailSimHandle, lbl_803E8324, lbl_803E831C, lbl_803E8394);
    *(int*)((char*)obj + 0x108) = (int)fn_802BC788;
    ObjModelChain_SetEnabled((ObjModelChain*)((DREarthWarriorState*)inner)->tailSimHandle, 1);
}
#pragma opt_propagation reset
