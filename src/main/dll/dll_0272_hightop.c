/*
 * hightop (DLL 0x272) - the "HighTop" rideable/escortable dinosaur baddie
 * (object type 0x43).
 *
 * Runs as a BaddieState-driven object with an 11-entry state-handler
 * table (gHighTopStateHandlers, installed in hightop_initialise) plus a
 * default handler. States cover idle/wander (04), locomotion (02),
 * follow/turn (01), the air-meter ride sequence (07/08), reset/death (09),
 * and a scripted progress state (10). It owns a path-control walker
 * (gPathControlInterface) for ground motion, a look-controller from
 * dll_2E, eye animation, movement SFX, and the on-screen air meter
 * (gGameUIInterface). Hits drain the air meter; emptying it shuts the
 * meter down, spawns a follow-up object and sets GameBit 0xB48.
 *
 * Interaction is gated through trigger sequences (gObjectTriggerInterface)
 * and a set of GameBits (e.g. 0x631/0x632/0x634, the 0x9C7.. progress
 * quartet, and the 0x3F0.. counters).
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/obj_placement.h"
#include "main/audio/sfx_trigger_ids.h"

#define PAD_BUTTON_A 0x100

/* 0x2C-byte Obj_AllocObjectSetup(0x2C, 0xD4) buffer composed in
 * hightop_takeHit when the air meter empties (death follow-up spawn). */
typedef struct HighTopDeathSpawn
{
    ObjPlacement base; /* 0x00..0x17 */
    u8 pad18[0x1A - 0x18];
    s16 unk1A; /* 0x1A: 0x675 */
    s16 unk1C; /* 0x1C */
    s16 unk1E; /* 0x1E: -1 */
    u8 pad20[0x2C - 0x20];
} HighTopDeathSpawn;

STATIC_ASSERT(offsetof(HighTopDeathSpawn, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(HighTopDeathSpawn, unk1E) == 0x1E);
STATIC_ASSERT(sizeof(HighTopDeathSpawn) == 0x2C);

typedef struct HightopPlacement
{
    s32 unk0;
    u8 pad4[0x19 - 0x4];
    s8 unk19;
    u8 pad1A[0x1E - 0x1A];
    s16 gameBitId;
    u8 pad20[0x25F - 0x20];
    s8 unk25F;
    u8 pad260[0x27A - 0x260];
    u8 moveJustStartedA; /* 0x27A: BaddieState one-shot */
    u8 pad27B[0x280 - 0x27B];
    f32 unk280;
    f32 unk284;
    u8 pad288[0x28C - 0x288];
    f32 unk28C;
    f32 unk290;
    f32 unk294;
    f32 unk298;
    f32 unk29C;
    f32 unk2A0;
    u8 pad2A4[0x2B8 - 0x2A4];
    f32 unk2B8;
    u8 pad2BC[0x318 - 0x2BC];
    s32 unk318;
    s32 unk31C;
    u8 pad320[0x330 - 0x320];
    s16 unk330;
    u8 pad332[0x334 - 0x332];
    s16 unk334;
    s16 unk336;
    s16 unk338;
    u8 pad33A[0x346 - 0x33A];
    u8 moveDone;         /* 0x346: BaddieState move-complete flag */
    u8 pad347[0x354 - 0x347];
    u8 unk354;
    u8 pad355[0x9FD - 0x355];
    u8 flags;
    u8 pad9FE[0xC16 - 0x9FE];
    s16 unkC16;
    s16 airMeterCapacity;
    u8 padC1A[0xC28 - 0xC1A];
    f32 unkC28;
    u8 padC2C[0xC38 - 0xC2C];
    f32 sfxIntervalTimer;
    u8 padC3C[0xC40 - 0xC3C];
    u16 flagsC40;
    u8 padC42[0xC4B - 0xC42];
    u8 substate;
    u8 padC4C[0xC50 - 0xC4C];
} HightopPlacement;

typedef struct HighTopRuntime
{
    BaddieState baddie;
    u8 pad35C[0x3ec - 0x35c];
    u8 lookController[0x9fd - 0x3ec]; /* dll_2E look-controller block */
    u8 flags;
    u8 pad9FE[0xb18 - 0x9fe];
    f32 pathPointWorldPositions[12];
    u8 padB48[0xb6c - 0xb48];
    f32 pathPoint2X;
    f32 pathPoint2Y;
    f32 pathPoint2Z;
    f32 pathPoint0X;
    f32 pathPoint0Y;
    f32 pathPoint0Z;
    u8 padB84[0xc16 - 0xb84];
    s16 turnRateThreshold;
    s16 airMeterRemaining; /* seeded from placement airMeterCapacity; -=1 on hit; 0 -> airMeterSetShutdown */
    u8 padC1A[2];
    f32 lookTargetX;
    f32 lookTargetY;
    f32 lookTargetZ;
    f32 unkC28;
    u8 padC2C[4];
    f32 stateTimer; /* per-state countdown; -= framesThisStep, re-armed from random */
    u8 padC34[4];
    f32 sfxIntervalTimer;
    s32 savedControlMode;
    u16 flagsC40;
    u8 idleSeqIndex; /* index into gHighTopIdleSequenceIds/Weights */
    u8 unkC43;
    u8 padC44;
    u8 unkC45;
    u8 padC46[3];
    BitFlags8 flagsC49;
    BitFlags8 flagsC4A;
    u8 substate; /* (s8) per-handler behavior substate dispatched via switch */
} HighTopRuntime;

STATIC_ASSERT(sizeof(HighTopRuntime) == 0xC4C);
STATIC_ASSERT(offsetof(HighTopRuntime, flags) == 0x9FD);
STATIC_ASSERT(offsetof(HighTopRuntime, turnRateThreshold) == 0xC16);
STATIC_ASSERT(offsetof(HighTopRuntime, substate) == 0xC4B);

typedef struct HighTopObject
{
    union {
        ObjAnimComponent anim;
        struct {
            s16 yaw;
            u8 pad02[0xc - 0x2];
            f32 x;
            f32 y;
            f32 z;
            u8 pad18[0xb8 - 0x18];
        };
    };
    HighTopRuntime* runtime;
} HighTopObject;

STATIC_ASSERT(offsetof(HighTopObject, anim) == 0x00);
STATIC_ASSERT(offsetof(HighTopObject, yaw) == offsetof(ObjAnimComponent, rotX));
STATIC_ASSERT(offsetof(HighTopObject, x) == offsetof(ObjAnimComponent, localPosX));
STATIC_ASSERT(offsetof(HighTopObject, runtime) == 0xB8);

#define HIGHTOP_OBJECT_TYPE_ID 0x43

int hightop_defaultStateHandler(void) { return 0x0; }

void hightop_func15(void)
{
}

int hightop_func14(void) { return 0x0; }

int hightop_func10(void) { return 0x0; }

int hightop_func0E(void) { return 0x1; }

int hightop_func0B(void) { return 0x1; }

int hightop_getExtraSize(void) { return sizeof(HighTopRuntime); }

int hightop_getObjectTypeId(void) { return HIGHTOP_OBJECT_TYPE_ID; }

void hightop_release(void)
{
}

int hightop_render2(void) { return 0x0; }

int hightop_setScale(void) { return 0x0; }

void hightop_func11(int obj, int val)
{
    u8 v = val;
    HighTopRuntime* p = ((GameObject*)obj)->extra;
    p->unkC43 = v;
}

f32 hightop_func13(int obj, f32* out)
{
    *out = lbl_803E6B34;
    return lbl_803E6AA8;
}

void hightop_func12(int obj, f32* a, int* b)
{
    *a = lbl_803E6AA8;
    *b = 0;
}

void hightop_modelMtxFn(int obj, f32* a, f32* b, f32* c)
{
    HighTopRuntime* runtime = ((HighTopObject*)obj)->runtime;
    *a = runtime->pathPoint2X;
    *b = runtime->pathPoint2Y;
    *c = runtime->pathPoint2Z;
}

void hightop_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0x26);
    ObjGroup_RemoveObject(obj, 0xa);
    (*gGameUIInterface)->airMeterSetShutdown();
}

int hightop_stateHandler00(int obj)
{
    int p = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((HightopPlacement*)p)->unk19 != 0)
    {
        return 0xa;
    }
    if (GameBit_Get(0x631) != 0)
    {
        return 8;
    }
    return 5;
}

int hightop_stateHandler06(int obj, u8* state)
{
    HighTopRuntime* p = ((GameObject*)obj)->extra;
    if ((s8)((BaddieState*)state)->moveJustStartedA != 0)
    {
        p->flags |= 1;
    }
    if (GameBit_Get(0x632) != 0)
    {
        return 8;
    }
    return 2;
}

void hightop_func0F(int obj, f32* ox, f32* oy, f32* oz)
{
    int* player;
    ObjPosParams pos;
    f32 mtx[16];
    player = Obj_GetPlayerObject();
    pos.x = ((GameObject*)player)->anim.localPosX;
    pos.y = ((GameObject*)player)->anim.localPosY;
    pos.z = ((GameObject*)player)->anim.localPosZ;
    pos.rx = ((GameObject*)player)->anim.rotX;
    pos.ry = ((GameObject*)player)->anim.rotY;
    pos.rz = ((GameObject*)player)->anim.rotZ;
    pos.scale = lbl_803E6AB8;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, lbl_803E6AA8, lbl_803E6B38, lbl_803E6B3C, ox, oy, oz);
}

int hightop_stateHandler03(int obj, u8* state)
{
    HighTopRuntime* p = ((GameObject*)obj)->extra;
    f32 zero = lbl_803E6AA8;
    ((HighTopRuntime*)state)->baddie.animSpeedC = zero;
    ((HighTopRuntime*)state)->baddie.animSpeedB = zero;
    ((HighTopRuntime*)state)->baddie.animSpeedA = zero;
    ((GameObject*)obj)->anim.velocityX = zero;
    ((GameObject*)obj)->anim.velocityY = zero;
    ((GameObject*)obj)->anim.velocityZ = zero;
    if ((s8)((BaddieState*)state)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x78);
        if (*(u32*)&p->savedControlMode == 4)
        {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E6AA8, 0);
            ((HighTopRuntime*)state)->baddie.moveSpeed = lbl_803E6AC8;
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E6AA8, 0);
            ((HighTopRuntime*)state)->baddie.moveSpeed = lbl_803E6AC8;
        }
    }
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E6B00)
    {
        return p->savedControlMode + 1;
    }
    return 0;
}

int hightop_stateHandler05(int obj, u8* state)
{
    HighTopRuntime* p = ((GameObject*)obj)->extra;
    if ((s8)((BaddieState*)state)->moveJustStartedA != 0)
    {
        p->flagsC49.b1 = 0;
        p->substate = 0xa;
    }
    switch ((s8)p->substate)
    {
    case 1:
        if (GameBit_Get(0x62c) != 0)
        {
            p->substate = 2;
        }
        break;
    case 0xa:
        if (GameBit_Get(0x630) != 0)
        {
            return 7;
        }
        break;
    }
    return 0;
}

int hightop_interactionCallback(int obj)
{
    HighTopRuntime* p;
    seqFn_800394a0(obj);
    p = ((GameObject*)obj)->extra;
    p->flags &= ~1;
    p->flagsC49.b4 = 0;
    p->flagsC49.b6 = 1;
    if ((s8)p->substate == 0)
    {
        p->flagsC4A.b0 = 1;
    }
    return 0;
}

#pragma dont_inline on
void hightop_playMovementSfx(int obj, int state2, int state)
{
    int flags = *(int*)((char*)state + 0x314);
    int idx;
    if ((flags & 0x81) != 0)
    {
        if (flags & 1)
        {
            idx = 0;
        }
        if (flags & 0x80)
        {
            idx = 1;
        }
        Sfx_PlayFromObject((u32)obj, (u16)(&gHighTopMovementSfxIds)[idx]);
    }
    if (*(int*)((char*)state + 0x314) & 0x100)
    {
        fn_8009A8C8(obj, lbl_803E6B30);
        Sfx_PlayFromObject((u32)obj, gHighTopMovementSfxIds);
    }
}
#pragma dont_inline reset

void hightop_getLookTargetYaw(int obj, int mode, int* out)
{
    f32 buf[6];
    HighTopRuntime* p;
    int yaw;
    switch (mode)
    {
    case 2:
        if (dll_2E_func0A(0x11, buf) != 0)
        {
            yaw = getAngle(buf[3] - ((GameObject*)obj)->anim.localPosX, buf[5] - ((GameObject*)obj)->anim.localPosZ);
            *out = yaw + gHighTopLookYawOffset;
            p = ((GameObject*)obj)->extra;
            p->lookTargetX = buf[3];
            p->lookTargetY = buf[4];
            p->lookTargetZ = buf[5];
        }
        else
        {
            *out = ((GameObject*)obj)->anim.rotX + 0x4000;
        }
        break;
    case 3:
        *out = 1;
        break;
    case 4:
        *out = 0;
        break;
    }
}

void hightop_renderGroundMarker(int obj, f32 scale)
{
    f32* mtx;
    f32 lx, ly, lz;
    ObjPosParams pos;
    mtx = ObjPath_GetPointModelMtx(obj, 2);
    ObjPath_GetPointLocalPosition(obj, 2, &lx, &ly, &lz);
    pos.x = lx;
    pos.y = ly;
    pos.z = lz;
    pos.rx = -0x8000;
    pos.ry = 0;
    pos.rz = 0;
    pos.scale = scale / ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    setMatrixFromObjectPos(gHighTopGroundMarkerMtx, &pos);
    mtx44_mult(gHighTopGroundMarkerMtx, mtx, gHighTopGroundMarkerMtx);
    fn_8003B950(gHighTopGroundMarkerMtx);
}

void hightop_render(void* obj, int p2, int p3, int p4, int p5, char visible)
{
    HighTopRuntime* runtime = ((HighTopObject*)obj)->runtime;
    if (visible != 0)
    {
        int count;
        int** list;
        int i;
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6AB8);
        ObjPath_GetPointWorldPosition((int)obj, 2, &runtime->pathPoint2X, &runtime->pathPoint2Y, &runtime->pathPoint2Z,
                                      0);
        ObjPath_GetPointWorldPositionArray((int)obj, 3, 4, runtime->pathPointWorldPositions);
        ObjPath_GetPointWorldPosition((int)obj, 0, &runtime->pathPoint0X, &runtime->pathPoint0Y, &runtime->pathPoint0Z,
                                      0);
        runtime->flagsC49.b5 = 1;
        dll_2E_func06((int)obj, runtime->lookController, 0);
        if (runtime->flagsC49.b1 != 0)
        {
            int** t = (int**)ObjGroup_GetObjects(55, &count);
            for (i = 0, list = t; i < count; i++)
            {
                int idx = (*(int (**)(int*))((char*)**(int***)((char*)*list + 0x68) + 0x24))(*list);
                void (*dispatch)(int*, void*, int, int, int, int, int) =
                    *(void (**)(int*, void*, int, int, int, int, int))((char*)**(int***)((char*)*list + 0x68) + 0x20);
                dispatch(*list, obj, lbl_8032AB48[idx], p2, p3, p4, p5);
                list++;
            }
        }
    }
    else
    {
        runtime->flagsC49.b5 = 0;
    }
}

void hightop_init(void* obj, u8* arg)
{
    u8* base = lbl_8032AAB0;
    HighTopRuntime* runtime = ((GameObject*)obj)->extra;
    u8* pathState;
    int* node;
    HtInitData local1;
    HtInitData local2;
    int local8;
    local8 = lbl_803E6AA0;
    local1 = gHighTopLookInitData1;
    local2 = gHighTopLookInitData2;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)arg[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = hightop_interactionCallback;
    runtime->unkC45 = arg[0x19];
    runtime->turnRateThreshold = 5;
    *(s8*)&runtime->substate = -1;
    node = *(int**)&((GameObject*)obj)->anim.modelState;
    if (node != 0)
    {
        *(int*)&((ObjModelState*)node)->flags |= 0xa10;
    }
    ObjGroup_AddObject((int)obj, 38);
    ObjGroup_AddObject((int)obj, 10);
    (*(void (**)(void*, char*, int, int))((char*)*gPlayerInterface + 4))(obj, (char*)runtime, 11, 1);
    runtime->baddie.gravity = lbl_803E6B4C;
    pathState = (u8*)&runtime->baddie + 4;
    pathState[0x25b] = 1;
    (*gPathControlInterface)->init(pathState, 3, 1024, 0);
    (*gPathControlInterface)->setLocalPointCollision(pathState, 2, &base[0xe8], &lbl_803DC318, 8);
    (*gPathControlInterface)->setup(pathState, 4, &base[0xa8], &base[0xd8], &local8);
    (*gPathControlInterface)->attachObject(obj, pathState);
    dll_2E_func05((int)obj, runtime->lookController, -4551, 23665, 6);
    dll_2E_func08((char*)runtime->lookController, 300, 120);
    dll_2E_func09((char*)runtime->lookController, &local2, &local1, 6);
    runtime->flags |= 2;
    runtime->flags |= 8;
    runtime->airMeterRemaining = *(s16*)(arg + 0x1a);
    runtime->flags |= 1;
    ((GameObject*)obj)->anim.modelInstance->runtimeSourceHitMask = 127;
    runtime->flagsC49.b4 = 0;
    runtime->flagsC49.b7 = 0;
    gHighTopAirMeterInitValue = *(s16*)(arg + 0x1a);
    if (*(s16*)(arg + 0x1c) == 0)
    {
        runtime->unkC28 = lbl_803E6B50;
    }
    else
    {
        runtime->unkC28 = (f32) * (s16*)(arg + 0x1c) / lbl_803E6B54;
    }
    runtime->flagsC49.b6 = 0;
    runtime->flagsC4A.b0 = 0;
}

int hightop_stateHandler08(int obj, u8* stateArg)
{
    HighTopRuntime* state = ((GameObject*)obj)->extra;
    if ((s8)((BaddieState*)stateArg)->moveJustStartedA != 0)
    {
        f32 zero;
        state->stateTimer = lbl_803E6AB4;
        zero = lbl_803E6AA8;
        ((HighTopRuntime*)stateArg)->baddie.animSpeedC = zero;
        ((HighTopRuntime*)stateArg)->baddie.animSpeedB = zero;
        ((HighTopRuntime*)stateArg)->baddie.animSpeedA = zero;
        ((GameObject*)obj)->anim.velocityX = zero;
        ((GameObject*)obj)->anim.velocityY = zero;
        ((GameObject*)obj)->anim.velocityZ = zero;
    }
    if ((s8)((BaddieState*)stateArg)->moveDone != 0)
    {
        s16 cur = ((GameObject*)obj)->anim.currentMove;
        switch (cur)
        {
        case 10:
            if (((HighTopRuntime*)stateArg)->baddie.moveSpeed > lbl_803E6AA8)
            {
                ObjAnim_SetCurrentMove(obj, 5, lbl_803E6AA8, 0);
            }
            else
            {
                return 8;
            }
            break;
        case 5:
            if (state->stateTimer < lbl_803E6AA8)
            {
                ObjAnim_SetCurrentMove(obj, 10, lbl_803E6AB8, 0);
                ((HighTopRuntime*)stateArg)->baddie.moveSpeed = lbl_803E6ABC;
            }
            break;
        default:
            ObjAnim_SetCurrentMove(obj, 10, lbl_803E6AA8, 0);
            ((HighTopRuntime*)stateArg)->baddie.moveSpeed = lbl_803E6AC0;
            break;
        }
    }
    if (((GameObject*)obj)->anim.currentMove == 10)
    {
        if (((HighTopRuntime*)stateArg)->baddie.moveSpeed < lbl_803E6AA8)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E6AC4)
            {
                ObjAnim_SetCurrentMove(obj, 0, lbl_803E6AA8, 0);
                ((HighTopRuntime*)stateArg)->baddie.moveSpeed = lbl_803E6AC8;
                return 8;
            }
        }
    }
    state->stateTimer -= (f32)(u32)framesThisStep;
    return 0;
}

void hightop_initialise(void)
{
    void** t = gHighTopStateHandlers;
    t[0] = hightop_stateHandler00;
    t[1] = hightop_stateHandler01;
    t[2] = hightop_stateHandler02;
    t[3] = hightop_stateHandler03;
    t[4] = hightop_stateHandler04;
    t[5] = hightop_stateHandler05;
    t[6] = hightop_stateHandler06;
    t[7] = hightop_stateHandler07;
    t[8] = hightop_stateHandler08;
    t[9] = hightop_stateHandler09;
    t[10] = hightop_stateHandler10;
    gHighTopDefaultStateHandler = hightop_defaultStateHandler;
}

#pragma dont_inline on
int hightop_handleMotionEvent(int obj, u8 event)
{
    HighTopRuntime* runtime = ((GameObject*)obj)->extra;
    switch (event)
    {
    case 0:
        break;
    case 5:
        (*(void (**)(int, char*, int))((char*)*gPlayerInterface + 0x14))(obj, (char*)runtime, 8);
        break;
    case 6:
        GameBit_Set(0x634, 1);
        (*gObjectTriggerInterface)->runSequence(4, (void*)obj, -1);
        break;
    case 7:
        GameBit_Set(0x634, 0);
        GameBit_Set(0x631, 1);
        ((GameObject*)obj)->anim.modelInstance->runtimeSourceHitMask |= 1;
        runtime->flagsC40 &= ~0x140;
        runtime->flags &= ~2;
        (*(void (**)(int, char*, int))((char*)*gPlayerInterface + 0x14))(obj, (char*)runtime, 7);
        break;
    case 8:
        (*gObjectTriggerInterface)->runSequence(7, (void*)obj, -1);
        break;
    case 9:
        (*(void (**)(int, char*, int))((char*)*gPlayerInterface + 0x14))(obj, (char*)runtime, 7);
        break;
    }
    return 0;
}
#pragma dont_inline reset

void hightop_hitDetect(int obj)
{
    HighTopRuntime* p = ((GameObject*)obj)->extra;
    f32 l10;
    f32 lc;
    f32 l8;
    int hit;
    s16 st;
    hit = ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &l8, &lc, &l10);
    if (hit == 0)
    {
        return;
    }
    st = p->baddie.controlMode;
    if (st != 4 && (u16)(st - 9) > 1)
    {
        if (hit == 0xf || hit == 0xe)
        {
            return;
        }
    }
    if (p->airMeterRemaining == 0)
    {
        return;
    }
    Obj_SpawnHitLightAndFade(obj, &l8, lbl_803E6B40);
    objSoundFn_800392f0(obj, (int)((char*)p + 0x3bc), &lbl_803DC308 + randomGetRange(0, 0) * 6, 1);
    st = p->baddie.controlMode;
    if (st != 3)
    {
        p->savedControlMode = st;
    }
    st = p->baddie.controlMode;
    if (st == 2 || st == 8)
    {
        p->airMeterRemaining -= 1;
        fn_8009A8C8(obj, lbl_803E6B30);
        if (p->airMeterRemaining <= 0)
        {
            (*gGameUIInterface)->airMeterSetShutdown();
            p->flagsC49.b7 = 0;
            GameBit_Set(0x634, 0);
            if (Obj_IsLoadingLocked() != 0)
            {
                HighTopDeathSpawn* spawn = (HighTopDeathSpawn*)Obj_AllocObjectSetup(0x2c, 0xd4);
                spawn->base.color[0] = 2;
                spawn->base.posX = ((GameObject*)obj)->anim.localPosX;
                spawn->base.posY = ((GameObject*)obj)->anim.localPosY;
                spawn->base.posZ = ((GameObject*)obj)->anim.localPosZ;
                spawn->unk1A = 0x675;
                spawn->unk1C = 0;
                spawn->unk1E = -1;
                Obj_SetupObject((int)spawn, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
            }
            ((GameObject*)obj)->anim.rotY = 0;
            ((GameObject*)obj)->anim.rotZ = 0;
            p->baddie.physicsActive = 0;
            *(int*)p |= 0x1000000;
            GameBit_Set(0xb48, 1);
            (*gGameUIInterface)->airMeterSetShutdown();
        }
    }
    else
    {
        (*(void (**)(int, char*, int))((char*)*gPlayerInterface + 0x14))(obj, (char*)p, 3);
    }
}

void hightop_update(int obj)
{
    char* p = ((GameObject*)obj)->extra;
    ((HighTopRuntime*)p)->turnRateThreshold = 5;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    *(s8*)&((BaddieState*)p)->physicsActive = !((BitFlags8*)(p + 0xc49))->b4;
    ((BaddieState*)p)->hitPoints = 0;
    *(int*)p &= ~0x8000;
    if ((((HighTopRuntime*)p)->flagsC40 & 0x40) != 0)
    {
        int ev = Obj_UpdateRomCurveFollowVelocity(obj, (f32*)(p + 0xa10),
                                                  lbl_803DC324 * (((HighTopRuntime*)p)->unkC28 * timeDelta),
                                                  lbl_803E6B44, lbl_803E6ADC * timeDelta, 0);
        if (ev != 0)
        {
            if (ev == -1)
            {
                ((HighTopRuntime*)p)->flagsC40 &= ~0x140;
                ((HighTopRuntime*)p)->flags &= ~2;
            }
            else
            {
                hightop_handleMotionEvent(obj, ev);
            }
        }
    }
    else
    {
        f32 v = lbl_803E6AA8;
        ((BaddieState*)p)->moveInputX = v;
        ((BaddieState*)p)->moveInputZ = v;
    }
    *(int*)&((BaddieState*)p)->unk31C = 0;
    *(int*)&((BaddieState*)p)->unk318 = 0;
    ((BaddieState*)p)->cameraYaw = 0;
    *(int*)p &= ~0x400000;
    (*(void (**)(int, char*, f32, f32, void**, void*))((char*)*gPlayerInterface + 0x8))(
        obj, p, (f32)(u32)framesThisStep, timeDelta, gHighTopStateHandlers, &gHighTopDefaultStateHandler);
    hightop_playMovementSfx(obj, (int)p, (int)p);
    characterDoEyeAnims(obj, (void*)(p + 0x38c));
    objAnimFn_80038f38(obj, (void*)(p + 0x3bc));
    dll_2E_func03(obj, (void*)(p + 0x3ec));
    if (ObjTrigger_IsSet(obj) != 0)
    {
        s8 v;
        buttonDisable(0, PAD_BUTTON_A);
        v = (s8)((HighTopRuntime*)p)->substate;
        if (v != -1)
        {
            if (v < 0xa)
            {
                (*gObjectTriggerInterface)
                    ->runSequence(v, (void*)obj, -1);
            }
            else
            {
                GameBit_Set(((s16*)((char*)&lbl_803DC314 - 0x14))[v], 1);
            }
        }
    }
    if ((int)randomGetRange(0, 0x64) == 0)
    {
        objSoundFn_800392f0(obj, (int)(p + 0x3bc), &lbl_8032AAB0[randomGetRange(0, 2) * 6], 0);
    }
    if (((BitFlags8*)(p + 0xc49))->b7 != 0)
    {
        (*gGameUIInterface)->runAirMeter(((HighTopRuntime*)p)->airMeterRemaining);
        ((HighTopRuntime*)p)->sfxIntervalTimer += timeDelta;
        if (((HighTopRuntime*)p)->sfxIntervalTimer > *(f32*)&gHighTopAirMeterSfxInterval)
        {
            ((HighTopRuntime*)p)->sfxIntervalTimer -= gHighTopAirMeterSfxInterval;
            Sfx_PlayFromObject((u32)obj, SFXTRIG_hightop_fstep);
        }
    }
}

int hightop_stateHandler01(int obj, int p)
{
    f32 v;
    v = lbl_803E6AA8;
    ((BaddieState*)p)->animSpeedC = v;
    ((BaddieState*)p)->animSpeedB = v;
    ((BaddieState*)p)->animSpeedA = v;
    ((GameObject*)obj)->anim.velocityX = v;
    ((GameObject*)obj)->anim.velocityY = v;
    ((GameObject*)obj)->anim.velocityZ = v;
    *(int*)((char*)p + 0) |= 0x200000;
    if ((s8)((BaddieState*)p)->moveJustStartedA != 0)
    {
        *(s16*)((char*)p + 0x338) = 0;
        ((BaddieState*)p)->moveSpeed = lbl_803E6B24;
        ((BaddieState*)p)->velSmoothTime = lbl_803E6B28;
        if (((GameObject*)obj)->anim.currentMove != gHighTopBandMoveIds)
        {
            ObjAnim_SetCurrentMove(obj, gHighTopBandMoveIds, v, 0);
        }
    }
    if (((BaddieState*)p)->inputMagnitude < lbl_803E6B2C)
    {
        *(s16*)((char*)p + 0x334) = 0;
        ((BaddieState*)p)->turnRate = 0;
        ((BaddieState*)p)->inputMagnitude = *(f32*)&lbl_803E6AA8;
    }
    if (*(f32*)&((BaddieState*)p)->trackedObj > *(f32*)&lbl_803E6AA8 && ((BaddieState*)p)->inputMagnitude > *(f32*)&lbl_803E6AA8)
    {
        return 3;
    }
    return 0;
}

int hightop_stateHandler07(int obj, int p)
{
    HighTopRuntime* rt = ((GameObject*)obj)->extra;
    f32 v;
    if ((s8)((BaddieState*)p)->moveJustStartedA != 0)
    {
        v = lbl_803E6AA8;
        ((BaddieState*)p)->animSpeedC = v;
        ((BaddieState*)p)->animSpeedB = v;
        ((BaddieState*)p)->animSpeedA = v;
        ((GameObject*)obj)->anim.velocityX = v;
        ((GameObject*)obj)->anim.velocityY = v;
        ((GameObject*)obj)->anim.velocityZ = v;
        ObjHits_SyncObjectPositionIfDirty(obj);
        (*gGameUIInterface)->airMeterSetShutdown();
        rt->flagsC49.b7 = 0;
        rt->flagsC49.b1 = 0;
        rt->substate = 5;
        ((BaddieState*)p)->moveSpeed = lbl_803E6AAC;
        rt->flags &= ~1;
        ObjGroup_RemoveObject(obj, 10);
    }
    if ((s8)((BaddieState*)p)->moveDone != 0)
    {
        if (((GameObject*)obj)->anim.currentMove != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6AA8, 0);
            ((BaddieState*)p)->moveSpeed = lbl_803E6AC8;
        }
    }
    if ((s32)randomGetRange(0, 1000) != 0)
    {
        return 0;
    }
    return 9;
}

int hightop_stateHandler04(int obj, int p)
{
    HighTopRuntime* state = ((GameObject*)obj)->extra;
    int move = -1;
    int count;
    int* player;
    if ((s8)((BaddieState*)p)->moveJustStartedA != 0)
    {
        state->flagsC49.b1 = 1;
        state->stateTimer = (f32)(int)randomGetRange(0x1f4, 0x3e8);
        state->substate = 0;
        if (((GameObject*)obj)->anim.currentMove != 2)
        {
            move = 2;
            ((BaddieState*)p)->moveSpeed = lbl_803E6AAC;
        }
        fn_80039264((char*)state + 0xb48);
    }
    count = GameBit_Get(0x9c7) + GameBit_Get(0x9c9) + GameBit_Get(0x9cb) + GameBit_Get(0x9cd);
    if (GameBit_Get(0x62b) != 0)
    {
        HighTopRuntime* state2;
        RomCurveInterface* curve;
        GameBit_Set(0x62f, 1);
        ObjHits_MarkObjectPositionDirty(obj);
        ObjHits_ClearSourceMask(obj, 1);
        ((GameObject*)obj)->anim.modelInstance->runtimeSourceHitMask &= ~1;
        *(s8*)&state->substate = -1;
        state->flagsC40 |= 0x40;
        state->flagsC40 |= 0x20;
        state->flagsC49.b1 = 0;
        ((void (*)(void*, int, int, void*))curve->slotA8)(
            (char*)state + 0xa10, obj, 0x3463a, (curve = *gRomCurveInterface));
        state2 = ((GameObject*)obj)->extra;
        state2->flagsC49.b7 = 1;
        (*gGameUIInterface)->initAirMeter(gHighTopAirMeterInitValue, 0x5ce);
        (*gGameUIInterface)->runAirMeter(state2->airMeterRemaining);
        fn_80039264((char*)state + 0xb48);
        return 7;
    }
    if (count == 4)
    {
        GameBit_Set(0x62a, 1);
        return 0;
    }
    objModelAndSoundFn_80039118(obj, (char*)state + 0xb48);
    state->stateTimer -= (f32)(u32)framesThisStep;
    if (((GameObject*)obj)->anim.currentMove != 9 && ((GameObject*)obj)->anim.currentMove != 0x11)
    {
        RandomTimer_UpdateRangeTrigger((char*)state + 0xc34, lbl_803E6AD8, lbl_803E6ADC);
        if (count == 0)
        {
            if (state->stateTimer < lbl_803E6AA8)
            {
                ((BaddieState*)p)->moveSpeed = lbl_803E6AE0 * count + lbl_803E6AB0;
                move = 9;
                state->stateTimer = (f32)(int)(randomGetRange(0x2bc, 0x3e8) - count * 0x12c);
            }
        }
        else
        {
            if (randFn_80080100((4 - count) * 0xa) != 0)
            {
                ((BaddieState*)p)->moveSpeed = lbl_803E6AE8 * count + lbl_803E6AE4;
                move = 9;
                state->stateTimer = (f32)(int)(randomGetRange(0x2bc, 0x3e8) - count * 0x12c);
            }
        }
    }
    if ((s8)((BaddieState*)p)->moveDone != 0)
    {
        if (((GameObject*)obj)->anim.currentMove != 2)
        {
            move = 2;
            ((BaddieState*)p)->moveSpeed = lbl_803E6AAC;
        }
    }
    if (move != -1)
    {
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x78);
        ObjAnim_SetCurrentMove(obj, move, lbl_803E6AA8, 0);
    }
    player = Obj_GetPlayerObject();
    if (player != 0)
    {
        f32 dy = ((GameObject*)player)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
        if ((dy >= lbl_803E6AA8 ? dy : -dy) < lbl_803E6AEC)
        {
            goto inRange;
        }
        if ((dy >= *(f32*)&lbl_803E6AA8 ? dy : -dy) > lbl_803E6AF0)
        {
        inRange:
            state->flags |= 1;
            if ((int)randomGetRange(0, 0x64) == 0 && ((GameObject*)obj)->anim.currentMove != 9)
            {
                f32 c = ((GameObject*)player)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
                f32 ac = c >= lbl_803E6AA8 ? c : -c;
                if (ac < lbl_803E6AEC)
                {
                    (*gObjectTriggerInterface)->runSequence(9, (void*)obj, -1);
                }
            }
            goto done;
        }
    }
    state->flags &= ~1;
done:
    return 0;
}

int hightop_stateHandler02(int obj, int p, f32 t)
{
    HighTopRuntime* state = ((GameObject*)obj)->extra;
    int cont = 1;
    s16 d336;
    int absd;
    int conv;
    u32 band;
    int idx;
    int changed;
    f32 v;
    f32 lateralSpeed;
    f32 ang;
    f32 moveSpeed;
    s16* vec;
    *(u32*)p = *(u32*)p | 0x200000;
    if (((HighTopRuntime*)p)->baddie.inputMagnitude < lbl_803E6B04)
    {
        *(s16*)((char*)p + 0x334) = 0;
        ((HighTopRuntime*)p)->baddie.turnRate = 0;
        ((HighTopRuntime*)p)->baddie.inputMagnitude = 0.0f;
    }
    d336 = ((HighTopRuntime*)p)->baddie.turnRate;
    if (d336 >= 0)
    {
        absd = d336;
    }
    else
    {
        absd = -d336;
    }
    if (absd > state->turnRateThreshold)
    {
        conv = (int)(gHighTopDegToAngle * ((f32)d336 * t));
        ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + ((s16)conv >> 5));
    }
    else
    {
        ((GameObject*)obj)->anim.rotX = (lbl_803E6B0C * (((f32)d336 * t) / lbl_803E6B10) + (f32) * (s16*)obj);
    }
    conv = (int)(gHighTopDegToAngle * ((f32) * (s16*)((char*)p + 0x336) * t));
    vec = (s16*)objModelGetVecFn_800395d8(obj, 9);
    if (vec != 0)
    {
        vec[1] = (s16)(vec[1] + (((s16)conv - vec[1]) >> 3));
        vec[0] = (s16)(vec[0] + ((-vec[0]) >> 3));
        vec[1] = (vec[1] < -0x1555) ? -0x1555 : ((vec[1] > 0x1555) ? 0x1555 : vec[1]);
        vec[1] = (vec[1] < -0x1555) ? -0x1555 : ((vec[1] > 0x1555) ? 0x1555 : vec[1]);
    }
    v = ((HighTopRuntime*)p)->baddie.inputMagnitude;
    if (v < 0.0f)
    {
        v = 0.0f;
    }
    if (v > lbl_803E6AB8)
    {
        v = lbl_803E6AB8;
    }
    lateralSpeed = lbl_803E6ADC * v;
    if (lateralSpeed < 0.0f)
    {
        lateralSpeed = 0.0f;
    }
    ((HighTopRuntime*)p)->baddie.animSpeedC =
        t * ((lateralSpeed - ((HighTopRuntime*)p)->baddie.animSpeedC) / ((HighTopRuntime*)p)->baddie.velSmoothTime) + ((HighTopRuntime*)p)->baddie.animSpeedC;
    if (((GameObject*)obj)->anim.rotY > 0)
    {
        ang = lateralSpeed - lbl_803E6B14 * mathSinf(gHighTopPi * (f32)((GameObject*)obj)->anim.rotY / lbl_803E6B1C);
    }
    else
    {
        ang = lateralSpeed - lbl_803E6B20 * mathSinf(gHighTopPi * (f32)((GameObject*)obj)->anim.rotY / lbl_803E6B1C);
    }
    ((HighTopRuntime*)p)->baddie.animSpeedA =
        t * ((ang - ((HighTopRuntime*)p)->baddie.animSpeedA) / ((HighTopRuntime*)p)->baddie.velSmoothTime) + ((HighTopRuntime*)p)->baddie.animSpeedA;
    changed = 0;
    moveSpeed = ((GameObject*)obj)->anim.currentMoveProgress;
    band = 0;
    while ((&gHighTopBandMoveIds)[band] != ((GameObject*)obj)->anim.currentMove && band < 2)
    {
        band++;
    }
    if (band >= 2)
    {
        band = 0;
    }
    idx = band * 2;
    while (cont != 0)
    {
        f32 spd = ((HighTopRuntime*)p)->baddie.animSpeedC;
        if (spd < gHighTopBandSpeedThresholds[idx])
        {
            if ((int)band == 1)
            {
                return 2;
            }
            band -= 1;
            idx -= 2;
            changed = 1;
        }
        else if (spd >= gHighTopBandSpeedThresholds[idx + 1])
        {
            if ((int)band == 0)
            {
                moveSpeed = 0.0f;
            }
            band += 1;
            idx += 2;
            changed = 1;
        }
        else
        {
            cont = 0;
        }
    }
    if (changed != 0)
    {
        ObjAnim_SetCurrentMove(obj, (&gHighTopBandMoveIds)[band], moveSpeed, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xa);
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((HighTopRuntime*)p)->baddie.animSpeedA,
                                                                        (f32*)((char*)p + 0x2a0));
    return 0;
}

#pragma opt_common_subs off
int hightop_stateHandler09(int obj, int p)
{
    HighTopRuntime* state = ((GameObject*)obj)->extra;
    int* sub = *(int**)&((GameObject*)obj)->anim.placementData;
    int i;
    int prevCount;
    int* weight;
    int roll;
    int idx;
    if ((s8)((HightopPlacement*)p)->moveJustStartedA != 0 || state->flagsC49.b6 != 0)
    {
        if (state->flagsC4A.b0 == 0)
        {
            state->substate = 0;
        }
        else
        {
            state->substate = 9;
        }
        state->flags &= ~1;
        state->flagsC49.b1 = 0;
        state->idleSeqIndex = 0;
        state->flagsC49.b6 = 0;
        *(u32*)p |= 0x1000000;
        storeZeroToFloatParam((char*)state + 0xc2c);
        ObjHits_EnableObject(obj);
        if (((GameObject*)obj)->anim.currentMove != 2)
        {
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x78);
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E6AA8, 0);
            ((HightopPlacement*)p)->unk2A0 = lbl_803E6AAC;
        }
        ((HightopPlacement*)p)->unk2A0 = lbl_803E6AAC;
        prevCount = GameBit_Get(0x3f0) - 1;
        state->savedControlMode = 9;
        for (i = 0; i < 4; i++)
        {
            GameBit_Set((&gHighTopProgressGameBitIds)[i], i > prevCount);
        }
        if (prevCount == 3)
        {
            GameBit_Set(0x3f4, 1);
            return 0xb;
        }
    }
    if (GameBit_Get(((HightopPlacement*)sub)->gameBitId) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        if (randFn_80080100(0x64) != 0)
        {
            objSoundFn_800392f0(obj, (int)((char*)state + 0x3bc), &lbl_803DC308 + randomGetRange(0, 0) * 6, 1);
        }
        if ((s8)((HightopPlacement*)p)->moveDone != 0)
        {
            if (randFn_80080100(2) != 0)
            {
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x78);
                ObjAnim_SetCurrentMove(obj, 9, lbl_803E6AA8, 0);
                ((HightopPlacement*)p)->unk2A0 = lbl_803E6AB0;
            }
            else
            {
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x78);
                ObjAnim_SetCurrentMove(obj, 2, lbl_803E6AA8, 0);
                ((HightopPlacement*)p)->unk2A0 = lbl_803E6AAC;
            }
        }
        return 0;
    }
    {
        s16 yItem;
        getYButtonItem(&yItem);
        if ((GameBit_Get(0xaf7) != 0 && cMenuGetSelectedItem() != -1) || yItem == 0xaf7)
        {
            Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 4);
        }
        else
        {
            Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 2);
        }
    }
    if (ObjTrigger_IsSetById(obj, 0xaf7) != 0)
    {
        int total = GameBit_Get(0x3f0);
        total = total + GameBit_Get(0xaf7);
        GameBit_Set(0x3f0, total);
        GameBit_Set(0xaf7, 0);
        if (randFn_80080100(5 - total) != 0)
        {
            state->substate = 2;
        }
        else
        {
            state->substate = 9;
        }
        objModelClearVecFn_8003aa40(obj);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0);
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E6AA8, 0);
        ObjHits_DisableObject(obj);
        Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 2);
        (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        return 0;
    }
    if ((s8)((HightopPlacement*)p)->moveDone != 0)
    {
        if (((GameObject*)obj)->anim.currentMove != 2)
        {
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x78);
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E6AA8, 0);
            ((HightopPlacement*)p)->unk2A0 = lbl_803E6AAC;
        }
    }
    if (fn_80080150((char*)state + 0xc2c) != 0)
    {
        if (timerCountDown((char*)state + 0xc2c) != 0)
        {
            *(s8*)&state->substate = -1;
            (*gObjectTriggerInterface)->runSequence(gHighTopIdleSequenceIds[state->idleSeqIndex], (void*)obj, -1);
        }
    }
    else
    {
        if (Vec_distance((f32*)((char*)Obj_GetPlayerObject() + 0x18), &((GameObject*)obj)->anim.worldPosX) >
            lbl_803E6AA4)
        {
            if (randFn_80080100(0x1f4) != 0)
            {
                roll = randomGetRange(0, 0x64);
                idx = 0;
                weight = gHighTopIdleSequenceWeights;
                while (*weight < roll)
                {
                    weight++;
                    roll -= gHighTopIdleSequenceWeights[idx++];
                }
                state->idleSeqIndex = idx;
                state->flags |= 1;
                s16toFloat((char*)state + 0xc2c, 0x14);
            }
        }
    }
    return 0;
}
#pragma opt_common_subs reset

#pragma opt_strength_reduction off
int hightop_stateHandler10(int obj, int p)
{
    HighTopRuntime* rt = ((GameObject*)obj)->extra;
    int* weight;
    int r;
    int i;
    if ((s8)((BaddieState*)p)->moveJustStartedA != 0)
    {
        rt->substate = 3;
        *(int*)((char*)p + 0) |= 0x1000000;
    }
    if (GameBit_Get(0x1c3) != 0)
    {
        if ((int)GameBit_Get(0xee) == 2)
        {
            rt->substate = 7;
        }
        else
        {
            rt->substate = 9;
        }
    }
    else
    {
        rt->substate = 3;
    }
    if (Vec_distance((f32*)((char*)Obj_GetPlayerObject() + 0x18), &((GameObject*)obj)->anim.worldPosX) > lbl_803E6AA4)
    {
        if (randFn_80080100(500) != 0)
        {
            r = randomGetRange(0, 100);
            i = 0;
            weight = gHighTopIdleSequenceWeights;
            while (*weight < r)
            {
                weight++;
                r -= gHighTopIdleSequenceWeights[i++];
            }
            (*gObjectTriggerInterface)
                ->runSequence(gHighTopIdleSequenceIds[i], (void*)obj, -1);
        }
    }
    return 0;
}
#pragma opt_strength_reduction reset

int gHighTopIdleSequenceIds[3] = { 0x4, 0x5, 0x6 };
int gHighTopIdleSequenceWeights[3] = { 0x32, 0x19, 0x19 };
int lbl_8032AB48[26] = { 0x8, 0x9, 0x7, 0xA, -1043857408, 0x0, -1032847360, 0x41C80000, 0x0, -1032847360, 0x41C80000, 0x0, 0x42700000, -1043857408, 0x0, 0x42700000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x420C0000, 0x0, 0x0, -1039400960 };
f32 gHighTopBandSpeedThresholds[4] = { 0.0f, 0.03f, 0.05f, 8.0f };
