#include "main/dll/objfsa_romcurve.h"
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"

typedef struct KtrexMsgBlob
{
    int w[4];
} KtrexMsgBlob;


typedef struct KTRexWork
{
    s16 unk0;
    s16 unk2;
    s16 unk4;
    u8 pad6[0x8 - 0x6];
    f32 unk8;
    f32 posX; /* 0xC */
    f32 posY; /* 0x10 */
    f32 posZ; /* 0x14 */
} KTRexWork;


typedef struct KtrexPlacement
{
    u8 pad0[0x38 - 0x0];
    f32 unk38;
    u8 pad3C[0x40 - 0x3C];
} KtrexPlacement;


typedef struct KtrexState
{
    u8 pad0[0x38 - 0x0];
    f32 unk38;
    u8 pad3C[0x274 - 0x3C];
    s16 unk274;
    u8 pad276[0x5A4 - 0x276];
} KtrexState;


/*
 * KT Rex boss arena state, allocated alongside the runtime and linked at
 * runtime+0x40c (gKTRexState points at it).
 */
typedef struct KTRexArenaState
{
    int stack; /* allocModelStruct stack handle */
    f32 stateTimer;
    f32 laneLerpT; /* 0x8: interpolation t along the lane path: pos = A + t*(B-A) */
    int lastPhase;
    f32 laneAX[4]; /* 0x10: per-lane rom-curve points, one f32[4] per plane */
    f32 laneAY[4]; /* 0x20 */
    f32 laneAZ[4]; /* 0x30 */
    f32 laneBX[4]; /* 0x40 */
    f32 laneBY[4]; /* 0x50 */
    f32 laneBZ[4]; /* 0x60 */
    f32 laneCX[4]; /* 0x70 */
    f32 laneCY[4]; /* 0x80 */
    f32 laneCZ[4]; /* 0x90 */
    f32 laneDX[4]; /* 0xa0 */
    f32 laneDY[4]; /* 0xb0 */
    f32 laneDZ[4]; /* 0xc0 */
    void* rowAX; /* 0xd0: &laneAX */
    void* rowAY;
    void* rowAZ;
    void* rowBX;
    void* rowBY;
    void* rowBZ;
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 unkF4;
    s16 homeYaw; /* 0xf8: spawn heading */
    u16 timerFA;
    u8 laneIndex;
    u8 moveVariant; /* 0xFD: 0/1 charge-attack move/curve selector, indexes lbl_803DC260/lbl_8032A51C */
    u8 unkFE;
    u8 unkFF;
    u8 laneMode; /* 0x100: 1/2 z-lanes, 4/8 x-lanes */
    u8 phaseCounter; /* 0x101: arena phase/stage counter (published to GameBit 0x572/1394) */
    u8 phaseCountdown;
    u8 pathCountdown;
    u32 phaseFlags; /* 0x104: arena phase progression bits */
    u8 unk108;
    u8 pad109[0x23];
    f32 unk12C;
    u8 pad130[0x14];
    f32 unk144;
    u8 pad148[0x24];
    f32 vecX;
    f32 vecY;
    f32 vecZ;
    void* light; /* 0x178 */
} KTRexArenaState;

STATIC_ASSERT(offsetof(KTRexArenaState, light) == 0x178);

/* Per-object extra block for the KT Rex boss (ktrex_getExtraSize == 0x5a4). */
typedef struct KTRexRuntime
{
    u8 pad000[0x25f];
    u8 unk25F;
    u8 pad260[0x10];
    s16 unk270;
    u8 pad272[8];
    u8 moveJustStartedA; /* 0x27A: baddie one-shot, gates per-state move setup (BaddieState.moveJustStartedA) */
    u8 unk27B; /* player-control handoff latch (BaddieState.moveJustStartedB @ 0x27B) */
    u8 pad27C[4];
    f32 unk280;
    f32 unk284;
    u8 pad288[0xc];
    f32 unk294;
    u8 pad298[8];
    f32 curvePhase;
    u8 pad2A4[0x1c];
    f32 unk2C0;
    u8 pad2C4[0xc];
    void* unk2D0;
    u8 pad2D4[0x40];
    int handlerState; /* 0x314 */
    u8 pad318[0x2e];
    u8 moveDone; /* 0x346: set when current move completes; state handlers advance off it (BaddieState.moveDone) */
    u8 pad347[2];
    u8 unk349;
    u8 pad34A[2];
    s8 unk34C;
    u8 pad34D[2];
    s8 unk34F;
    u8 pad350[4];
    u8 hitCountdown;
    u8 pad355[0x93];
    f32 unk3E8;
    f32 unk3EC;
    u8 pad3F0[4];
    s16 unk3F4;
    u8 pad3F6[0x16];
    KTRexArenaState* arena; /* 0x40c: gKTRexState */
} KTRexRuntime;

STATIC_ASSERT(offsetof(KTRexRuntime, arena) == 0x40c);

static inline f32* KTRex_GetActiveContactPointTable(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    u8* model = (u8*)objAnim->banks[objAnim->bankIndex];
    return *(f32**)(model + 0x50);
}

int ktrex_stateHandlerA00(void) { return 0x0; }

void ktrex_func0B(void)
{
}

int ktrex_getExtraSize(void) { return 0x5a4; }

int ktrex_getObjectTypeId(void) { return 0x49; }

void ktrex_release(void)
{
}

int ktrex_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 4;
            break;
        case 2:
            *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 8;
            break;
        case 3:
            *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x800;
            break;
        case 4:
            *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x1000;
            break;
        case 5:
            *(u32*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x20000LL;
            break;
        case 6:
            if (((KTRexArenaState*)gKTRexState)->light != NULL)
            {
                ModelLightStruct_free(((KTRexArenaState*)gKTRexState)->light);
                ((KTRexArenaState*)gKTRexState)->light = NULL;
            }
            break;
        }
    }
    ktrex_updateAttackEffects(obj);
    if (((GameObject*)obj)->unkF8 == 0)
    {
        ((GameObject*)obj)->unkF8 = 1;
    }
    else if (((GameObject*)obj)->unkF8 == 3)
    {
        ((GameObject*)obj)->unkF8 = 4;
    }
    return 0;
}

#pragma dont_inline on
void ktrex_spawnRandomEnergyArc(int obj, int angle, f32 arcLen, int slot)
{
    int* model;
    f32 point1[3];
    f32 point2[3];
    f32 localPoint[3];

    if (((void**)((char*)gKTRexState + 0x17c))[slot] != NULL)
    {
        mm_free(((void**)((char*)gKTRexState + 0x17c))[slot]);
        ((void**)((char*)gKTRexState + 0x17c))[slot] = NULL;
    }
    model = Obj_GetActiveModel(obj);
    localPoint[0] = lbl_803E67B8;
    localPoint[1] = lbl_803E67B8;
    localPoint[2] = lbl_803E67B8;

    PSMTXMultVec(ObjModel_GetJointMatrix(model, randomGetRange(0, *(u8*)(*(int*)model + 0xf3) - 1)),
                 localPoint, point1);
    point1[0] = point1[0] + playerMapOffsetX;
    point1[1] = point1[1] + lbl_803E67BC;
    point1[2] = point1[2] + playerMapOffsetZ;

    PSMTXMultVec(ObjModel_GetJointMatrix(model, randomGetRange(0, *(u8*)(*(int*)model + 0xf3) - 1)),
                 localPoint, point2);
    point2[0] = point2[0] + playerMapOffsetX;
    point2[2] = point2[2] + playerMapOffsetZ;

    ((void**)((char*)gKTRexState + 0x17c))[slot] =
        lightningCreate(point1, point2, lbl_803E67B4, lbl_803E67C0, angle, 96, 0);
}
#pragma dont_inline reset

int ktrex_stateHandlerA06(int obj, int runtime)
{
    int slot;
    if (*(s8*)&((KTRexRuntime*)runtime)->unk27B != 0)
    {
        (*(void (**)(int, int, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 5);
    }
    else if (*(s8*)&((KTRexRuntime*)runtime)->moveDone != 0)
    {
        slot = 0;
        if (Stack_IsEmpty(((KTRexArenaState*)gKTRexState)->stack) == 0)
        {
            Stack_Pop(((KTRexArenaState*)gKTRexState)->stack, &slot);
        }
        return slot + 1;
    }
    return 0;
}

#pragma dont_inline on
int ktrex_isPlayerInLaneThreatRange(int obj)
{
    u8 state = ((KTRexArenaState*)gKTRexState)->laneMode;
    f32 center;
    f32 lo;
    f32 hi;
    if (state == 0)
    {
        return 0;
    }
    switch (state)
    {
    case 1:
    case 2:
        center = ((GameObject*)obj)->anim.localPosZ;
        lo = (center - gKTRexLaneThreatHalfWidth) - *(f32*)((char*)gKTRexMapBlock + 0x28);
        hi = (gKTRexLaneThreatHalfWidth + center) - *(f32*)((char*)gKTRexMapBlock + 0x28);
        if (lo > lbl_803E6840 || hi < lbl_803E6840)
        {
            return 0;
        }
        return 1;
    case 4:
    case 8:
        center = ((GameObject*)obj)->anim.localPosX;
        lo = (center - gKTRexLaneThreatHalfWidth) - *(f32*)((char*)gKTRexMapBlock + 0x24);
        hi = (gKTRexLaneThreatHalfWidth + center) - *(f32*)((char*)gKTRexMapBlock + 0x24);
        if (lo > lbl_803E6844 || hi < lbl_803E6844)
        {
            return 0;
        }
        return 1;
    }
    return 0;
}
#pragma dont_inline reset

int ktrex_setScale(int obj)
{
    void* p = ((GameObject*)obj)->extra;
    gKTRexRuntime = p;
    return ((KtrexState*)p)->unk274;
}

void ktrex_initialise(void)
{
    ktrex_initialiseStateHandlerTables();
}

int ktrex_stateHandlerB00(int obj, u8* p2)
{
    if ((s8)p2[0x27a] != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E67B8, 0);
    }
    *(f32*)(p2 + 0x2a0) = lbl_803E6808;
    return 0;
}

void ktrex_hitDetect(int obj)
{
    f32 z, y, x;
    if (((KTRexArenaState*)gKTRexState)->light != 0)
    {
        ObjPath_GetPointWorldPosition(obj, 5, &x, &y, &z, 0);
        modelLightStruct_setPosition(((KTRexArenaState*)gKTRexState)->light, x, y, z);
        modelLightStruct_updateGlowAlpha(((KTRexArenaState*)gKTRexState)->light);
    }
}

void ktrex_free(int obj)
{
    int i;
    gKTRexRuntime = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 0x3);
    (*(void (**)(int, void*, int))((char*)*gBaddieControlInterface + 0x40))(obj, gKTRexRuntime, 0);
    Stack_Free(*(void**)gKTRexState);
    if (gKTRexResource != NULL)
    {
        Resource_Release(gKTRexResource);
    }
    if (((KTRexArenaState*)gKTRexState)->light != 0)
    {
        ModelLightStruct_free(((KTRexArenaState*)gKTRexState)->light);
    }
    for (i = 0; i < 5; i++)
    {
        void* m = *(void**)((char*)gKTRexState + i * 4 + 0x17c);
        if (m != 0)
        {
            mm_free(m);
        }
    }
    gKTRexResource = NULL;
    Music_Trigger(0x28, 0);
    Music_Trigger(0x93, 0);
    Music_Trigger(0x94, 0);
}

int ktrex_shouldAdvanceArenaPhase(void)
{
    u8 a;
    u8 b;
    KTRexArenaState* s = (KTRexArenaState*)gKTRexState;
    int r6;
    r6 = s->timerFA & 1;
    a = s->unkFE;
    b = s->unkFF;
    if ((a & b) != 0)
    {
        if (r6 != 0)
        {
            if (s->laneLerpT < s->unkF4)
            {
                return 1;
            }
        }
        else
        {
            if (s->laneLerpT > s->unkF4)
            {
                return 1;
            }
        }
        return 0;
    }
    if (r6 != 0)
    {
        if ((a == 8 && (b & 1)) || (a == 2 && (b & 8)) || (a == 4 && (b & 2)) || (a == 1 && (b & 4)))
        {
            return 1;
        }
        return 0;
    }
    if ((a == 1 && (b & 8)) || (a == 4 && (b & 1)) || (a == 2 && (b & 4)) || (a == 8 && (b & 2)))
    {
        return 1;
    }
    return 0;
}

void ktrex_initialiseStateHandlerTables(void)
{
    gKTRexStateHandlersB[0] = ktrex_stateHandlerB00;
    gKTRexStateHandlersB[1] = ktrex_stateHandlerB01;
    gKTRexStateHandlersB[2] = ktrex_stateHandlerB02;
    gKTRexStateHandlersB[3] = ktrex_stateHandlerB03;
    gKTRexStateHandlersB[4] = ktrex_stateHandlerB04;
    gKTRexStateHandlersB[5] = ktrex_stateHandlerB05;
    gKTRexStateHandlersB[6] = ktrex_stateHandlerB06;
    gKTRexStateHandlersB[7] = ktrex_stateHandlerB07;
    gKTRexStateHandlersB[8] = ktrex_stateHandlerB08;
    gKTRexStateHandlersA[0] = ktrex_stateHandlerA00;
    gKTRexStateHandlersA[1] = ktrex_stateHandlerA01;
    gKTRexStateHandlersA[2] = ktrex_stateHandlerA02;
    gKTRexStateHandlersA[3] = ktrex_stateHandlerA03;
    gKTRexStateHandlersA[4] = ktrex_stateHandlerA04;
    gKTRexStateHandlersA[5] = ktrex_stateHandlerA05;
    gKTRexStateHandlersA[6] = ktrex_stateHandlerA06;
    gKTRexStateHandlersA[7] = ktrex_stateHandlerA07;
    gKTRexStateHandlersA[8] = ktrex_stateHandlerA08;
    gKTRexStateHandlersA[9] = ktrex_stateHandlerA09;
    gKTRexStateHandlersA[10] = ktrex_stateHandlerA10;
    gKTRexStateHandlersA[11] = ktrex_stateHandlerA11;
}

int ktrex_updateArenaPathProgress(int obj)
{
    u16 flags;
    int phase;
    int dir;
    f32 speed;
    int changed;

    changed = 0;
    flags = ((KTRexArenaState*)gKTRexState)->timerFA;
    dir = flags & 1;
    phase = (flags >> 1) & 3;
    if (dir != 0)
    {
        speed = -*(f32*)((char*)obj + 0x294);
    }
    else
    {
        speed = *(f32*)((char*)obj + 0x294);
    }
    ((KTRexArenaState*)gKTRexState)->laneLerpT = speed * timeDelta + ((KTRexArenaState*)gKTRexState)->laneLerpT;
    if ((((KTRexArenaState*)gKTRexState)->laneLerpT > gKTRexLaneSpeedMax[((KTRexArenaState*)gKTRexState)->laneIndex] && speed >
            lbl_803E67B8) ||
        (((KTRexArenaState*)gKTRexState)->laneLerpT<gKTRexLaneSpeedMin[((KTRexArenaState*)gKTRexState)->laneIndex] && speed <
            lbl_803E67B8))
    {
        if (dir != 0)
        {
            phase--;
            if (phase < 0)
            {
                phase = 3;
            }
        }
        else
        {
            phase++;
            if (phase >= 4)
            {
                phase = 0;
            }
        }
        ((KTRexArenaState*)gKTRexState)->timerFA = ((KTRexArenaState*)gKTRexState)->timerFA & ~6;
        ((KTRexArenaState*)gKTRexState)->timerFA = ((KTRexArenaState*)gKTRexState)->timerFA | (phase << 1);
        if (((KTRexArenaState*)gKTRexState)->laneLerpT > gKTRexLaneSpeedMax[((KTRexArenaState*)gKTRexState)->laneIndex])
        {
            ((KTRexArenaState*)gKTRexState)->laneLerpT = gKTRexLaneSpeedMax[((KTRexArenaState*)gKTRexState)->laneIndex];
        }
        else if (((KTRexArenaState*)gKTRexState)->laneLerpT<gKTRexLaneSpeedMin[((KTRexArenaState*)gKTRexState)->laneIndex])
        {
            ((KTRexArenaState*)gKTRexState)->laneLerpT = gKTRexLaneSpeedMin[((KTRexArenaState*)gKTRexState)->laneIndex];
        }
        changed = 1;
    }
    ((KTRexArenaState*)gKTRexState)->posX = ((KTRexArenaState*)gKTRexState)->laneLerpT * (((f32*)*(int*)&((KTRexArenaState*)
        gKTRexState)->rowBX)[phase] - ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)->rowAX)[phase]) + ((f32*)*(int*)&((
        KTRexArenaState*)gKTRexState)->rowAX)[phase];
    ((KTRexArenaState*)gKTRexState)->posY = ((KTRexArenaState*)gKTRexState)->laneLerpT * (((f32*)*(int*)&((KTRexArenaState*)
        gKTRexState)->rowBY)[phase] - ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)->rowAY)[phase]) + ((f32*)*(int*)&((
        KTRexArenaState*)gKTRexState)->rowAY)[phase];
    ((KTRexArenaState*)gKTRexState)->posZ = ((KTRexArenaState*)gKTRexState)->laneLerpT * (((f32*)*(int*)&((KTRexArenaState*)
        gKTRexState)->rowBZ)[phase] - ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)->rowAZ)[phase]) + ((f32*)*(int*)&((
        KTRexArenaState*)gKTRexState)->rowAZ)[phase];
    return changed;
}

void ktrex_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    f32 m[12];
    void* e;
    int i;

    gKTRexRuntime = ((GameObject*)obj)->extra;
    if (visible == 0)
    {
        return;
    }
    switch (((GameObject*)obj)->unkF4)
    {
    case 0:
        break;
    default:
        return;
    }
    if (((KTRexArenaState*)gKTRexState)->light != NULL)
    {
        queueGlowRender(((KTRexArenaState*)gKTRexState)->light);
    }
    for (i = 0; i < 5; i++)
    {
        e = *(void**)((char*)gKTRexState + 380 + i * 4);
        if (e != NULL)
        {
            lightningRender(e);
            *(u16*)((char*)*(void**)((char*)gKTRexState + 380 + i * 4) + 0x20) =
                (f32)(u32) * (u16*)((char*)*(void**)((char*)gKTRexState + 380 + i * 4) + 0x20) + timeDelta;
            if (*(u16*)((char*)*(void**)((char*)gKTRexState + 380 + i * 4) + 0x20) >=
                *(u16*)((char*)*(void**)((char*)gKTRexState + 380 + i * 4) + 0x22))
            {
                mm_free(*(void**)((char*)gKTRexState + 380 + i * 4));
                *(int*)((char*)gKTRexState + 380 + i * 4) = 0;
            }
        }
    }
    if (((KTRexRuntime*)gKTRexRuntime)->unk3E8 != lbl_803E67B8)
    {
        fn_8003B5E0(200, 0, 0, (int)((KTRexRuntime*)gKTRexRuntime)->unk3E8);
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6818);
    ObjPath_GetPointWorldPosition((int)obj, 1, (f32*)((char*)gKTRexState + 0x130), (f32*)((char*)gKTRexState + 0x134),
                                  (f32*)((char*)gKTRexState + 0x138), 0);
    ObjPath_GetPointWorldPosition((int)obj, 2, (f32*)((char*)gKTRexState + 0x148), (f32*)((char*)gKTRexState + 0x14c),
                                  (f32*)((char*)gKTRexState + 0x150), 0);
    ObjPath_GetPointWorldPosition((int)obj, 3, (f32*)((char*)gKTRexState + 0x160), (f32*)((char*)gKTRexState + 0x164),
                                  (f32*)((char*)gKTRexState + 0x168), 0);
    ObjPath_GetPointWorldPosition((int)obj, 0, (f32*)((char*)gKTRexState + 0x118), (f32*)((char*)gKTRexState + 0x11c),
                                  (f32*)((char*)gKTRexState + 0x120), 0);
    memcpy(m, ObjPath_GetPointModelMtx((int)obj, 4), 48);
    ((KTRexArenaState*)gKTRexState)->vecX = lbl_803E67B4 * (f32)(int)
    randomGetRange(-50, 50);
    ((KTRexArenaState*)gKTRexState)->vecY = lbl_803E67B4 * (f32)(int)
    randomGetRange(60, 120);
    ((KTRexArenaState*)gKTRexState)->vecZ = lbl_803E6848 * (f32)(int)
    randomGetRange(100, 150);
    PSMTXMultVecSR(m, &((KTRexArenaState*)gKTRexState)->vecX, &((KTRexArenaState*)gKTRexState)->vecX);
    *(u32*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x100000LL;
}

#pragma fp_contract off
void ktrex_update(int obj)
{
    void* runtime;
    void* player;
    f32 d[3];
    f32* dp;
    u32 tmp;
    s16* bitA;
    s16* bitB;
    int i;
    u8 maskA;
    u8 maskB;
    u8 flags;
    int phase;
    f32 dx, dz, frac;

    if (((GameObject*)obj)->unkF4 != 0)
    {
        return;
    }
    gKTRexRuntime = ((GameObject*)obj)->extra;
    runtime = gKTRexRuntime;
    if (((GameObject*)obj)->unkF8 == 1)
    {
        Music_Trigger(40, 1);
        ((GameObject*)obj)->unkF8 = 2;
        ((KTRexRuntime*)runtime)->unk270 = 11;
        ((KTRexRuntime*)runtime)->unk27B = 1;
    }
    ObjHits_RegisterActiveHitVolumeObject(obj);
    ((KTRexRuntime*)runtime)->unk2D0 = Obj_GetPlayerObject();
    if (((KTRexRuntime*)runtime)->unk2D0 != NULL)
    {
        player = ((KTRexRuntime*)runtime)->unk2D0;
        dp = d;
        dp[0] = ((GameObject*)player)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        dp[1] = ((GameObject*)player)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        dp[2] = ((GameObject*)player)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        ((KTRexRuntime*)runtime)->unk2C0 = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
    }
    characterDoEyeAnims(obj, (char*)gKTRexRuntime + 0x3ac);
    maskA = 0;
    bitA = lbl_803DC290;
    for (i = 0; i < 4; i++)
    {
        if (GameBit_Get(*bitA) != 0)
        {
            maskA |= 1 << i;
        }
        bitA++;
    }
    ((KTRexArenaState*)gKTRexState)->unkFF = maskA;
    player = ((KTRexRuntime*)runtime)->unk2D0;
    {
        KTRexArenaState* st = (KTRexArenaState*)gKTRexState;
        phase = (st->timerFA >> 1) & 3;
        dz = ((f32*)*(int*)&st->rowBX)[phase] - ((f32*)*(int*)&st->rowAX)[phase];
        dx = ((f32*)*(int*)&st->rowBZ)[phase] - ((f32*)*(int*)&st->rowAZ)[phase];
        if (__fabs(dz) > __fabs(dx))
        {
            frac =
                (((GameObject*)player)->anim.localPosX - ((f32*)*(int*)&st->rowAX)[phase]) /
                dz;
        }
        else
        {
            frac =
                (((GameObject*)player)->anim.localPosZ - ((f32*)*(int*)&st->rowAZ)[phase]) /
                dx;
        }
    }
    ((KTRexArenaState*)gKTRexState)->unkF4 = frac;
    {
        KTRexArenaState* st = (KTRexArenaState*)gKTRexState;
        int t = st->timerFA;
        tmp = lbl_803E67B0;
        st->unkFE = ((u8*)&tmp)[(t >> 1) & 3];
    }
    flags = ((KTRexArenaState*)gKTRexState)->unkFE;
    maskB = 0;
    bitB = lbl_803DC298;
    for (i = 0; i < 4; i++)
    {
        if ((flags & (1 << i)) != 0 && GameBit_Get(*bitB) != 0)
        {
            maskB |= 1 << i;
        }
        bitB++;
    }
    ((KTRexArenaState*)gKTRexState)->laneMode = maskB;
    (*(void (**)(int, void*, void*, int, void*, int, int, int))((char*)*gBaddieControlInterface + 0x54))(
        obj, runtime, (char*)gKTRexRuntime + 0x35c, ((KTRexRuntime*)gKTRexRuntime)->unk3F4,
        (char*)gKTRexRuntime + 0x405, 2, 2, 0);
    ktrex_updateContactEffects(obj, runtime);
    ktrex_updateAttackEffects(obj);
    (*(void (**)(int, void*, f32, int))((char*)*gBaddieControlInterface + 0x2c))(obj, runtime, lbl_803E67B8, 0);
    ObjHits_SetHitVolumeMasks(obj, 24, 2, 0x1fffff);
    (*(void (**)(int, void*, f32, f32, void**, void*))((char*)*gPlayerInterface + 0x8))(
        obj, runtime, timeDelta, timeDelta, gKTRexStateHandlersB, gKTRexStateHandlersA);
    ((GameObject*)obj)->anim.localPosY = ((KTRexArenaState*)gKTRexState)->posY;
}
#pragma fp_contract reset

int ktrex_stateHandlerB05(int obj, int runtime)
{
    f32 z;
    if ((s8)((KTRexRuntime*)runtime)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, (&lbl_803DC250)[((KTRexArenaState*)gKTRexState)->laneIndex], lbl_803E67B8, 0);
        ((KTRexRuntime*)runtime)->curvePhase = lbl_803E6810;
        z = lbl_803E67B8;
        ((KTRexRuntime*)runtime)->unk280 = z;
        ((KTRexRuntime*)runtime)->unk284 = z;
    }
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 1) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~1;
        *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x200;
    }
    return 0;
}

int ktrex_stateHandlerB07(int obj, int runtime)
{
    if ((s8)((KTRexRuntime*)runtime)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 12, lbl_803E67B8, 0);
        ((KTRexRuntime*)runtime)->curvePhase = lbl_803E6808;
    }
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 1) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~1;
        *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x2000;
    }
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 0x80) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~0x80;
        *(u32*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x40000LL;
    }
    return 0;
}

int ktrex_stateHandlerB08(int obj, int runtime)
{
    if ((s8)((KTRexRuntime*)runtime)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 13, lbl_803E67B8, 0);
        ((KTRexRuntime*)runtime)->curvePhase =
            lbl_803E67F4 + lbl_803E67F8 * (f32)(int)(((KTRexArenaState*)gKTRexState)->phaseCounter >> 1);
        Sfx_PlayFromObject(obj, SFXmv_cagesqk11);
    }
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 1) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~1;
        *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x2000;
    }
    return 0;
}

int ktrex_stateHandlerB06(int obj, int runtime)
{
    f32 z;
    if ((s8)((KTRexRuntime*)runtime)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 11, lbl_803E67B8, 0);
        Sfx_PlayFromObject(obj, 1108);
        ((KTRexRuntime*)runtime)->curvePhase = lbl_803E680C;
        z = lbl_803E67B8;
        ((KTRexRuntime*)runtime)->unk280 = z;
        ((KTRexRuntime*)runtime)->unk284 = z;
    }
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 1) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~1;
        *(u32*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x80000LL;
    }
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 0x80) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~0x80;
        *(u32*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x20000LL;
    }
    return 0;
}

int ktrex_stateHandlerB03(int obj, int runtime)
{
    f32 z;
    u16 dir;
    dir = ((KTRexArenaState*)gKTRexState)->timerFA & 1;
    if ((s8)((KTRexRuntime*)runtime)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 15, lbl_803E67B8, 0);
        ((KTRexRuntime*)runtime)->curvePhase = lbl_803E6810;
        z = lbl_803E67B8;
        ((KTRexRuntime*)runtime)->unk280 = z;
        ((KTRexRuntime*)runtime)->unk284 = z;
        ((KTRexArenaState*)gKTRexState)->homeYaw = ((GameObject*)obj)->anim.rotX;
    }
    if (dir != 0)
    {
        ((GameObject*)obj)->anim.rotX = lbl_803E6814 * ((GameObject*)obj)->anim.currentMoveProgress + (f32)(int)(
            (KTRexArenaState*)gKTRexState)->homeYaw;
    }
    else
    {
        ((GameObject*)obj)->anim.rotX = (f32)(int)((KTRexArenaState*)gKTRexState)->homeYaw - lbl_803E6814 * ((GameObject*)obj)->anim.
            currentMoveProgress;
    }
    return 0;
}

int ktrex_stateHandlerB04(int obj, int runtime)
{
    f32 z;
    u16 mask;
    if ((s8)((KTRexRuntime*)runtime)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, (&lbl_803DC260)[((KTRexArenaState*)gKTRexState)->moveVariant], lbl_803E67B8, 0);
        ((KTRexRuntime*)runtime)->curvePhase = lbl_8032A51C[((KTRexArenaState*)gKTRexState)->moveVariant];
        z = lbl_803E67B8;
        ((KTRexRuntime*)runtime)->unk280 = z;
        ((KTRexRuntime*)runtime)->unk284 = z;
    }
    mask = (&lbl_803DC288)[((KTRexArenaState*)gKTRexState)->moveVariant];
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 1) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~1;
        *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= mask;
    }
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 0x200) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~0x200;
        *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x800;
    }
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 0x400) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~0x400;
        *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x1000;
    }
    return 0;
}

int ktrex_stateHandlerB01(int obj, int runtime)
{
    f32 z;
    u16 mask;
    int maskI;
    f32 dx;
    f32 dz;
    if ((s8)((KTRexRuntime*)runtime)->moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, (&lbl_803DC258)[((KTRexArenaState*)gKTRexState)->laneIndex], lbl_803E67B8, 0);
        z = lbl_803E67B8;
        ((KTRexRuntime*)runtime)->unk280 = z;
        ((KTRexRuntime*)runtime)->unk284 = z;
    }
    mask = (&lbl_803DC268)[((KTRexArenaState*)gKTRexState)->laneIndex];
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 4) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~4;
        *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= mask;
    }
    mask = (&lbl_803DC270)[((KTRexArenaState*)gKTRexState)->laneIndex];
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 2) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~2;
        *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= mask;
    }
    if (((KTRexArenaState*)gKTRexState)->unk108 != 0)
    {
        mask = (&lbl_803DC278)[((KTRexArenaState*)gKTRexState)->laneIndex];
    }
    else
    {
        mask = (&lbl_803DC280)[((KTRexArenaState*)gKTRexState)->laneIndex];
    }
    maskI = mask;
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 1) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~1;
        *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= maskI;
    }
    dx = oneOverTimeDelta * (((KTRexArenaState*)gKTRexState)->posX - ((GameObject*)obj)->anim.localPosX);
    dz = oneOverTimeDelta * (((KTRexArenaState*)gKTRexState)->posZ - ((GameObject*)obj)->anim.localPosZ);
    ObjAnim_SampleRootCurvePhase(sqrtf(dx * dx + dz * dz), (ObjAnimComponent*)obj, &((KTRexRuntime*)runtime)->curvePhase);
    ((GameObject*)obj)->anim.localPosX = ((KTRexArenaState*)gKTRexState)->posX;
    ((GameObject*)obj)->anim.localPosZ = ((KTRexArenaState*)gKTRexState)->posZ;
    return 0;
}

int ktrex_stateHandlerB02(int obj, int runtime)
{
    u16 dir;
    f32 tmpY;
    int lane;
    ObjPosParams pos;
    f32 mtx[16];

    dir = ((KTRexArenaState*)gKTRexState)->timerFA & 1;
    if ((s8)((KTRexRuntime*)runtime)->moveJustStartedA != 0)
    {
        lane = ((KTRexArenaState*)gKTRexState)->laneIndex * 2;
        ObjAnim_SetCurrentMove(obj, lbl_8032A510[lane + dir], lbl_803E67B8, 0);
        ((KTRexRuntime*)runtime)->curvePhase = lbl_8032A528[((KTRexArenaState*)gKTRexState)->laneIndex];
        ((KTRexArenaState*)gKTRexState)->homeYaw = ((GameObject*)obj)->anim.rotX;
    }
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 4) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~4;
        *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 1;
    }
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 2) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~2;
        *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 2;
    }
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 1) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~1;
        *(int*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x40;
    }
    if ((((KTRexRuntime*)gKTRexRuntime)->handlerState & 0x80) != 0)
    {
        ((KTRexRuntime*)gKTRexRuntime)->handlerState &= ~0x80;
        *(u32*)&((KTRexArenaState*)gKTRexState)->phaseFlags |= 0x10000LL;
    }
    ((KTRexRuntime*)runtime)->unk34C |= 1;
    (*(void (**)(int, int, f32, int))((char*)*gPlayerInterface + 0x20))(obj, runtime, timeDelta, 3);
    pos.rx = ((KTRexArenaState*)gKTRexState)->homeYaw;
    pos.ry = 0;
    pos.rz = 0;
    pos.scale = lbl_803E6818;
    pos.x = lbl_803E67B8;
    pos.y = lbl_803E67B8;
    pos.z = lbl_803E67B8;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, ((KTRexRuntime*)runtime)->unk284, lbl_803E67B8, -((KTRexRuntime*)runtime)->unk280,
                          &((GameObject*)obj)->anim.velocityX, &tmpY, &((GameObject*)obj)->anim.velocityZ);
    if (dir != 0)
    {
        ((GameObject*)obj)->anim.rotX = lbl_803E681C * ((GameObject*)obj)->anim.currentMoveProgress + (f32)(int)(
            (KTRexArenaState*)gKTRexState)->homeYaw;
    }
    else
    {
        ((GameObject*)obj)->anim.rotX = (f32)(int)((KTRexArenaState*)gKTRexState)->homeYaw - lbl_803E681C * ((GameObject*)obj)->anim.
            currentMoveProgress;
    }
    return 0;
}

void ktrex_init(int obj, char* arg, int flag)
{
    int* pA;
    int* pB;
    int* pC;
    int* base = (int*)lbl_8032A510;
    KTRexRuntime* rt;
    int i;
    ObjfsaRomCurveDef* cp;
    u8 spawnFlags;
    s16 yaw;
    gKTRexRuntime = ((GameObject*)obj)->extra;
    spawnFlags = 0x10;
    if (flag != 0)
    {
        spawnFlags |= 1;
    }
    (*(void (**)(int, char*, void*, int, int, int, u8, f32))((char*)*gBaddieControlInterface + 0x58))(
        obj, arg, gKTRexRuntime, 9, 0xc, 0x100, spawnFlags, lbl_803E684C);
    ((GameObject*)obj)->animEventCallback = ktrex_animEventCallback;
    rt = (KTRexRuntime*)gKTRexRuntime;
    (*(void (**)(int, void*, int))((char*)*gPlayerInterface + 0x14))(obj, rt, 0);
    rt->unk270 = 2;
    *(int*)&rt->unk2D0 = 0;
    rt->unk25F = 0;
    rt->unk349 = 0;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x88;
    ObjHits_EnableObject(obj);
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0x810;
    }
    gKTRexState = ((KTRexRuntime*)gKTRexRuntime)->arena;
    ((KTRexArenaState*)gKTRexState)->stack = allocModelStruct_800139e8(4, 4);
    yaw = (s16)((s8)arg[0x2a] << 8);
    ((GameObject*)obj)->anim.rotX = yaw;
    ((KTRexArenaState*)gKTRexState)->homeYaw = yaw;
    pA = base + 0x4c / 4;
    pB = base + 0x3c / 4;
    pC = base + 0x6c / 4;
    base = base + 0x5c / 4;
    for (i = 0; i < 4; i++)
    {
        cp = (ObjfsaRomCurveDef*)(*gRomCurveInterface)->getById(*pA);
        if (cp != NULL)
        {
            ((KTRexArenaState*)gKTRexState)->laneAX[i] = cp->x;
            ((KTRexArenaState*)gKTRexState)->laneAY[i] = cp->y;
            ((KTRexArenaState*)gKTRexState)->laneAZ[i] = cp->z;
            cp = (ObjfsaRomCurveDef*)(*gRomCurveInterface)->getById(*pB);
            ((KTRexArenaState*)gKTRexState)->laneBX[i] = cp->x;
            ((KTRexArenaState*)gKTRexState)->laneBY[i] = cp->y;
            ((KTRexArenaState*)gKTRexState)->laneBZ[i] = cp->z;
            cp = (ObjfsaRomCurveDef*)(*gRomCurveInterface)->getById(*pC);
            ((KTRexArenaState*)gKTRexState)->laneCX[i] = cp->x;
            ((KTRexArenaState*)gKTRexState)->laneCY[i] = cp->y;
            ((KTRexArenaState*)gKTRexState)->laneCZ[i] = cp->z;
            cp = (ObjfsaRomCurveDef*)(*gRomCurveInterface)->getById(*base);
            ((KTRexArenaState*)gKTRexState)->laneDX[i] = cp->x;
            ((KTRexArenaState*)gKTRexState)->laneDY[i] = cp->y;
            ((KTRexArenaState*)gKTRexState)->laneDZ[i] = cp->z;
        }
        pA++;
        pB++;
        pC++;
        base++;
    }
    ((KTRexArenaState*)gKTRexState)->rowAX = (char*)gKTRexState + 0x10;
    ((KTRexArenaState*)gKTRexState)->rowAY = (char*)gKTRexState + 0x20;
    ((KTRexArenaState*)gKTRexState)->rowAZ = (char*)gKTRexState + 0x30;
    ((KTRexArenaState*)gKTRexState)->rowBX = (char*)gKTRexState + 0x40;
    ((KTRexArenaState*)gKTRexState)->rowBY = (char*)gKTRexState + 0x50;
    ((KTRexArenaState*)gKTRexState)->rowBZ = (char*)gKTRexState + 0x60;
    ((KTRexArenaState*)gKTRexState)->phaseCountdown = 4;
    rt->hitCountdown = 3;
    gKTRexResource = Resource_Acquire(0x5a, 1);
    ((GameObject*)obj)->unkF8 = 0;
    gKTRexMapBlock = (void*)mapBlockFn_800592e4();
    ((KTRexArenaState*)gKTRexState)->light = objCreateLight(0, 1);
    if (((KTRexArenaState*)gKTRexState)->light != 0)
    {
        modelLightStruct_setLightKind(((KTRexArenaState*)gKTRexState)->light, 2);
        modelLightStruct_setPosition(((KTRexArenaState*)gKTRexState)->light, ((GameObject*)obj)->anim.localPosX,
                                     ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ);
        modelLightStruct_setDiffuseColor(((KTRexArenaState*)gKTRexState)->light, 0xff, 0, 0, 0);
        modelLightStruct_setDistanceAttenuation(((KTRexArenaState*)gKTRexState)->light, lbl_803E6850, lbl_803E67F0);
        modelLightStruct_setupGlow(((KTRexArenaState*)gKTRexState)->light, 0, 0xff, 0, 0, 0x50, lbl_803E67F0);
        modelLightStruct_setGlowProjectionRadius(((KTRexArenaState*)gKTRexState)->light, lbl_803E67BC);
    }
    streamFn_8000a380(3, 2, 0x1f4);
}

void ktrex_updateAttackEffects(int obj)
{
    int i;
    f32 mag;
    mag = lbl_803E6818 - ((KTRexRuntime*)gKTRexRuntime)->unk2C0 / lbl_803E6824;
    if (mag < lbl_803E67B8)
    {
        mag = lbl_803E67B8;
    }
    else if (mag > lbl_803E6818)
    {
        mag = lbl_803E6818;
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x40) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_bodyf4_c);
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x80) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_cagerat01);
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x100) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_cagesqk11);
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x200) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_canras_c);
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x10000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_cogstr_c);
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x40000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_curtainopen16);
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x80000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_deaththud16);
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x2000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_deaththud16);
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x1000) != 0)
    {
        ((KTRexArenaState*)gKTRexState)->phaseFlags &= ~0x1800LL;
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x20000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_cogstr_c);
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E67C8 * mag);
    }
    if ((((KTRexArenaState*)gKTRexState)->timerFA & 0x10) != 0)
    {
        for (i = 0; i < 5; i++)
        {
            if ((int)randomGetRange(0, 5) == 0 && *(void**)((char*)gKTRexState + i * 4 + 0x17c) == NULL)
            {
                ktrex_spawnRandomEnergyArc(obj, randomGetRange(8, 0xc), lbl_803E6828, i);
            }
        }
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x4000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_dive4_c);
        ((KTRexArenaState*)gKTRexState)->unk108 ^= 1;
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x8000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_gdtur2_c);
        ((KTRexArenaState*)gKTRexState)->unk108 ^= 1;
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x3) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_icesmash16);
        doRumble(lbl_803E67CC);
        if (mag > lbl_803E67B4)
        {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(mag);
            GameBit_Set(0x554, 1);
        }
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0xc) != 0)
    {
        doRumble(lbl_803E682C);
        Sfx_PlayFromObject(obj, SFXmv_ladderslide16);
        if (mag > lbl_803E67B4)
        {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E67C8 * mag);
            GameBit_Set(0x554, 1);
        }
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x30) != 0)
    {
        doRumble(lbl_803E6830);
        Sfx_PlayFromObject(obj, SFXmv_persquk1);
        if (mag > lbl_803E67B4)
        {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E6834 * mag);
            GameBit_Set(0x554, 1);
        }
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x100000) == 0)
    {
        ((KTRexArenaState*)gKTRexState)->phaseFlags &= 0x1800LL;
        return;
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x1) != 0)
    {
        ((KTRexArenaState*)gKTRexState)->unk12C = lbl_803E6818;
        for (i = 0; i < 10; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x124,
                                             0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x124,
                                             0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, (char*)gKTRexState + 0x124,
                                             0x200001, -1, NULL);
        }
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x2) != 0)
    {
        ((KTRexArenaState*)gKTRexState)->unk144 = lbl_803E6818;
        for (i = 0; i < 10; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x13c,
                                             0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x13c,
                                             0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, (char*)gKTRexState + 0x13c,
                                             0x200001, -1, NULL);
        }
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x4) != 0)
    {
        ((KTRexArenaState*)gKTRexState)->unk12C = lbl_803E6838;
        for (i = 0; i < 13; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x124,
                                             0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x124,
                                             0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, (char*)gKTRexState + 0x124,
                                             0x200001, -1, NULL);
        }
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x8) != 0)
    {
        ((KTRexArenaState*)gKTRexState)->unk144 = lbl_803E6838;
        for (i = 0; i < 13; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x13c,
                                             0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x13c,
                                             0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, (char*)gKTRexState + 0x13c,
                                             0x200001, -1, NULL);
        }
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x10) != 0)
    {
        ((KTRexArenaState*)gKTRexState)->unk12C = lbl_803E67C8;
        for (i = 0; i < 16; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x124,
                                             0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x124,
                                             0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, (char*)gKTRexState + 0x124,
                                             0x200001, -1, NULL);
        }
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x20) != 0)
    {
        ((KTRexArenaState*)gKTRexState)->unk144 = lbl_803E67C8;
        for (i = 0; i < 16; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x13c,
                                             0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x483, (char*)gKTRexState + 0x13c,
                                             0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x484, (char*)gKTRexState + 0x13c,
                                             0x200001, -1, NULL);
        }
    }
    if ((((KTRexArenaState*)gKTRexState)->phaseFlags & 0x800) != 0)
    {
        (*gPartfxInterface)->spawnObject((void*)obj, 0x487, (char*)gKTRexState + 0x10c,
                                         0x200001, -1, (char*)gKTRexState + 0x16c);
    }
    ((KTRexArenaState*)gKTRexState)->phaseFlags &= 0x1800LL;
    if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject == (int)Obj_GetPlayerObject())
    {
        Sfx_PlayFromObject((int)Obj_GetPlayerObject(), SFXbaddie_haga_talk1);
    }
}

void ktrex_updateContactEffects(int obj, void* runtime)
{
    int hitType;
    u32 hitC;
    int hitA;
    int msg[4];
    int hit;
    f32* contactPoints;
    f32* pt;
    *(KtrexMsgBlob*)msg = *(KtrexMsgBlob*)gKTRexMsgTemplate;
    if (gKTRexContactEffectCooldown != 0)
    {
        gKTRexContactEffectCooldown -= 1;
    }
    if (((KTRexRuntime*)gKTRexRuntime)->unk3E8 > lbl_803E67B8)
    {
        ((KTRexRuntime*)gKTRexRuntime)->unk3E8 =
            timeDelta * ((KTRexRuntime*)gKTRexRuntime)->unk3EC + ((KTRexRuntime*)gKTRexRuntime)->unk3E8;
        if (((KTRexRuntime*)gKTRexRuntime)->unk3E8 < lbl_803E67B8)
        {
            ((KTRexRuntime*)gKTRexRuntime)->unk3E8 = lbl_803E67B8;
        }
        else if (((KTRexRuntime*)gKTRexRuntime)->unk3E8 > lbl_803E6820)
        {
            ((KTRexRuntime*)gKTRexRuntime)->unk3E8 =
                lbl_803E6820 - (((KTRexRuntime*)gKTRexRuntime)->unk3E8 - lbl_803E6820);
            ((KTRexRuntime*)gKTRexRuntime)->unk3EC = -((KTRexRuntime*)gKTRexRuntime)->unk3EC;
        }
    }
    hit = ObjHits_GetPriorityHit(obj, &hitA, &hitType, &hitC);
    if (hit == 0)
    {
        return;
    }
    contactPoints = KTRex_GetActiveContactPointTable(obj);
    if ((s8)((KTRexRuntime*)runtime)->hitCountdown != 0 && (hitType == 3 || hitType == 2) &&
        (((KTRexArenaState*)gKTRexState)->timerFA & 0x10) != 0 && hit == 5)
    {
        ((KTRexWork*)gKTRexEffectSpawnWork)->posX = playerMapOffsetX + (pt = contactPoints + hitType * 4)[1];
        ((KTRexWork*)gKTRexEffectSpawnWork)->posY = pt[2];
        ((KTRexWork*)gKTRexEffectSpawnWork)->posZ = playerMapOffsetZ + pt[3];
        Sfx_PlayFromObject(obj, SFXmv_deaththud16);
        Sfx_PlayFromObject(obj, SFXmv_roothack16);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x4b2, gKTRexEffectSpawnWork, 0x200001, -1,
                                         NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x4b3, gKTRexEffectSpawnWork, 0x200001, -1,
                                         NULL);
        if (hit == 0xe)
        {
            ((KTRexRuntime*)runtime)->hitCountdown -= 1;
        }
        else
        {
            ((KTRexRuntime*)runtime)->hitCountdown = 0;
        }
        if ((s8)((KTRexRuntime*)runtime)->hitCountdown <= 0)
        {
            ((KTRexRuntime*)runtime)->hitCountdown = 0;
            ((KTRexArenaState*)gKTRexState)->timerFA &= ~0x10;
            ((KTRexArenaState*)gKTRexState)->timerFA |= 0x8;
        }
        ((KTRexRuntime*)runtime)->unk34F = hit;
    }
    else if (gKTRexContactEffectCooldown == 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_ropecreak22);
        contactPoints = KTRex_GetActiveContactPointTable(obj);
        ((KTRexWork*)gKTRexEffectSpawnWork)->posX = playerMapOffsetX + (pt = contactPoints + hitType * 4)[1];
        ((KTRexWork*)gKTRexEffectSpawnWork)->posY = pt[2];
        ((KTRexWork*)gKTRexEffectSpawnWork)->posZ = playerMapOffsetZ + pt[3];
        (*gPartfxInterface)->spawnObject((void*)obj, 0x328, gKTRexEffectSpawnWork, 0x200001, -1,
                                         NULL);
        ((KTRexWork*)gKTRexEffectSpawnWork)->posX -= ((GameObject*)obj)->anim.worldPosX;
        ((KTRexWork*)gKTRexEffectSpawnWork)->posY -= ((GameObject*)obj)->anim.worldPosY;
        ((KTRexWork*)gKTRexEffectSpawnWork)->posZ -= ((GameObject*)obj)->anim.worldPosZ;
        ((KTRexWork*)gKTRexEffectSpawnWork)->unk8 = lbl_803E6818;
        ((KTRexWork*)gKTRexEffectSpawnWork)->unk0 = 0;
        ((KTRexWork*)gKTRexEffectSpawnWork)->unk2 = 0;
        ((KTRexWork*)gKTRexEffectSpawnWork)->unk4 = 0;
        msg[1] += randomGetRange(0, 0x9b);
        msg[2] += randomGetRange(0, 0x9b);
        (*(void (**)(int, int, void*, int, int, int*))(*(int*)gKTRexResource + 0x4))(
            obj, 0, gKTRexEffectSpawnWork, 1, -1, msg);
        gKTRexContactEffectCooldown = 0x3c;
    }
    if ((s8)((KTRexRuntime*)runtime)->hitCountdown < 1)
    {
        ((KTRexRuntime*)runtime)->hitCountdown = 0;
    }
    ObjMsg_SendToObject(hitA, 0xe0001, obj, 0);
}

int ktrex_stateHandlerA02(int obj, int runtime)
{
    void* p;
    u16 flags;
    u8 phase;
    int idx;
    int flag1;
    u8* pb;
    p = ((GameObject*)obj)->anim.placementData;
    if ((s8)((KTRexRuntime*)runtime)->unk27B != 0)
    {
        (*(void (**)(int, int, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 1);
        ((KTRexArenaState*)gKTRexState)->laneIndex = 0;
        ((KTRexArenaState*)gKTRexState)->timerFA &= ~0x20;
        {
            u8* row = (u8*)p + 0x38;
            ((KTRexRuntime*)runtime)->unk294 =
                *(f32*)(row + ((KTRexArenaState*)gKTRexState)->laneIndex * 4) / lbl_803E67C4;
        }
    }
    if (ktrex_updateArenaPathProgress(runtime) != 0)
    {
        int push = 2;
        if (Stack_IsFull(((KTRexArenaState*)gKTRexState)->stack) == 0)
        {
            Stack_Push(((KTRexArenaState*)gKTRexState)->stack, &push);
        }
        return 4;
    }
    flags = ((KTRexArenaState*)gKTRexState)->timerFA;
    flag1 = flags & 1;
    if (((KTRexArenaState*)gKTRexState)->laneIndex == 0 &&
        (phase = ((KTRexArenaState*)gKTRexState)->phaseCounter) >= 2 && (flags & 0x20) == 0 &&
        ((flag1 == 0 && ((KTRexArenaState*)gKTRexState)->laneLerpT >= lbl_803E67E8) ||
            (flag1 != 0 && ((KTRexArenaState*)gKTRexState)->laneLerpT <= lbl_803E67C0)))
    {
        idx = phase >> 1;
        pb = (u8*)p;
        if ((int)randomGetRange(0, 0x64) <= pb[idx + 0x56])
        {
            int push;
            ((KTRexArenaState*)gKTRexState)->pathCountdown = 2;
            push = 5;
            if (Stack_IsFull(((KTRexArenaState*)gKTRexState)->stack) == 0)
            {
                Stack_Push(((KTRexArenaState*)gKTRexState)->stack, &push);
            }
            ((KTRexArenaState*)gKTRexState)->moveVariant = 1;
            return 5;
        }
        if ((int)randomGetRange(0, 0x64) <= pb[idx + 0x52])
        {
            u8 cond;
            u8 fe = ((KTRexArenaState*)gKTRexState)->unkFE;
            if (fe == 1)
            {
                cond = ((KTRexArenaState*)gKTRexState)->unkFF == 2;
            }
            else if (fe == 2)
            {
                cond = ((KTRexArenaState*)gKTRexState)->unkFF == 1;
            }
            else if (fe == 4)
            {
                cond = ((KTRexArenaState*)gKTRexState)->unkFF == 8;
            }
            else
            {
                cond = ((KTRexArenaState*)gKTRexState)->unkFF == 4;
            }
            if (cond && (((KTRexArenaState*)gKTRexState)->timerFA & 0x40) == 0)
            {
                int push;
                ((KTRexArenaState*)gKTRexState)->moveVariant = 0;
                push = 0xb;
                if (Stack_IsFull(((KTRexArenaState*)gKTRexState)->stack) == 0)
                {
                    Stack_Push(((KTRexArenaState*)gKTRexState)->stack, &push);
                }
                return 5;
            }
        }
        ((KTRexArenaState*)gKTRexState)->timerFA |= 0x20;
    }
    if ((((KTRexArenaState*)gKTRexState)->unkFE & ((KTRexArenaState*)gKTRexState)->unkFF) != 0)
    {
        ((KTRexArenaState*)gKTRexState)->timerFA &= ~0x40;
        {
            u8 result;
            if ((((KTRexArenaState*)gKTRexState)->unkFE & ((KTRexArenaState*)gKTRexState)->unkFF) != 0)
            {
                if ((((KTRexArenaState*)gKTRexState)->timerFA & 1) != 0)
                {
                    if (((KTRexArenaState*)gKTRexState)->laneLerpT - ((KTRexArenaState*)gKTRexState)->unkF4 > lbl_803E67B4)
                    {
                        result = 1;
                        goto haveResult;
                    }
                }
                else
                {
                    if (((KTRexArenaState*)gKTRexState)->unkF4 - ((KTRexArenaState*)gKTRexState)->laneLerpT > lbl_803E67B4)
                    {
                        result = 1;
                        goto haveResult;
                    }
                }
            }
            result = 0;
        haveResult:;
            if (result != 0)
            {
                int push;
                ((KTRexArenaState*)gKTRexState)->pathCountdown = 1;
                push = 5;
                if (Stack_IsFull(((KTRexArenaState*)gKTRexState)->stack) == 0)
                {
                    Stack_Push(((KTRexArenaState*)gKTRexState)->stack, &push);
                }
                ((KTRexArenaState*)gKTRexState)->moveVariant = 1;
                return 5;
            }
        }
    }
    return 0;
}

int ktrex_stateHandlerA03(int obj, int runtime)
{
    int phase;
    f32 f4;
    f32 f5;
    int popped;
    if ((s8)((KTRexRuntime*)runtime)->unk27B != 0)
    {
        (*(void (**)(int, int, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 2);
        goto ret0;
    }
    if ((s8)((KTRexRuntime*)runtime)->moveDone != 0)
    {
        phase = (((KTRexArenaState*)gKTRexState)->timerFA >> 1) & 3;
        f5 = ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)->rowBX)[phase] - ((f32*)*(int*)&((KTRexArenaState*)
            gKTRexState)->rowAX)[phase];
        f4 = ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)->rowBZ)[phase] - ((f32*)*(int*)&((KTRexArenaState*)
            gKTRexState)->rowAZ)[phase];
        if (__fabs(f5) > __fabs(f4))
        {
            f4 = (((GameObject*)obj)->anim.localPosX -
                  ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)->rowAX)[phase]) /
                f5;
        }
        else
        {
            f4 = (((GameObject*)obj)->anim.localPosZ -
                  ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)->rowAZ)[phase]) /
                f4;
        }
        ((KTRexArenaState*)gKTRexState)->laneLerpT = f4;
        popped = 0;
        if (Stack_IsEmpty(((KTRexArenaState*)gKTRexState)->stack) == 0)
        {
            Stack_Pop(((KTRexArenaState*)gKTRexState)->stack, &popped);
        }
        return popped + 1;
    }
ret0:
    return 0;
}

int ktrex_stateHandlerA07(int obj, int runtime)
{
    if ((s8)((KTRexRuntime*)runtime)->unk27B != 0)
    {
        (*(void (**)(int, int, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 6);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        ((KTRexArenaState*)gKTRexState)->phaseCounter += 1;
        ktrexlevel_clearPathGameBits();
        GameBit_Set(1394, ((KTRexArenaState*)gKTRexState)->phaseCounter);
        ((KTRexArenaState*)gKTRexState)->timerFA |= 0x10;
        ((KTRexArenaState*)gKTRexState)->timerFA &= ~8;
        Music_Trigger(148, 0);
        Music_Trigger(40, 0);
        Music_Trigger(147, 1);
    }
    else if ((s8)((KTRexRuntime*)runtime)->moveDone != 0 || (((KTRexArenaState*)gKTRexState)->timerFA & 8) != 0)
    {
        return 9;
    }
    return 0;
}

int ktrex_stateHandlerA04(int obj, int runtime)
{
    void* p;
    int popped;
    f32 t;
    p = ((GameObject*)obj)->anim.placementData;
    if ((s8)((KTRexRuntime*)runtime)->unk27B != 0)
    {
        (*(void (**)(int, int, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 4);
        ((KTRexArenaState*)gKTRexState)->stateTimer =
            (f32)(u32)((u16*)((char*)p + 0x44))[((KTRexArenaState*)gKTRexState)->moveVariant];
    }
    else
    {
        t = ((KTRexArenaState*)gKTRexState)->stateTimer - timeDelta;
        ((KTRexArenaState*)gKTRexState)->stateTimer = t;
        if (t < lbl_803E67B8)
        {
            ((KTRexArenaState*)gKTRexState)->stateTimer = lbl_803E67B8;
        }
        if ((s8)((KTRexRuntime*)runtime)->moveDone != 0)
        {
            if (((KTRexArenaState*)gKTRexState)->stateTimer <= lbl_803E67B8)
            {
                popped = 0;
                if (Stack_IsEmpty(((KTRexArenaState*)gKTRexState)->stack) == 0)
                {
                    Stack_Pop(((KTRexArenaState*)gKTRexState)->stack, &popped);
                }
                return popped + 1;
            }
        }
    }
    return 0;
}

int ktrex_stateHandlerA05(int obj, int runtime)
{
    void* p;
    int pushLo;
    int pushHi;
    p = ((GameObject*)obj)->anim.placementData;
    if ((s8)((KTRexRuntime*)runtime)->unk27B != 0)
    {
        (*(void (**)(int, int, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 1);
        ((KTRexArenaState*)gKTRexState)->laneIndex = 1;
        p = (char*)p + ((KTRexArenaState*)gKTRexState)->laneIndex * 4;
        ((KTRexRuntime*)runtime)->unk294 = ((KtrexPlacement*)p)->unk38 / lbl_803E67C4;
    }
    if (RandomTimer_UpdateRangeTrigger((char*)gKTRexState + 0x190, lbl_803E67C8, lbl_803E67CC) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_gdtur2_c);
    }
    if (ktrex_updateArenaPathProgress(runtime) != 0)
    {
        ((KTRexArenaState*)gKTRexState)->pathCountdown -= 1;
        if ((s8)((KTRexArenaState*)gKTRexState)->pathCountdown <= 0)
        {
            pushLo = 2;
            if (Stack_IsFull(((KTRexArenaState*)gKTRexState)->stack) == 0)
            {
                Stack_Push(((KTRexArenaState*)gKTRexState)->stack, &pushLo);
            }
        }
        else
        {
            pushHi = 5;
            if (Stack_IsFull(((KTRexArenaState*)gKTRexState)->stack) == 0)
            {
                Stack_Push(((KTRexArenaState*)gKTRexState)->stack, &pushHi);
            }
        }
        return 4;
    }
    if (ktrex_isPlayerInLaneThreatRange(obj) != 0)
    {
        return 8;
    }
    return 0;
}

int ktrex_stateHandlerA08(int obj, int runtime)
{
    void* p;
    f32 t;
    p = ((GameObject*)obj)->anim.placementData;
    if ((s8)((KTRexRuntime*)runtime)->unk27B != 0)
    {
        (*(void (**)(int, int, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 7);
        {
            u8* row = (u8*)p + 0x4a;
            ((KTRexArenaState*)gKTRexState)->stateTimer =
                (f32)(u32) * (u16*)(row + (((KTRexArenaState*)gKTRexState)->phaseCounter & ~1));
        }
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        goto ret0;
    }
    if ((((KTRexArenaState*)gKTRexState)->timerFA & 8) == 0)
    {
        t = ((KTRexArenaState*)gKTRexState)->stateTimer - timeDelta;
        ((KTRexArenaState*)gKTRexState)->stateTimer = t;
        if (!(t <= lbl_803E67B8))
        {
            goto ret0;
        }
    }
    if ((((KTRexArenaState*)gKTRexState)->timerFA & 8) != 0)
    {
        ((KTRexArenaState*)gKTRexState)->phaseCountdown -= 1;
        ((KTRexRuntime*)runtime)->hitCountdown = 3;
    }
    ((KTRexArenaState*)gKTRexState)->timerFA &= ~0x10;
    if (((KTRexArenaState*)gKTRexState)->phaseCountdown == 0)
    {
        return 2;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    return 10;
ret0:
    return 0;
}

int ktrex_stateHandlerA11(int obj, int runtime)
{
    int phase;
    f32 f4;
    f32 f5;
    if ((((KTRexArenaState*)gKTRexState)->timerFA & 1) != 0u)
    {
        ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + 0x8000);
    }
    else
    {
        ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX - 0x8000);
    }
    ((KTRexArenaState*)gKTRexState)->timerFA ^= 1;
    if ((((KTRexArenaState*)gKTRexState)->timerFA & 1) != 0)
    {
        ((KTRexArenaState*)gKTRexState)->rowAX = (char*)gKTRexState + 0x70;
        ((KTRexArenaState*)gKTRexState)->rowAY = (char*)gKTRexState + 0x80;
        ((KTRexArenaState*)gKTRexState)->rowAZ = (char*)gKTRexState + 0x90;
        ((KTRexArenaState*)gKTRexState)->rowBX = (char*)gKTRexState + 0xa0;
        ((KTRexArenaState*)gKTRexState)->rowBY = (char*)gKTRexState + 0xb0;
        ((KTRexArenaState*)gKTRexState)->rowBZ = (char*)gKTRexState + 0xc0;
    }
    else
    {
        ((KTRexArenaState*)gKTRexState)->rowAX = (char*)gKTRexState + 0x10;
        ((KTRexArenaState*)gKTRexState)->rowAY = (char*)gKTRexState + 0x20;
        ((KTRexArenaState*)gKTRexState)->rowAZ = (char*)gKTRexState + 0x30;
        ((KTRexArenaState*)gKTRexState)->rowBX = (char*)gKTRexState + 0x40;
        ((KTRexArenaState*)gKTRexState)->rowBY = (char*)gKTRexState + 0x50;
        ((KTRexArenaState*)gKTRexState)->rowBZ = (char*)gKTRexState + 0x60;
    }
    phase = (((KTRexArenaState*)gKTRexState)->timerFA >> 1) & 3;
    f5 = ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)->rowBX)[phase] - ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)
        ->rowAX)[phase];
    f4 = ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)->rowBZ)[phase] - ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)
        ->rowAZ)[phase];
    if (__fabs(f5) > __fabs(f4))
    {
        f4 = (((GameObject*)obj)->anim.localPosX - ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)->rowAX)[phase]) / f5;
    }
    else
    {
        f4 = (((GameObject*)obj)->anim.localPosZ - ((f32*)*(int*)&((KTRexArenaState*)gKTRexState)->rowAZ)[phase]) / f4;
    }
    ((KTRexArenaState*)gKTRexState)->laneLerpT = f4;
    ((KTRexArenaState*)gKTRexState)->timerFA |= 0x40;
    return 3;
}

int ktrex_stateHandlerA09(int obj, int runtime)
{
    if ((s8)((KTRexRuntime*)runtime)->unk27B != 0)
    {
        (*(void (**)(int, int, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 8);
        if ((*gCameraInterface)->getMode() == 66)
        {
            (*gCameraInterface)->loadTriggeredCamAction(2, 0, 0);
        }
    }
    else if ((s8)((KTRexRuntime*)runtime)->moveDone != 0)
    {
        ((KTRexArenaState*)gKTRexState)->lastPhase = (((KTRexArenaState*)gKTRexState)->timerFA >> 1) & 3;
        ((KTRexArenaState*)gKTRexState)->stateTimer = lbl_803E67D8;
        Music_Trigger(147, 0);
        Music_Trigger(148, 1);
        return 11;
    }
    return 0;
}

int ktrex_stateHandlerA10(int obj, int runtime)
{
    void* p;
    u16 flags;
    int phase;
    int laneBit;
    p = ((GameObject*)obj)->anim.placementData;
    flags = ((KTRexArenaState*)gKTRexState)->timerFA;
    phase = (flags >> 1) & 3;
    laneBit = flags & 1;
    if ((s8)((KTRexRuntime*)runtime)->unk27B != 0)
    {
        (*(void (**)(int, int, int))((char*)*gPlayerInterface + 0x14))(obj, runtime, 1);
        ((KTRexArenaState*)gKTRexState)->laneIndex = 2;
        {
            u8* row = (u8*)p + 0x38;
            ((KTRexRuntime*)runtime)->unk294 =
                *(f32*)(row + ((KTRexArenaState*)gKTRexState)->laneIndex * 4) / lbl_803E67C4;
        }
    }
    if (ktrex_updateArenaPathProgress(runtime) != 0)
    {
        int push = 0xa;
        if (Stack_IsFull(((KTRexArenaState*)gKTRexState)->stack) == 0)
        {
            Stack_Push(((KTRexArenaState*)gKTRexState)->stack, &push);
        }
        return 4;
    }
    if ((u8)ktrex_shouldAdvanceArenaPhase() != 0)
    {
        (*gCameraInterface)->loadTriggeredCamAction(3, 0, 0);
    }
    if (RandomTimer_UpdateRangeTrigger((char*)gKTRexState + 0x190, lbl_803E67C8, lbl_803E67CC) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_gdtur2_c);
    }
    {
        f32 u4 = ((KTRexArenaState*)gKTRexState)->stateTimer - timeDelta;
        ((KTRexArenaState*)gKTRexState)->stateTimer = u4;
        if (u4 <= lbl_803E67B8)
        {
            ((KTRexArenaState*)gKTRexState)->stateTimer = *(f32 *)&lbl_803E67B8;
        }
    }
    if (((KTRexArenaState*)gKTRexState)->stateTimer <= lbl_803E67B8 &&
        ((KTRexArenaState*)gKTRexState)->lastPhase == phase &&
        ((laneBit == 0 && ((KTRexArenaState*)gKTRexState)->laneLerpT >= lbl_803E67D0) ||
            (laneBit != 0 && ((KTRexArenaState*)gKTRexState)->laneLerpT <= lbl_803E67D4)))
    {
        if ((((KTRexArenaState*)gKTRexState)->timerFA & 8) != 0)
        {
            u8 cond;
            u8 fe;
            ((KTRexArenaState*)gKTRexState)->phaseCounter += 1;
            GameBit_Set(0x572, ((KTRexArenaState*)gKTRexState)->phaseCounter);
            ((KTRexArenaState*)gKTRexState)->moveVariant = 0;
            ((KTRexArenaState*)gKTRexState)->timerFA &= ~0x8;
            fe = ((KTRexArenaState*)gKTRexState)->unkFE;
            if (fe == 1)
            {
                cond = ((KTRexArenaState*)gKTRexState)->unkFF == 2;
            }
            else if (fe == 2)
            {
                cond = ((KTRexArenaState*)gKTRexState)->unkFF == 1;
            }
            else if (fe == 4)
            {
                cond = ((KTRexArenaState*)gKTRexState)->unkFF == 8;
            }
            else
            {
                cond = ((KTRexArenaState*)gKTRexState)->unkFF == 4;
            }
            if (cond && (((KTRexArenaState*)gKTRexState)->timerFA & 0x40) == 0)
            {
                int push = 0xb;
                if (Stack_IsFull(((KTRexArenaState*)gKTRexState)->stack) == 0)
                {
                    Stack_Push(((KTRexArenaState*)gKTRexState)->stack, &push);
                }
            }
            else
            {
                int push = 2;
                if (Stack_IsFull(((KTRexArenaState*)gKTRexState)->stack) == 0)
                {
                    Stack_Push(((KTRexArenaState*)gKTRexState)->stack, &push);
                }
            }
            {
                int push = 4;
                if (Stack_IsFull(((KTRexArenaState*)gKTRexState)->stack) == 0)
                {
                    Stack_Push(((KTRexArenaState*)gKTRexState)->stack, &push);
                }
            }
        }
        else
        {
            int push;
            ((KTRexArenaState*)gKTRexState)->phaseCounter -= 1;
            push = 2;
            if (Stack_IsFull(((KTRexArenaState*)gKTRexState)->stack) == 0)
            {
                Stack_Push(((KTRexArenaState*)gKTRexState)->stack, &push);
            }
        }
        ktrexlevel_updatePathGameBits();
        (*gCameraInterface)->loadTriggeredCamAction(3, 0, 0);
        GameBit_Set(0x572, ((KTRexArenaState*)gKTRexState)->phaseCounter);
        {
            int popped = 0;
            if (Stack_IsEmpty(((KTRexArenaState*)gKTRexState)->stack) == 0)
            {
                Stack_Pop(((KTRexArenaState*)gKTRexState)->stack, &popped);
            }
            return popped + 1;
        }
    }
    return 0;
}

int ktrex_stateHandlerA01(int obj, int runtime)
{
    if ((s8)((KTRexRuntime*)runtime)->unk27B != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        ((KTRexRuntime*)runtime)->unk349 = 0;
        ((KTRexRuntime*)runtime)->unk25F = 0;
        *(f32*)((char*)gKTRexState + 4) = lbl_803E67EC;
    }
    else
    {
        *(f32*)((char*)gKTRexState + 4) -= timeDelta;
        if (*(f32*)((char*)gKTRexState + 4) <= lbl_803E67F0)
        {
            if (((GameObject*)obj)->unkF8 != 3)
            {
                (*gScreenTransitionInterface)->start(30, 1);
                ((GameObject*)obj)->unkF8 = 3;
            }
        }
        if (*(f32*)((char*)gKTRexState + 4) <= lbl_803E67B8)
        {
            Obj_SetModelColorFadeRecursive((int)Obj_GetPlayerObject(), 0, 0, 0, 0, 0);
            Music_Trigger(40, 0);
            Music_Trigger(147, 0);
            Music_Trigger(148, 0);
            ((ObjAnimComponent*)obj)->bankIndex = 1;
            GameBit_Set(1380, 1);
            GameBit_Set(874, 0);
            (*gMapEventInterface)->setObjGroupStatus(13, 0, 1);
            (*gMapEventInterface)->setObjGroupStatus(13, 1, 1);
            (*gMapEventInterface)->setObjGroupStatus(13, 5, 1);
            (*gMapEventInterface)->setObjGroupStatus(13, 10, 1);
            (*gMapEventInterface)->setObjGroupStatus(13, 11, 1);
            GameBit_Set(3589, 0);
            unlockLevel(53, 1, 0);
            GameBit_Set(2107, 1);
            (*gMapEventInterface)->setMapAct(4, 2);
        }
    }
    return 0;
}
