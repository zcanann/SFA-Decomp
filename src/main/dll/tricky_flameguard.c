/* tricky_flameguard - Tricky (DLL 0x00C4) flame/guard AI sub-TU. Spawns Tricky's
   flameblast (def 0x4F0) for the fire-breath/guard behaviour. */
#include "main/audio/sfx.h"
#include "main/game_object.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/baddie/trickyfollow.h"
#include "main/engine_shared.h"

typedef struct TrickyState
{
    u8 pad0[0x58 - 0x0];
    u8 unk58;
    u8 pad59[0x60 - 0x59];
} TrickyState;

#define TRICKY_STATE_FLAGS_OFFSET 0x54
#define TRICKY_STATE_TARGET_DIRTY_FLAG 0x00000400
#define TRICKY_STATE_RESET_FLAG_10 0x00000010
#define TRICKY_STATE_HELPERS_ACTIVE_FLAG 0x00000800
#define TRICKY_STATE_HELPERS_FINISHED_FLAG 0x00001000
#define TRICKY_STATE_RESET_FLAG_10000 0x00010000
#define TRICKY_STATE_RESET_FLAG_20000 0x00020000
#define TRICKY_STATE_RESET_FLAG_40000 0x00040000
#define TRICKY_GUARD_HELPER_COUNT 7
#define TRICKY_GUARD_APPROACH_GROUP 3
#define TRICKY_GUARD_HELPER_SETUP_SIZE 0x24
#define TRICKY_GUARD_HELPER_DEF_ID 0x04F0

typedef struct TrickyRuntime
{
    u8* helperSpawnCount;
    u8 pad04[0x08 - 0x04];
    u8 growlLatState;
    u8 pad09;
    u8 guardState;
    u8 pad0B[0x0D - 0x0B];
    s8 unk0D;
    u8 pad0E[0x24 - 0x0E];
    ObjAnimComponent* homeObj;
    f32* targetPosition;
    u8 pad2C[TRICKY_STATE_FLAGS_OFFSET - 0x2C];
    u32 flags;
    u8 pad58[0xD2 - 0x58];
    u16 targetTurnTimer;
    u8 padD4[0x700 - 0xD4];
    void* guardHelpers[TRICKY_GUARD_HELPER_COUNT];
    f32 guardPoint[3];
    f32 guardTimer;
    ObjAnimComponent* guardTarget;
    s32 guardWalkGroup;
    u8 guardCanSpawnHelpers;
} TrickyRuntime;

STATIC_ASSERT(offsetof(TrickyRuntime, flags) == TRICKY_STATE_FLAGS_OFFSET);
STATIC_ASSERT(offsetof(TrickyRuntime, helperSpawnCount) == 0x00);
STATIC_ASSERT(offsetof(TrickyRuntime, growlLatState) == 0x08);
STATIC_ASSERT(offsetof(TrickyRuntime, guardState) == 0x0A);
STATIC_ASSERT(offsetof(TrickyRuntime, unk0D) == 0x0D);
STATIC_ASSERT(offsetof(TrickyRuntime, homeObj) == 0x24);
STATIC_ASSERT(offsetof(TrickyRuntime, targetPosition) == 0x28);
STATIC_ASSERT(offsetof(TrickyRuntime, targetTurnTimer) == 0xD2);
STATIC_ASSERT(offsetof(TrickyRuntime, guardHelpers) == 0x700);
STATIC_ASSERT(offsetof(TrickyRuntime, guardPoint) == 0x71C);
STATIC_ASSERT(offsetof(TrickyRuntime, guardTimer) == 0x728);
STATIC_ASSERT(offsetof(TrickyRuntime, guardTarget) == 0x72C);
STATIC_ASSERT(offsetof(TrickyRuntime, guardWalkGroup) == 0x730);
STATIC_ASSERT(offsetof(TrickyRuntime, guardCanSpawnHelpers) == 0x734);

#define TRICKY_RUNTIME(st) ((TrickyRuntime *)(st))

#define TRICKY_CLEAR_TARGET_DIRTY(st) \
    (*(s32*)&TRICKY_RUNTIME(st)->flags &= ~(u64)TRICKY_STATE_TARGET_DIRTY_FLAG)

#define TRICKY_MARK_HELPERS_FINISHED(st) \
    { \
        TRICKY_RUNTIME(st)->flags &= ~(u64)TRICKY_STATE_HELPERS_ACTIVE_FLAG; \
        TRICKY_RUNTIME(st)->flags |= TRICKY_STATE_HELPERS_FINISHED_FLAG; \
    }

#define TRICKY_CLEAR_RESET_FLAGS(st) \
    { \
        TRICKY_RUNTIME(st)->flags &= ~(u64)TRICKY_STATE_RESET_FLAG_10; \
        TRICKY_RUNTIME(st)->flags &= ~(u64)TRICKY_STATE_RESET_FLAG_10000; \
        TRICKY_RUNTIME(st)->flags &= ~(u64)TRICKY_STATE_RESET_FLAG_20000; \
        TRICKY_RUNTIME(st)->flags &= ~(u64)TRICKY_STATE_RESET_FLAG_40000; \
        TRICKY_RUNTIME(st)->unk0D = -1; \
    }

extern void* ObjGroup_GetObjects();
extern int Objfsa_GetWalkGroupIndexAtPoint(float* pos, void* flag);
extern f32 getXZDistance(f32* a, f32* b);

int trickyGuardFindBaddieTarget(TrickyRuntime * state);

extern int Objfsa_FindNearestCurveType24(float* pos, int p2, int p3);
extern int trickyUpdateApproachSpeed(int p1, int p2, f32 f, void* target, int p4);
extern int trickyMove(int p1, void* p2);
extern void trickyTurnTowardYaw(int p1, s16 angle);
extern void objAnimFn_8013a3f0(int obj, int p2, f32 f, int p4);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int Obj_SetupObject(void* setup, int p2, int p3, int p4, void* p5);
extern void objSetAnimSpeedTo1(int* obj);
extern void objAudioFn_800393f8(int obj, void* p2, int p3, int p4, int p5, int p6);
extern char lbl_8031D2E8[];
extern int getAngle(float y, float x);
extern void* ObjGroup_GetObjects(int group, int* count);
extern f32 lbl_803E23EC;
extern f32 lbl_803E23F4;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E2420;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E2454;
extern f32 lbl_803E2458;
extern f32 lbl_803E247C;
extern f32 lbl_803E24C4;
extern f32 lbl_803E24D0;
extern f32 lbl_803E24D8;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E4;
extern f32 lbl_803E2418;
extern f32 lbl_803E2488;
extern f32 lbl_803E24AC;
extern f32 lbl_803E24F8;
extern f32 lbl_803E2504;

void trickyFlame(int p1, int p2)
{
    register char* strBase = lbl_8031D2E8;
    void** slot;
    int i;
    void** slot2;
    int i2;
    void* setup;
    void* state;
    void* target;
    int dieFlag;
    int newTarget;
    f32 fz;

    switch (*(u8*)(p2 + 0xa))
    {
    case 0:
        trickyDebugPrint(strBase + 0x700);
        *(int*)(p2 + 0x71c) = Objfsa_FindNearestCurveType24(&((TrickyRuntime*)p2)->homeObj->worldPosX, -1, 4);
        if (*(u8*)(*(int*)(p2 + 0x71c) + 0x3) != 0)
        {
            newTarget = *(int*)(p2 + 0x71c) + 0x8;
            if (*(u32*)(p2 + 0x28) != newTarget)
            {
                *(int*)(p2 + 0x28) = newTarget;
                TRICKY_CLEAR_TARGET_DIRTY(p2);
                ((TrickyRuntime*)p2)->targetTurnTimer = 0;
            }
            *(u8*)(p2 + 0xa) = 1;
        }
        else
        {
            *(int*)(p2 + 0x720) =
                (int)(*gRomCurveInterface)->getById(*(int*)(*(int*)(p2 + 0x71c) + 0x1c));
            newTarget = *(int*)(p2 + 0x720) + 0x8;
            if (*(u32*)(p2 + 0x28) != newTarget)
            {
                *(int*)(p2 + 0x28) = newTarget;
                TRICKY_CLEAR_TARGET_DIRTY(p2);
                ((TrickyRuntime*)p2)->targetTurnTimer = 0;
            }
            *(u8*)(p2 + 0xa) = 3;
        }
        trickyFn_8013b368((void*)p1, lbl_803E2488, (void*)p2);
        break;
    case 3:
        trickyDebugPrint(strBase + 0x70c);
        trickyFn_8013b368((void*)p1, lbl_803E2488, (void*)p2);
        if ((u8) * (u8*)(*(int*)(p2 + 0x720) + 0x3) == Objfsa_GetWalkGroupIndexAtPoint(
            (float*)&((GameObject*)p1)->anim.worldPosX, 0x0))
        {
            *(u8*)(p2 + 0x9) = 1;
            *(u8*)(p2 + 0xa) = 4;
        }
        break;
    case 4:
        trickyDebugPrint(strBase + 0x720);
        target = (void*)(*(int*)(p2 + 0x71c) + 0x8);
        trickyUpdateApproachSpeed(p1, p2, lbl_803E2488, target, 1);
        trickyMove(p1, target);
        if (Objfsa_GetWalkGroupIndexAtPoint((float*)&((GameObject*)p1)->anim.worldPosX, 0x0) == 0)
        {
            ((TrickyRuntime*)p2)->flags |= TRICKY_STATE_RESET_FLAG_10;
            *(u8*)(p2 + 0xa) = 5;
        }
        break;
    case 5:
        trickyDebugPrint(strBase + 0x734);
        target = (void*)(*(int*)(p2 + 0x71c) + 0x8);
        trickyUpdateApproachSpeed(p1, p2, lbl_803E2488, target, 1);
        if (trickyMove(p1, target) == 0)
        {
            objAnimFn_8013a3f0(p1, 0x1a, lbl_803E23E4, 0x4000000);
            *(u8*)(p2 + 0xa) = 7;
            (*(u8*)*(int*)p2) -= 4;
        }
        break;
    case 7:
        trickyDebugPrint(strBase + 0x744);
        {
            s16 srcAng = (s16)((s8) * (u8*)(*(int*)(p2 + 0x71c) + 0x2c) << 8);
            s16 delta = (s16)(srcAng - (u16) * (s16*)p1);
            int absDelta;
            if (delta > 0x8000)
            {
                delta = (s16)(delta - 0xFFFF);
            }
            if (delta < -0x8000)
            {
                delta = (s16)(delta + 0xFFFF);
            }
            absDelta = delta;
            absDelta = (absDelta >= 0) ? absDelta : -absDelta;
            if (absDelta >= 0x4000)
            {
                srcAng = (s16)(srcAng + 0x8000);
            }
            trickyTurnTowardYaw(p1, srcAng);
        }
        if ((double)((GameObject*)p1)->anim.currentMoveProgress > (double)lbl_803E24AC)
        {
            if ((((TrickyRuntime*)p2)->flags & TRICKY_STATE_HELPERS_ACTIVE_FLAG) == 0)
            {
                if ((u8)Obj_IsLoadingLocked() != 0)
                {
                    ((TrickyRuntime*)p2)->flags |= TRICKY_STATE_HELPERS_ACTIVE_FLAG;
                    for (i = 0, slot = (void**)p2; i < TRICKY_GUARD_HELPER_COUNT; i++)
                    {
                        setup = Obj_AllocObjectSetup(TRICKY_GUARD_HELPER_SETUP_SIZE, TRICKY_GUARD_HELPER_DEF_ID);
                        *(u8*)((char*)setup + 0x4) = 2;
                        *(u8*)((char*)setup + 0x5) = 1;
                        *(s16*)((char*)setup + 0x1a) = i;
                        slot[0x700 / 4] = (void*)Obj_SetupObject(setup, 5, ((GameObject*)p1)->anim.mapEventSlot, -1,
                                                                 ((GameObject*)p1)->anim.parent);
                        slot++;
                    }
                    Sfx_PlayFromObject(p1, 0x3db);
                    Sfx_AddLoopedObjectSound(p1, 0x3dc);
                }
            }
            else
            {
                int (*cb)(int, int) = *(int (**)(int, int))(p2 + 0x724);
                if (cb != NULL && cb((int)((TrickyRuntime*)p2)->homeObj, 1) == 0)
                {
                }
                else if ((double)((GameObject*)p1)->anim.currentMoveProgress > (double)lbl_803E2504)
                {
                    TRICKY_MARK_HELPERS_FINISHED(p2);
                    for (i = 0, slot = (void**)p2; i < TRICKY_GUARD_HELPER_COUNT; i++)
                    {
                        objSetAnimSpeedTo1(slot[0x700 / 4]);
                        slot++;
                    }
                    Sfx_RemoveLoopedObjectSound(p1, 0x3dc);
                    state = ((GameObject*)p1)->extra;
                    if ((((u32)((TrickyState*)state)->unk58 >> 6) & 1) == 0)
                    {
                        s16 a0 = ((GameObject*)p1)->anim.currentMove;
                        if (a0 >= 0x30 || a0 < 0x29)
                        {
                            if (Sfx_IsPlayingFromObjectChannel(p1, 0x10) == 0)
                            {
                                objAudioFn_800393f8(p1, (char*)state + 0x3a8, 0x29d, 0, -1, 0);
                            }
                        }
                    }
                    dieFlag = 0;
                    goto flame_diecheck;
                }
            }
        }
        dieFlag = 1;
    flame_diecheck:
        if (dieFlag == 0)
        {
            *(u8*)(p2 + 0xa) = 8;
            *(f32*)(p2 + 0x728) = lbl_803E24F8;
        }
        break;
    case 1:
        trickyDebugPrint(strBase + 0x750);
        {
            int r = trickyFn_8013b368((void*)p1, lbl_803E2488, (void*)p2);
            if (r == 0)
            {
                ((TrickyRuntime*)p2)->flags |= TRICKY_STATE_RESET_FLAG_10;
                *(u8*)(p2 + 0xa) = 2;
            }
            else if (r == 2)
            {
                ((TrickyRuntime*)p2)->growlLatState = 1;
                *(u8*)(p2 + 0xa) = 0;
                fz = lbl_803E23DC;
                *(f32*)(p2 + 0x71c) = fz;
                *(f32*)(p2 + 0x720) = fz;
                TRICKY_CLEAR_RESET_FLAGS(p2);
            }
        }
        break;
    case 2:
        trickyDebugPrint(strBase + 0x764);
        target = (void*)((int)((TrickyRuntime*)p2)->homeObj + 0x18);
        trickyUpdateApproachSpeed(p1, p2, lbl_803E2418, target, 1);
        if (trickyMove(p1, target) == 0)
        {
            objAnimFn_8013a3f0(p1, 0x1a, lbl_803E23E4, 0x4000000);
            *(u8*)(p2 + 0xa) = 6;
            (*(u8*)*(int*)p2) -= 4;
        }
        break;
    case 6:
        trickyDebugPrint(strBase + 0x778);
        if ((double)((GameObject*)p1)->anim.currentMoveProgress > (double)lbl_803E24AC)
        {
            if ((((TrickyRuntime*)p2)->flags & TRICKY_STATE_HELPERS_ACTIVE_FLAG) == 0)
            {
                if ((u8)Obj_IsLoadingLocked() != 0)
                {
                    ((TrickyRuntime*)p2)->flags |= TRICKY_STATE_HELPERS_ACTIVE_FLAG;
                    for (i = 0, slot = (void**)p2; i < TRICKY_GUARD_HELPER_COUNT; i++)
                    {
                        setup = Obj_AllocObjectSetup(TRICKY_GUARD_HELPER_SETUP_SIZE, TRICKY_GUARD_HELPER_DEF_ID);
                        *(u8*)((char*)setup + 0x4) = 2;
                        *(u8*)((char*)setup + 0x5) = 1;
                        *(s16*)((char*)setup + 0x1a) = i;
                        slot[0x700 / 4] = (void*)Obj_SetupObject(setup, 5, ((GameObject*)p1)->anim.mapEventSlot, -1,
                                                                 ((GameObject*)p1)->anim.parent);
                        slot++;
                    }
                    Sfx_PlayFromObject(p1, 0x3db);
                    Sfx_AddLoopedObjectSound(p1, 0x3dc);
                }
            }
            else
            {
                int (*cb)(int, int) = *(int (**)(int, int))(p2 + 0x724);
                if (cb != NULL && cb((int)((TrickyRuntime*)p2)->homeObj, 1) == 0)
                {
                }
                else if ((double)((GameObject*)p1)->anim.currentMoveProgress > (double)lbl_803E2504)
                {
                    TRICKY_MARK_HELPERS_FINISHED(p2);
                    for (i2 = 0, slot2 = (void**)p2; i2 < TRICKY_GUARD_HELPER_COUNT; i2++)
                    {
                        objSetAnimSpeedTo1(slot2[0x700 / 4]);
                        slot2++;
                    }
                    Sfx_RemoveLoopedObjectSound(p1, 0x3dc);
                    state = ((GameObject*)p1)->extra;
                    if ((((u32)((TrickyState*)state)->unk58 >> 6) & 1) == 0)
                    {
                        s16 a0 = ((GameObject*)p1)->anim.currentMove;
                        if (a0 >= 0x30 || a0 < 0x29)
                        {
                            if (Sfx_IsPlayingFromObjectChannel(p1, 0x10) == 0)
                            {
                                objAudioFn_800393f8(p1, (char*)state + 0x3a8, 0x29d, 0, -1, 0);
                            }
                        }
                    }
                    dieFlag = 0;
                    goto guard_diecheck;
                }
            }
        }
        dieFlag = 1;
    guard_diecheck:
        if (dieFlag == 0)
        {
            ((TrickyRuntime*)p2)->growlLatState = 1;
            *(u8*)(p2 + 0xa) = 0;
            fz = lbl_803E23DC;
            *(f32*)(p2 + 0x71c) = fz;
            *(f32*)(p2 + 0x720) = fz;
            TRICKY_CLEAR_RESET_FLAGS(p2);
        }
        break;
    case 8:
        trickyDebugPrint(strBase + 0x784);
        *(f32*)(p2 + 0x728) = *(f32*)(p2 + 0x728) - timeDelta;
        if (*(f32*)(p2 + 0x728) <= lbl_803E23DC)
        {
            target = (void*)(*(int*)(p2 + 0x720) + 0x8);
            trickyUpdateApproachSpeed(p1, p2, lbl_803E2488, target, 1);
            trickyMove(p1, target);
            if (Objfsa_GetWalkGroupIndexAtPoint((float*)&((GameObject*)p1)->anim.worldPosX, 0x0) != 0)
            {
                ((TrickyRuntime*)p2)->growlLatState = 1;
                *(u8*)(p2 + 0xa) = 0;
                fz = lbl_803E23DC;
                *(f32*)(p2 + 0x71c) = fz;
                *(f32*)(p2 + 0x720) = fz;
                TRICKY_CLEAR_RESET_FLAGS(p2);
            }
        }
        break;
    }
}

#pragma scheduling on
static int trickyGuardIsBaddieTargetValid(TrickyRuntime* trickyState)
{
    u32 target = (u32)trickyState->guardTarget;
    int count;
    int* list;
    int i;

    list = ObjGroup_GetObjects(TRICKY_GUARD_APPROACH_GROUP, &count);
    for (i = 0; (s16)i < count; i++)
    {
        if ((u32)*list == target)
        {
            return 1;
        }
        list++;
    }
    return 0;
}

#pragma scheduling off
void trickyGuard(ObjAnimComponent* obj, TrickyRuntime* trickyState)
{
    char* strBase = lbl_8031D2E8;
    int i;
    void** slot;
    void** slot2;
    int i2;
    void* setup;
    void* state;
    int found;
    int newTarget;

    switch (trickyState->guardState)
    {
    case 0:
        trickyDebugPrint(strBase + 0x648);
        trickyState->guardWalkGroup = Objfsa_GetWalkGroupIndexAtPoint(trickyState->targetPosition, 0x0);
        trickyState->guardPoint[0] = (f32)(trickyState->homeObj->worldPosX - lbl_803E247C *
            mathSinf((lbl_803E2454 * trickyState->homeObj->rotX) / lbl_803E2458));
        trickyState->guardPoint[1] = trickyState->homeObj->worldPosY;
        trickyState->guardPoint[2] = (f32)(trickyState->homeObj->worldPosZ - lbl_803E247C *
            mathCosf((lbl_803E2454 * trickyState->homeObj->rotX) / lbl_803E2458));
        trickyState->guardCanSpawnHelpers = 0;
        trickyState->guardState = 1;
        break;
    case 1:
        trickyDebugPrint(strBase + 0x654);
        trickyFn_8013b368((void*)obj, lbl_803E2488, (void*)trickyState);
        if (trickyState->guardWalkGroup == Objfsa_GetWalkGroupIndexAtPoint(&obj->worldPosX, 0x0))
        {
            trickyState->guardState = 2;
        }
        break;
    case 2:
        trickyDebugPrint(strBase + 0x664);
        if (trickyFn_8013b368((void*)obj, lbl_803E2488, (void*)trickyState) == 0)
        {
            if ((u32)trickyState->targetPosition != (u32)trickyState->guardPoint)
            {
                trickyState->targetPosition = trickyState->guardPoint;
                TRICKY_CLEAR_TARGET_DIRTY(trickyState);
                trickyState->targetTurnTimer = 0;
            }
            trickyState->guardState = 3;
        }
        else
        {
            trickyGuardFindBaddieTarget(trickyState);
        }
        break;
    case 3:
        trickyDebugPrint(strBase + 0x674);
        if (trickyFn_8013b368((void*)obj, lbl_803E2488, (void*)trickyState) == 0)
        {
            if (lbl_803E23DC == *(f32*)((int)trickyState + 0x2ac))
            {
                found = 0;
            }
            else if (lbl_803E2410 == *(f32*)((int)trickyState + 0x2b0))
            {
                found = 1;
            }
            else if ((*(f32*)((int)trickyState + 0x2b4) - *(f32*)((int)trickyState + 0x2b0)) > lbl_803E2414)
            {
                found = 1;
            }
            else
            {
                found = 0;
            }
            if (found != 0)
            {
                objAnimFn_8013a3f0((int)obj, 0x8, lbl_803E243C, 0);
                *(f32*)((int)trickyState + 0x79c) = lbl_803E2440;
                *(f32*)((int)trickyState + 0x838) = lbl_803E23DC;
                trickyDebugPrint(strBase + 0x184);
            }
            else
            {
                objAnimFn_8013a3f0((int)obj, 0, lbl_803E2444, 0);
                trickyDebugPrint(strBase + 0x190);
            }
        }
        trickyGuardFindBaddieTarget(trickyState);
        break;
    case 4:
        trickyDebugPrint(strBase + 0x684);
        if (trickyFn_8013b368((void*)obj, lbl_803E247C, (void*)trickyState) == 0)
        {
            trickyState->flags = trickyState->flags | TRICKY_STATE_RESET_FLAG_10;
            if (*trickyState->helperSpawnCount != 0 && trickyState->guardCanSpawnHelpers != 0)
            {
                if ((u8)Obj_IsLoadingLocked() != 0)
                {
                    trickyState->flags = trickyState->flags | TRICKY_STATE_HELPERS_ACTIVE_FLAG;
                    for (i = 0, slot = (void**)trickyState; i < TRICKY_GUARD_HELPER_COUNT; i++)
                    {
                        setup = Obj_AllocObjectSetup(TRICKY_GUARD_HELPER_SETUP_SIZE, TRICKY_GUARD_HELPER_DEF_ID);
                        *(u8*)((char*)setup + 0x4) = 2;
                        *(u8*)((char*)setup + 0x5) = 1;
                        *(s16*)((char*)setup + 0x1a) = i;
                        slot[0x700 / 4] = (void*)Obj_SetupObject(setup, 5, obj->mapEventSlot, -1, obj->parent);
                        slot++;
                    }
                    Sfx_PlayFromObject((int)obj, 0x3db);
                    Sfx_AddLoopedObjectSound((int)obj, 0x3dc);
                }
                (*trickyState->helperSpawnCount)--;
                objAnimFn_8013a3f0((int)obj, 0x34, lbl_803E2444, 0x4000000);
                trickyState->guardState = 5;
            }
            else
            {
                objAnimFn_8013a3f0((int)obj, 0x32, lbl_803E23EC, 0x4000000);
                trickyState->guardState = 6;
            }
        }
        else
        {
            if (trickyState->guardWalkGroup == Objfsa_GetWalkGroupIndexAtPoint(trickyState->targetPosition, 0x0))
            {
                break;
            }
            newTarget = (int)&trickyState->homeObj->worldPosX;
            if ((u32)trickyState->targetPosition != newTarget)
            {
                trickyState->targetPosition = (f32*)newTarget;
                TRICKY_CLEAR_TARGET_DIRTY(trickyState);
                trickyState->targetTurnTimer = 0;
            }
            trickyState->guardState = 2;
            break;
        }
    case 5:
        trickyDebugPrint(strBase + 0x694);
        if ((double)obj->currentMoveProgress >= (double)lbl_803E24D0)
        {
            TRICKY_MARK_HELPERS_FINISHED(trickyState);
            for (i2 = 0, slot2 = (void**)trickyState; i2 < TRICKY_GUARD_HELPER_COUNT; i2++)
            {
                objSetAnimSpeedTo1(slot2[0x700 / 4]);
                slot2++;
            }
            Sfx_RemoveLoopedObjectSound((int)obj, 0x3dc);
            state = ((GameObject*)obj)->extra;
            if ((((u32)((TrickyState*)state)->unk58 >> 6) & 1) == 0)
            {
                s16 a0 = obj->currentMove;
                if (a0 >= 0x30 || a0 < 0x29)
                {
                    if (Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
                    {
                        objAudioFn_800393f8((int)obj, (char*)state + 0x3a8, 0x29d, 0, -1, 0);
                    }
                }
            }
            trickyState->flags &= ~(u64)TRICKY_STATE_RESET_FLAG_10;
            if (trickyGuardFindBaddieTarget(trickyState) == 0)
            {
                newTarget = (int)&trickyState->homeObj->worldPosX;
                if ((u32)trickyState->targetPosition != newTarget)
                {
                    trickyState->targetPosition = (f32*)newTarget;
                    TRICKY_CLEAR_TARGET_DIRTY(trickyState);
                    trickyState->targetTurnTimer = 0;
                }
                trickyState->guardState = 2;
            }
        }
        else if (trickyGuardIsBaddieTargetValid(trickyState) != 0)
        {
            int targ = (int)((TrickyRuntime*)((GameObject*)obj)->extra)->targetPosition;
            trickyTurnTowardYaw((int)obj, getAngle(
                                    -(*(f32*)targ - obj->worldPosX),
                                    -(*(f32*)(targ + 0x8) - obj->worldPosZ)));
        }
        break;
    case 6:
        trickyDebugPrint(strBase + 0x6a4);
        if ((double)obj->currentMoveProgress >= (double)lbl_803E24D0)
        {
            objAnimFn_8013a3f0((int)obj, 0x33, lbl_803E2444, 0x4000000);
            trickyState->guardTimer = lbl_803E23DC;
            state = ((GameObject*)obj)->extra;
            if ((((u32)((TrickyState*)state)->unk58 >> 6) & 1) == 0)
            {
                s16 a0 = obj->currentMove;
                if (a0 >= 0x30 || a0 < 0x29)
                {
                    if (Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
                    {
                        objAudioFn_800393f8((int)obj, (char*)state + 0x3a8, 0x299, 0x100, -1, 0);
                    }
                }
            }
            trickyState->guardState = 7;
        }
        else if (trickyGuardIsBaddieTargetValid(trickyState) != 0)
        {
            int targ = (int)((TrickyRuntime*)((GameObject*)obj)->extra)->targetPosition;
            trickyTurnTowardYaw((int)obj, getAngle(
                                    -(*(f32*)targ - obj->worldPosX),
                                    -(*(f32*)(targ + 0x8) - obj->worldPosZ)));
        }
        break;
    case 7:
        trickyDebugPrint(strBase + 0x6b8);
        if (randomGetRange(0, 10) == 0)
        {
            state = ((GameObject*)obj)->extra;
            if ((((u32)((TrickyState*)state)->unk58 >> 6) & 1) == 0)
            {
                s16 a0 = obj->currentMove;
                if (a0 >= 0x30 || a0 < 0x29)
                {
                    if (Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
                    {
                        objAudioFn_800393f8((int)obj, (char*)state + 0x3a8, 0x299, 0x100, -1, 0);
                    }
                }
            }
        }
        trickyState->guardTimer = trickyState->guardTimer + timeDelta;
        if (((double)trickyState->guardTimer >= (double)lbl_803E24D8 &&
                (double)getXZDistance(trickyState->targetPosition, &obj->worldPosX) >= (double)lbl_803E24C4) ||
            trickyGuardIsBaddieTargetValid(trickyState) == 0)
        {
            objAnimFn_8013a3f0((int)obj, 0x32, lbl_803E23F4, 0x4000000);
            trickyState->guardState = 8;
        }
        else
        {
            int targ = (int)((TrickyRuntime*)((GameObject*)obj)->extra)->targetPosition;
            trickyTurnTowardYaw((int)obj, getAngle(
                                    -(*(f32*)targ - obj->worldPosX),
                                    -(*(f32*)(targ + 0x8) - obj->worldPosZ)));
        }
        break;
    case 8:
        trickyDebugPrint(strBase + 0x6c8);
        if ((double)obj->currentMoveProgress <= (double)lbl_803E2420)
        {
            trickyState->flags &= ~(u64)TRICKY_STATE_RESET_FLAG_10;
            if (trickyGuardFindBaddieTarget(trickyState) == 0)
            {
                newTarget = (int)&trickyState->homeObj->worldPosX;
                if ((u32)trickyState->targetPosition != newTarget)
                {
                    trickyState->targetPosition = (f32*)newTarget;
                    TRICKY_CLEAR_TARGET_DIRTY(trickyState);
                    trickyState->targetTurnTimer = 0;
                }
                trickyState->guardState = 2;
            }
        }
        break;
    }
}

#pragma peephole on
int trickyGuardFindBaddieTarget(TrickyRuntime* trickyState)
{
    int count;
    f32 d;
    f32 bestDist;
    int* list;
    int i;
    int* groupObjects;
    u32 best = 0;

    groupObjects = ObjGroup_GetObjects(TRICKY_GUARD_APPROACH_GROUP, &count);
    i = 0;
    list = groupObjects;
    for (; (s16)i < count; i++)
    {
        d = getXZDistance((float*)(*list + 0x18), trickyState->guardPoint);
        if (best == 0)
        {
            if (trickyState->guardWalkGroup == Objfsa_GetWalkGroupIndexAtPoint((float*)(*list + 0x18), 0x0))
            {
                bestDist = d;
                best = *list;
            }
        }
        else if (d < bestDist)
        {
            if (trickyState->guardWalkGroup == Objfsa_GetWalkGroupIndexAtPoint((float*)(*list + 0x18), 0x0))
            {
                bestDist = d;
                best = *list;
            }
        }
        list++;
    }
    if (best != 0)
    {
        trickyState->guardTarget = (ObjAnimComponent*)best;
        if ((u32)trickyState->targetPosition != (best + 0x18))
        {
            trickyState->targetPosition = (f32*)(best + 0x18);
            *(s32*)&trickyState->flags &= ~(u64)TRICKY_STATE_TARGET_DIRTY_FLAG;
            trickyState->targetTurnTimer = 0;
        }
        trickyState->guardState = 4;
        return 1;
    }
    return 0;
}
#pragma peephole off

void fn_8014128C(void)
{
}
