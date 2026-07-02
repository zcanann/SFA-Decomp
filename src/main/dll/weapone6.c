/*
 * Tricky companion-AI substate handlers (TrickyState::substate machines).
 *
 * Each fn_* is one behavior tick dispatched off TrickyState->substate:
 *   fn_8013F100 - fetch/carry-stick behavior (grab a thrown stick via
 *                 fn_8017xxxx stick slots, swim or walk to it, return it).
 *   fn_8013F9E4 - idle/eat ambient state (random bark cues, eating anim).
 *   fn_8013FBE4 - track a TumbleweedBush target and steer Tricky toward it,
 *                 gated by game bit 0x48b.
 *   fn_8013FEC0 - simple swim-or-walk move toward the follow target.
 *
 * Common to all: water is detected by comparing waterLevel / unk2B0 / unk2B4
 * to pick a swim anim vs a ground anim. fn_8013F100 and fn_8013F9E4 play a
 * localized bark sfx unless one is already on object channel 16. Debug strings
 * are emitted via
 * trickyDebugPrint. tricky_state.h owns the TrickyState layout; the lbl_803E*
 * floats are this TU's tuning constants (.sdata2).
 */
#include "main/audio/sfx.h"
#include "main/frustum.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/dll/tricky_state.h"
#include "main/gameplay_runtime.h"

#define TRICKY_STATE_FLAGS_OFFSET 0x54
#define TRICKY_STATE_TARGET_DIRTY_FLAG 0x00000400
#define TRICKY_STATE_RESET_FLAG_10 0x00000010
#define TRICKY_STATE_RESET_FLAG_10000 0x00010000
#define TRICKY_STATE_RESET_FLAG_20000 0x00020000
#define TRICKY_STATE_RESET_FLAG_40000 0x00040000

typedef struct
{
    u8 hi : 4;
    u8 pad : 4;
} TrickyNibblePair;

#define TRICKY_CLEAR_TARGET_DIRTY(st) \
    (*(s32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~(u64)TRICKY_STATE_TARGET_DIRTY_FLAG)

#define TRICKY_CLEAR_TARGET_DIRTY_U32(st) \
    (*(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~(u64)TRICKY_STATE_TARGET_DIRTY_FLAG)

#define TRICKY_CLEAR_RESET_FLAGS(st) \
    { \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~(u64)TRICKY_STATE_RESET_FLAG_10; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~(u64)TRICKY_STATE_RESET_FLAG_10000; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~(u64)TRICKY_STATE_RESET_FLAG_20000; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~(u64)TRICKY_STATE_RESET_FLAG_40000; \
        { s8 mm; mm = -1; *(s8 *)((st) + 0xd) = mm; } \
    }

extern void objAudioFn_800393f8(int obj, void* audio, int sfxId, int volume, int param5, int param6);
extern void objAnimFn_8013a3f0(int obj, int animId, f32 blend, int flags);
extern int trickyFn_8013b368(int obj, f32 speed, int state);
extern int trickyFoodFn_8014460c(int obj, int state);
extern int tumbleweedbush_findNearestActive(void);
extern int fn_801CDE70(int);
extern f32 sqrtf(f32);
extern int fn_80179650(int slot);
extern void fn_80179678(int slot, int obj);
extern void fn_8017962C(int slot);
extern int fn_801793A4(int obj);
extern void fn_801796BC(int slot, int obj, double a, double b, double c);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern void Obj_FreeObject(int obj);
extern char sInWaterMessage[];
extern char lbl_8031D478[];
extern f32 timeDelta;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E8;
extern f32 lbl_803E2408;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E2454;
extern f32 lbl_803E2458;
extern f32 lbl_803E247C;
extern f32 lbl_803E2488;
extern f32 lbl_803E24A8;
extern f32 lbl_803E24C8;
extern f32 lbl_803E24D0;
extern f32 lbl_803E24D4;
extern f32 lbl_803E24EC;
extern f32 lbl_803E24F0;
extern f32 lbl_803E24F4;
extern f32 lbl_803E24F8;
extern f32 lbl_803E24FC;
extern f32 lbl_803E2500;

#pragma opt_propagation off
void fn_8013F100(int obj, register int state)
{
    int status;
    int extra;
    int useSwimAnim;
    s16 move;
    double bob;
    f32 fz;
    u8* targetPos;

    switch (((TrickyState*)state)->substate)
    {
    case 0:
        *(int*)&((TrickyState*)state)->unk700 = *(int*)&((TrickyState*)state)->followObj;
        *(float*)&((TrickyState*)state)->unk704 = lbl_803E24EC;
        ((TrickyState*)state)->substate = 1;
        ((TrickyState*)state)->unk7A4 = (f32)(s32)
        randomGetRange(150, 300);
        if (fn_80179650(*(int*)&((TrickyState*)state)->unk700) != 0)
        {
            status = trickyFn_8013b368(obj, lbl_803E24F0, state);
            if (status == 0)
            {
                if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                {
                    useSwimAnim = 0;
                }
                else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
                {
                    useSwimAnim = 1;
                }
                else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
                {
                    useSwimAnim = 1;
                }
                else
                {
                    useSwimAnim = 0;
                }
                if (useSwimAnim != 0)
                {
                    objAnimFn_8013a3f0(obj, 28, lbl_803E24F4, 0x4000000);
                }
                else
                {
                    objAnimFn_8013a3f0(obj, 17, lbl_803E24F4, 0x4000000);
                }
                *(int*)&((TrickyState*)state)->stateFlags |= TRICKY_STATE_RESET_FLAG_10;
                ((TrickyState*)state)->substate = 3;
                fn_80179678(*(int*)&((TrickyState*)state)->unk700, obj);
            }
            else if (status == 2)
            {
                extra = *(int*)&((GameObject*)obj)->extra;
                if ((((u32) * (u8*)(extra + 0x58) >> 6) & 1) == 0)
                {
                    move = ((GameObject*)obj)->anim.currentMove;
                    if (move >= 48 || move < 41)
                    {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0)
                        {
                            objAudioFn_800393f8(obj, (void*)(extra + 936), 861, 1280, -1, 0);
                        }
                    }
                }
                ((TrickyState*)state)->unk08 = 1;
                ((TrickyState*)state)->substate = 0;
                fz = lbl_803E23DC;
                ((TrickyState*)state)->unk71C = fz;
                ((TrickyState*)state)->unk720 = fz;
                TRICKY_CLEAR_RESET_FLAGS(state);
            }
        }
        else
        {
            status = trickyFn_8013b368(obj, lbl_803E2408, state);
            if (status == 0)
            {
                if (*(float*)&((TrickyState*)state)->unk704 > lbl_803E23DC)
                {
                    if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                    {
                        useSwimAnim = 0;
                    }
                    else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
                    {
                        useSwimAnim = 1;
                    }
                    else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
                    {
                        useSwimAnim = 1;
                    }
                    else
                    {
                        useSwimAnim = 0;
                    }
                    if (useSwimAnim != 0)
                    {
                        objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                        ((TrickyState*)state)->unk79C = lbl_803E2440;
                        ((TrickyState*)state)->unk838 = lbl_803E23DC;
                        trickyDebugPrint(sInWaterMessage);
                    }
                    else
                    {
                        objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                        trickyDebugPrint(lbl_8031D478);
                    }
                    *(float*)&((TrickyState*)state)->unk704 -= timeDelta;
                    if (*(float*)&((TrickyState*)state)->unk704 <= lbl_803E23DC)
                    {
                        if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                        {
                            useSwimAnim = 0;
                        }
                        else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
                        {
                            useSwimAnim = 1;
                        }
                        else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
                        {
                            useSwimAnim = 1;
                        }
                        else
                        {
                            useSwimAnim = 0;
                        }
                        if (useSwimAnim != 0)
                        {
                            *(float*)&((TrickyState*)state)->unk704 = lbl_803E24EC;
                        }
                        else
                        {
                            *(float*)&((TrickyState*)state)->unk708 = lbl_803E24F8;
                        }
                    }
                }
                else
                {
                    objAnimFn_8013a3f0(obj, 16, lbl_803E243C, 0x4000000);
                    *(float*)&((TrickyState*)state)->unk708 -= timeDelta;
                    if (*(float*)&((TrickyState*)state)->unk708 <= lbl_803E23DC)
                    {
                        *(float*)&((TrickyState*)state)->unk704 = lbl_803E24EC;
                    }
                }
            }
            else if (status == 1)
            {
                ((TrickyState*)state)->unk7A4 -= timeDelta;
                if (((TrickyState*)state)->unk7A4 <= lbl_803E23DC)
                {
                    ((TrickyState*)state)->unk7A4 = (f32)(s32)
                    randomGetRange(150, 300);
                    extra = *(int*)&((GameObject*)obj)->extra;
                    if ((((u32) * (u8*)(extra + 0x58) >> 6) & 1) != 0)
                    {
                        break;
                    }
                    move = ((GameObject*)obj)->anim.currentMove;
                    if (move < 48)
                    {
                        if (move >= 41)
                        {
                            break;
                        }
                    }
                    if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0)
                    {
                        objAudioFn_800393f8(obj, (void*)(extra + 936), 865, 1280, -1, 0);
                    }
                }
            }
            else
            {
                if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                {
                    useSwimAnim = 0;
                }
                else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
                {
                    useSwimAnim = 1;
                }
                else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
                {
                    useSwimAnim = 1;
                }
                else
                {
                    useSwimAnim = 0;
                }
                if (useSwimAnim != 0)
                {
                    objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                    ((TrickyState*)state)->unk79C = lbl_803E2440;
                    ((TrickyState*)state)->unk838 = lbl_803E23DC;
                    trickyDebugPrint(sInWaterMessage);
                }
                else
                {
                    objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                    trickyDebugPrint(lbl_8031D478);
                }
            }
        }
        break;
    case 1:
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E24FC)
        {
            status = *(int*)&((TrickyState*)state)->unk700;
            *(float*)(status + 0x10) += lbl_803E2488;
            bob = -mathCosf(lbl_803E2454 * (f32)(s32) * (short*)obj / lbl_803E2458);
            fn_801796BC(*(int*)&((TrickyState*)state)->unk700, obj,
                        -mathSinf(lbl_803E2454 * (f32)(s32) * (short*)obj / lbl_803E2458),
                        lbl_803E23E8, bob);
            ((TrickyState*)state)->substate = 2;
        }
        break;
    case 2:
        if ((((TrickyState*)state)->stateFlags & 0x8000000) != 0)
        {
            *(float*)(state + 0x828) = lbl_803E2408;
            status = ((TrickyState*)state)->progressPtr;
            if (*(u8*)(status + 2) >= 0xef)
            {
                *(u8*)(status + 2) = 0;
            }
            else
            {
                *(u8*)(status + 2) += 1;
            }
            {
                u32 m;
                u32 f2 = *(u32*)(state + TRICKY_STATE_FLAGS_OFFSET);
                m = ~TRICKY_STATE_RESET_FLAG_10;
                *(u32*)(state + TRICKY_STATE_FLAGS_OFFSET) = f2 & m;
            }
            ((TrickyState*)state)->substate = 7;
            targetPos = ((TrickyState*)state)->followObj + 24;
            if (((TrickyState*)state)->unk28 != targetPos)
            {
                ((TrickyState*)state)->unk28 = targetPos;
                {
                    u32 m;
                    u32 f2 = *(u32*)(state + TRICKY_STATE_FLAGS_OFFSET);
                    m = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                    *(u32*)(state + TRICKY_STATE_FLAGS_OFFSET) = f2 & m;
                }
                *(short*)&((TrickyState*)state)->unkD2 = 0;
            }
        }
        break;
    case 3:
        status = trickyFn_8013b368(obj, lbl_803E2408, state);
        if (status != 1)
        {
            if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
            {
                useSwimAnim = 0;
            }
            else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
            {
                useSwimAnim = 1;
            }
            else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
            {
                useSwimAnim = 1;
            }
            else
            {
                useSwimAnim = 0;
            }
            if (useSwimAnim != 0)
            {
                objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                ((TrickyState*)state)->unk79C = lbl_803E2440;
                ((TrickyState*)state)->unk838 = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            }
            else
            {
                objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                trickyDebugPrint(lbl_8031D478);
            }
            return;
        }
        if (fn_801793A4(*(int*)&((TrickyState*)state)->followObj) != 0)
        {
            *(float*)&((TrickyState*)state)->unk704 = lbl_803E24EC;
            ((TrickyState*)state)->substate = 1;
        }
        break;
    case 4:
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E24A8)
        {
            ((TrickyState*)state)->substate = 4;
        }
        break;
    case 5:
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E24D0)
        {
            targetPos = *(u8**)&((TrickyState*)state)->playerObj + 24;
            if (((TrickyState*)state)->unk28 != targetPos)
            {
                ((TrickyState*)state)->unk28 = targetPos;
                {
                    u32 m;
                    u32 f2 = *(u32*)(state + TRICKY_STATE_FLAGS_OFFSET);
                    m = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                    *(u32*)(state + TRICKY_STATE_FLAGS_OFFSET) = f2 & m;
                }
                *(short*)&((TrickyState*)state)->unkD2 = 0;
            }
            ((TrickyState*)state)->substate = 5;
            if (trickyFn_8013b368(obj, lbl_803E24C8, state) == 0)
            {
                if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                {
                    useSwimAnim = 0;
                }
                else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
                {
                    useSwimAnim = 1;
                }
                else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
                {
                    useSwimAnim = 1;
                }
                else
                {
                    useSwimAnim = 0;
                }
                if (useSwimAnim != 0)
                {
                    objAnimFn_8013a3f0(obj, 29, lbl_803E24F4, 0x4000000);
                }
                else
                {
                    objAnimFn_8013a3f0(obj, 19, lbl_803E24F4, 0x4000000);
                }
                ((TrickyState*)state)->substate = 6;
            }
        }
        break;
    case 6:
    case 7:
        break;
    }
    if (((((TrickyState*)state)->stateFlags & TRICKY_STATE_RESET_FLAG_10000) != 0) &&
        ViewFrustum_IsSphereVisible((float*)(obj + 0xc), lbl_803E2500) == 0)
    {
        Obj_FreeObject(*(int*)&((TrickyState*)state)->followObj);
    }
    else
    {
        fn_8017962C(*(int*)&((TrickyState*)state)->unk700);
    }
}

#pragma opt_propagation reset
void fn_8013F9E4(int obj, int state)
{
    int extra;
    int inWater;
    s16 move;

    if (trickyFoodFn_8014460c(obj, state) == 0)
    {
        if (trickyFn_8013b368(obj, lbl_803E2488, state) == 0)
        {
            ((TrickyState*)state)->unk740 -= timeDelta;
            if (((TrickyState*)state)->unk740 <= lbl_803E23DC)
            {
                ((TrickyState*)state)->unk740 = (f32)(s32)
                randomGetRange(500, 750);
                extra = *(int*)&((GameObject*)obj)->extra;
                if ((((u32) * (u8*)(extra + 0x58) >> 6) & 1) == 0)
                {
                    move = ((GameObject*)obj)->anim.currentMove;
                    if (move >= 48 || move < 41)
                    {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0)
                        {
                            objAudioFn_800393f8(obj, (void*)(extra + 936), 864, 1280, -1, 0);
                        }
                    }
                }
            }
            if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
            {
                inWater = 0;
            }
            else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
            {
                inWater = 1;
            }
            else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
            {
                inWater = 1;
            }
            else
            {
                inWater = 0;
            }
            if (inWater != 0)
            {
                objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                ((TrickyState*)state)->unk79C = lbl_803E2440;
                ((TrickyState*)state)->unk838 = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            }
            else
            {
                switch (((GameObject*)obj)->anim.currentMove)
                {
                case 13:
                    if ((((TrickyState*)state)->stateFlags & 0x8000000) != 0)
                    {
                        objAnimFn_8013a3f0(obj, 49, lbl_803E243C, 0);
                    }
                    break;
                case 49:
                    break;
                default:
                    objAnimFn_8013a3f0(obj, 13, lbl_803E2444, 0);
                    break;
                }
                trickyDebugPrint(lbl_8031D478);
            }
        }
    }
}

#pragma opt_propagation off
void fn_8013FBE4(int obj, register int state)
{
    int inWater;
    float dx;
    float dz;
    float distance;
    f32 fz;
    float* targetPos;
    u8* trackedObj;
    u32 currentBit;
    u8 bitIndex;
    u8 newBit;

    switch (((TrickyState*)state)->substate)
    {
    case 0:
        newBit = GameBit_Get(0x48b);
        ((TrickyNibblePair*)(state + 0x700))->hi = newBit;
        *(int*)&((TrickyState*)state)->unk710 = 0;
        ((TrickyState*)state)->substate = 1;
    case 1:
        currentBit = GameBit_Get(0x48b);
        bitIndex = ((TrickyNibblePair*)(state + 0x700))->hi;
        if (bitIndex != currentBit)
        {
            ((TrickyNibblePair*)(state + 0x700))->hi++;
            **(u8**)state -= 2;
        }
        targetPos = (float*)fn_801CDE70(*(int*)&((TrickyState*)state)->followObj);
        trackedObj = (u8*)tumbleweedbush_findNearestActive();
        if (trackedObj != 0 && **(u8**)state != 0)
        {
            if (trackedObj != *(u8**)&((TrickyState*)state)->unk710 &&
                ((TrickyState*)state)->unk28 != (u8*)(state + 0x704))
            {
                ((TrickyState*)state)->unk28 = (u8*)(state + 0x704);
                {
                    u32 m;
                    u32 f2 = *(u32*)(state + TRICKY_STATE_FLAGS_OFFSET);
                    m = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                    *(u32*)(state + TRICKY_STATE_FLAGS_OFFSET) = f2 & m;
                }
                *(short*)&((TrickyState*)state)->unkD2 = 0;
            }
            dx = *targetPos - ((GameObject*)obj)->anim.worldPosX;
            dz = targetPos[2] - ((GameObject*)obj)->anim.worldPosZ;
            distance = sqrtf(dx * dx + dz * dz);
            if (lbl_803E23DC != distance)
            {
                dx = dx / distance;
                dz = dz / distance;
            }
            distance = lbl_803E24D4;
            *(float*)&((TrickyState*)state)->unk704 = -(distance * dx - *(float*)(trackedObj + 0x18));
            *(float*)&((TrickyState*)state)->unk708 = *(float*)(trackedObj + 0x1c);
            *(float*)&((TrickyState*)state)->unk70C = -(distance * dz - *(float*)(trackedObj + 0x20));
            if (trickyFn_8013b368(obj, lbl_803E2488, state) == 0)
            {
                if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                {
                    inWater = 0;
                }
                else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
                {
                    inWater = 1;
                }
                else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
                {
                    inWater = 1;
                }
                else
                {
                    inWater = 0;
                }
                if (inWater != 0)
                {
                    objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                    ((TrickyState*)state)->unk79C = lbl_803E2440;
                    ((TrickyState*)state)->unk838 = lbl_803E23DC;
                    trickyDebugPrint(sInWaterMessage);
                }
                else
                {
                    objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                    trickyDebugPrint(lbl_8031D478);
                }
            }
        }
        else
        {
            ((TrickyState*)state)->unk08 = 1;
            ((TrickyState*)state)->substate = 0;
            fz = lbl_803E23DC;
            ((TrickyState*)state)->unk71C = fz;
            ((TrickyState*)state)->unk720 = fz;
            TRICKY_CLEAR_RESET_FLAGS(state);
        }
        break;
    }
}

#pragma opt_propagation reset
void fn_8013FEC0(int obj, int state)
{
    int inWater;
    int result;

    result = trickyFn_8013b368(obj, lbl_803E247C, state);
    if (result == 0)
    {
        if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
        {
            inWater = 0;
        }
        else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
        {
            inWater = 1;
        }
        else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
        {
            inWater = 1;
        }
        else
        {
            inWater = 0;
        }
        if (inWater != 0)
        {
            objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
            ((TrickyState*)state)->unk79C = lbl_803E2440;
            ((TrickyState*)state)->unk838 = lbl_803E23DC;
            trickyDebugPrint(sInWaterMessage);
        }
        else
        {
            objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
            trickyDebugPrint(lbl_8031D478);
        }
    }
}
