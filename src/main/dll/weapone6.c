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
 * Common to all: water is detected by comparing waterLevel / eventTime /
 * currentTime to pick a swim anim vs a ground anim. fn_8013F100 and fn_8013F9E4 play a
 * localized bark sfx unless one is already on object channel 16. Debug strings
 * are emitted via
 * trickyDebugPrint. tricky_state.h owns the TrickyState layout; the lbl_803E*
 * floats are pooled .sdata2 tuning constants shared with the sibling tricky_*
 * TUs (not ownable by this unit).
 *
 * fn_8013F100's case numbering/fallthrough (0 into 1, 4 into 5 via the label
 * inside the if) is ground truth from the retail jump table at 0x8031D910 --
 * do not renumber or "un-nest" case 5.
 */
#include "main/audio/sfx.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frustum.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/dll/dll_00F5_sidekickball.h"
#include "main/dll/dll_01A0_nwgeyser.h"
#include "main/dll/tricky_state.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/objprint_sound_api.h"
#include "main/dll/dll_00C4_tricky_api.h"
#include "main/dll/skeetla_anim_api.h"
#include "main/dll/tricky_substates_ext.h"
#include "main/dll/trickyfollow_ext.h"
#include "main/dll/dll_00D1_tumbleweedbush.h"

typedef struct
{
    u8 hi : 4;
    u8 pad : 4;
} TrickyNibblePair;

#define TRICKY_STATE_TARGET_DIRTY_FLAG 0x00000400
#define TRICKY_STATE_RESET_FLAG_10     0x00000010
#define TRICKY_STATE_RESET_FLAG_10000  0x00010000
#define TRICKY_STATE_RESET_FLAG_20000  0x00020000
#define TRICKY_STATE_RESET_FLAG_40000  0x00040000

#define TRICKY_CLEAR_RESET_FLAGS(st)                                                                                   \
    {                                                                                                                  \
        *(u32*)&((TrickyState*)(st))->stateFlags &= ~(u64)TRICKY_STATE_RESET_FLAG_10;                                  \
        *(u32*)&((TrickyState*)(st))->stateFlags &= ~(u64)TRICKY_STATE_RESET_FLAG_10000;                               \
        *(u32*)&((TrickyState*)(st))->stateFlags &= ~(u64)TRICKY_STATE_RESET_FLAG_20000;                               \
        *(u32*)&((TrickyState*)(st))->stateFlags &= ~(u64)TRICKY_STATE_RESET_FLAG_40000;                               \
        {                                                                                                              \
            s8 mm;                                                                                                     \
            mm = -1;                                                                                                   \
            *(s8*)&((TrickyState*)(st))->commandPhase = mm;                                                            \
        }                                                                                                              \
    }

extern char sInWaterMessage[];
extern char lbl_8031D478[];
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
void fn_8013F100(GameObject* obj, register int state)
{
    int status;
    int extra;
    int useSwimAnim;
    s16 move;
    f32 bob;
    f32 resetTimer;
    u8* targetPos;

    switch (((TrickyState*)state)->substate)
    {
    case 0:
        ((TrickyState*)state)->scratch700.ptr = ((TrickyState*)state)->followObj;
        ((TrickyState*)state)->scratch704.f = lbl_803E24EC;
        ((TrickyState*)state)->substate = 1;
        ((TrickyState*)state)->sfxIntervalTimer = (f32)(s32)randomGetRange(150, 300);
        /* fall through */
    case 1:
        if (fn_80179650((GameObject*)((TrickyState*)state)->scratch700.i) != 0)
        {
            status = trickyFn_8013b368(obj, lbl_803E24F0, (TrickyState*)state);
            if (status == 0)
            {
                if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                {
                    useSwimAnim = 0;
                }
                else if (lbl_803E2410 == ((TrickyState*)state)->eventTime)
                {
                    useSwimAnim = 1;
                }
                else if (((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime > lbl_803E2414)
                {
                    useSwimAnim = 1;
                }
                else
                {
                    useSwimAnim = 0;
                }
                if (useSwimAnim != 0)
                {
                    objAnimFn_8013a3f0((int)obj, 28, lbl_803E24F4, 0x4000000);
                }
                else
                {
                    objAnimFn_8013a3f0((int)obj, 17, lbl_803E24F4, 0x4000000);
                }
                *(int*)&((TrickyState*)state)->stateFlags |= TRICKY_STATE_RESET_FLAG_10;
                ((TrickyState*)state)->substate = 3;
                fn_80179678((GameObject*)(((TrickyState*)state)->scratch700.i), obj);
            }
            else if (status == 2)
            {
                extra = *(int*)&(obj)->extra;
                if ((((u32) * (u8*)(extra + 0x58) >> 6) & 1) == 0)
                {
                    move = (obj)->anim.currentMove;
                    if (move >= 48 || move < 41)
                    {
                        if (Sfx_IsPlayingFromObjectChannel((int)obj, 16) == 0)
                        {
                            objAudioFn_800393f8(obj, &((TrickyState*)extra)->soundState, 861, 1280, -1, 0);
                        }
                    }
                }
                ((TrickyState*)state)->stateIndex = 1;
                ((TrickyState*)state)->substate = 0;
                resetTimer = lbl_803E23DC;
                ((TrickyState*)state)->cooldownA = resetTimer;
                ((TrickyState*)state)->cooldownB.f = resetTimer;
                TRICKY_CLEAR_RESET_FLAGS(state);
            }
        }
        else
        {
            status = trickyFn_8013b368(obj, lbl_803E2408, (TrickyState*)state);
            if (status == 0)
            {
                if (((TrickyState*)state)->scratch704.f > lbl_803E23DC)
                {
                    if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                    {
                        useSwimAnim = 0;
                    }
                    else if (lbl_803E2410 == ((TrickyState*)state)->eventTime)
                    {
                        useSwimAnim = 1;
                    }
                    else if (((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime > lbl_803E2414)
                    {
                        useSwimAnim = 1;
                    }
                    else
                    {
                        useSwimAnim = 0;
                    }
                    if (useSwimAnim != 0)
                    {
                        objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                        ((TrickyState*)state)->cooldownC = lbl_803E2440;
                        ((TrickyState*)state)->particleTimer = lbl_803E23DC;
                        trickyDebugPrint(sInWaterMessage);
                    }
                    else
                    {
                        objAnimFn_8013a3f0((int)obj, 0, lbl_803E2444, 0);
                        trickyDebugPrint(lbl_8031D478);
                    }
                    ((TrickyState*)state)->scratch704.f -= timeDelta;
                    if (((TrickyState*)state)->scratch704.f <= lbl_803E23DC)
                    {
                        if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                        {
                            useSwimAnim = 0;
                        }
                        else if (lbl_803E2410 == ((TrickyState*)state)->eventTime)
                        {
                            useSwimAnim = 1;
                        }
                        else if (((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime > lbl_803E2414)
                        {
                            useSwimAnim = 1;
                        }
                        else
                        {
                            useSwimAnim = 0;
                        }
                        if (useSwimAnim != 0)
                        {
                            ((TrickyState*)state)->scratch704.f = lbl_803E24EC;
                        }
                        else
                        {
                            ((TrickyState*)state)->scratch708.f = lbl_803E24F8;
                        }
                    }
                }
                else
                {
                    objAnimFn_8013a3f0((int)obj, 16, lbl_803E243C, 0x4000000);
                    ((TrickyState*)state)->scratch708.f -= timeDelta;
                    if (((TrickyState*)state)->scratch708.f <= lbl_803E23DC)
                    {
                        ((TrickyState*)state)->scratch704.f = lbl_803E24EC;
                    }
                }
            }
            else if (status == 1)
            {
                ((TrickyState*)state)->sfxIntervalTimer -= timeDelta;
                if (((TrickyState*)state)->sfxIntervalTimer <= lbl_803E23DC)
                {
                    ((TrickyState*)state)->sfxIntervalTimer = (f32)(s32)randomGetRange(150, 300);
                    extra = *(int*)&(obj)->extra;
                    if ((((u32) * (u8*)(extra + 0x58) >> 6) & 1) != 0)
                    {
                        break;
                    }
                    move = (obj)->anim.currentMove;
                    if (move < 48)
                    {
                        if (move >= 41)
                        {
                            break;
                        }
                    }
                    if (Sfx_IsPlayingFromObjectChannel((int)obj, 16) == 0)
                    {
                        objAudioFn_800393f8(obj, &((TrickyState*)extra)->soundState, 865, 1280, -1, 0);
                    }
                }
            }
            else
            {
                if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                {
                    useSwimAnim = 0;
                }
                else if (lbl_803E2410 == ((TrickyState*)state)->eventTime)
                {
                    useSwimAnim = 1;
                }
                else if (((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime > lbl_803E2414)
                {
                    useSwimAnim = 1;
                }
                else
                {
                    useSwimAnim = 0;
                }
                if (useSwimAnim != 0)
                {
                    objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                    ((TrickyState*)state)->cooldownC = lbl_803E2440;
                    ((TrickyState*)state)->particleTimer = lbl_803E23DC;
                    trickyDebugPrint(sInWaterMessage);
                }
                else
                {
                    objAnimFn_8013a3f0((int)obj, 0, lbl_803E2444, 0);
                    trickyDebugPrint(lbl_8031D478);
                }
            }
        }
        break;
    case 6:
        if ((obj)->anim.currentMoveProgress >= lbl_803E24FC)
        {
            status = ((TrickyState*)state)->scratch700.i;
            *(float*)(status + 0x10) += lbl_803E2488;
            bob = -mathCosf(lbl_803E2454 * (f32)(s32) * (short*)obj / lbl_803E2458);
            fn_801796BC((GameObject*)((TrickyState*)state)->scratch700.i, obj,
                        -mathSinf(lbl_803E2454 * (f32)(s32) * (short*)obj / lbl_803E2458), lbl_803E23E8, bob);
            ((TrickyState*)state)->substate = 2;
        }
        break;
    case 2:
        if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0)
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
                u32 f2 = ((TrickyState*)state)->stateFlags;
                m = ~TRICKY_STATE_RESET_FLAG_10;
                ((TrickyState*)state)->stateFlags = f2 & m;
            }
            ((TrickyState*)state)->substate = 7;
            targetPos = ((TrickyState*)state)->followObj + 24;
            if (((TrickyState*)state)->targetPosPtr != targetPos)
            {
                ((TrickyState*)state)->targetPosPtr = targetPos;
                {
                    u32 m;
                    u32 f2 = ((TrickyState*)state)->stateFlags;
                    m = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                    ((TrickyState*)state)->stateFlags = f2 & m;
                }
                ((TrickyState*)state)->linkedWalkGroup = 0;
            }
        }
        break;
    case 7:
        status = trickyFn_8013b368(obj, lbl_803E2408, (TrickyState*)state);
        if (status != 1)
        {
            if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
            {
                useSwimAnim = 0;
            }
            else if (lbl_803E2410 == ((TrickyState*)state)->eventTime)
            {
                useSwimAnim = 1;
            }
            else if (((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime > lbl_803E2414)
            {
                useSwimAnim = 1;
            }
            else
            {
                useSwimAnim = 0;
            }
            if (useSwimAnim != 0)
            {
                objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                ((TrickyState*)state)->cooldownC = lbl_803E2440;
                ((TrickyState*)state)->particleTimer = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            }
            else
            {
                objAnimFn_8013a3f0((int)obj, 0, lbl_803E2444, 0);
                trickyDebugPrint(lbl_8031D478);
            }
            return;
        }
        if (fn_801793A4((GameObject*)*(int*)&((TrickyState*)state)->followObj) != 0)
        {
            ((TrickyState*)state)->scratch704.f = lbl_803E24EC;
            ((TrickyState*)state)->substate = 1;
        }
        break;
    case 3:
        if ((obj)->anim.currentMoveProgress >= lbl_803E24A8)
        {
            ((TrickyState*)state)->substate = 4;
        }
        break;
    case 4:
        if ((obj)->anim.currentMoveProgress >= lbl_803E24D0)
        {
            targetPos = *(u8**)&((TrickyState*)state)->playerObj + 24;
            if (((TrickyState*)state)->targetPosPtr != targetPos)
            {
                ((TrickyState*)state)->targetPosPtr = targetPos;
                {
                    u32 m;
                    u32 f2 = ((TrickyState*)state)->stateFlags;
                    m = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                    ((TrickyState*)state)->stateFlags = f2 & m;
                }
                ((TrickyState*)state)->linkedWalkGroup = 0;
            }
            ((TrickyState*)state)->substate = 5;
        case 5:
            if (trickyFn_8013b368(obj, lbl_803E24C8, (TrickyState*)state) == 0)
            {
                if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                {
                    useSwimAnim = 0;
                }
                else if (lbl_803E2410 == ((TrickyState*)state)->eventTime)
                {
                    useSwimAnim = 1;
                }
                else if (((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime > lbl_803E2414)
                {
                    useSwimAnim = 1;
                }
                else
                {
                    useSwimAnim = 0;
                }
                if (useSwimAnim != 0)
                {
                    objAnimFn_8013a3f0((int)obj, 29, lbl_803E24F4, 0x4000000);
                }
                else
                {
                    objAnimFn_8013a3f0((int)obj, 19, lbl_803E24F4, 0x4000000);
                }
                ((TrickyState*)state)->substate = 6;
            }
        }
        break;
    }
    if (((((TrickyState*)state)->stateFlags & TRICKY_STATE_RESET_FLAG_10000) != 0) &&
        ViewFrustum_IsSphereVisible(&(obj)->anim.localPosX, lbl_803E2500) == 0)
    {
        Obj_FreeObject((GameObject*)((TrickyState*)state)->followObj);
    }
    else
    {
        fn_8017962C((GameObject*)((TrickyState*)state)->scratch700.i);
    }
}

void fn_8013F9E4(GameObject* obj, int state)
{
    int extra;
    int inWater;
    s16 move;

    if (tricky_handleFeedOrTalk(obj, (int*)state) == 0)
    {
        if (trickyFn_8013b368(obj, lbl_803E2488, (TrickyState*)state) == 0)
        {
            ((TrickyState*)state)->idleSfxTimer -= timeDelta;
            if (((TrickyState*)state)->idleSfxTimer <= lbl_803E23DC)
            {
                ((TrickyState*)state)->idleSfxTimer = (f32)(s32)randomGetRange(500, 750);
                extra = *(int*)&obj->extra;
                if ((((u32) * (u8*)(extra + 0x58) >> 6) & 1) == 0)
                {
                    move = obj->anim.currentMove;
                    if (move >= 48 || move < 41)
                    {
                        if (Sfx_IsPlayingFromObjectChannel((int)obj, 16) == 0)
                        {
                            objAudioFn_800393f8(obj, &((TrickyState*)extra)->soundState, 864, 1280, -1, 0);
                        }
                    }
                }
            }
            if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
            {
                inWater = 0;
            }
            else if (lbl_803E2410 == ((TrickyState*)state)->eventTime)
            {
                inWater = 1;
            }
            else if (((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime > lbl_803E2414)
            {
                inWater = 1;
            }
            else
            {
                inWater = 0;
            }
            if (inWater != 0)
            {
                objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                ((TrickyState*)state)->cooldownC = lbl_803E2440;
                ((TrickyState*)state)->particleTimer = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            }
            else
            {
                switch (obj->anim.currentMove)
                {
                case 13:
                    if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0)
                    {
                        objAnimFn_8013a3f0((int)obj, 49, lbl_803E243C, 0);
                    }
                    break;
                case 49:
                    break;
                default:
                    objAnimFn_8013a3f0((int)obj, 13, lbl_803E2444, 0);
                    break;
                }
                trickyDebugPrint(lbl_8031D478);
            }
        }
    }
}

void fn_8013FBE4(GameObject* obj, register int state)
{
    int inWater;
    float dx;
    float dz;
    float distance;
    f32 resetTimer;
    float* targetPos;
    GameObject* trackedObj;
    u32 currentBit;
    u8 bitIndex;
    u8 newBit;

    switch (((TrickyState*)state)->substate)
    {
    case 0:
        newBit = mainGetBit(GAMEBIT_NW_MammothTumbleweedCount);
        ((TrickyNibblePair*)&((TrickyState*)state)->scratch700)->hi = newBit;
        ((TrickyState*)state)->scratch710.i = 0;
        ((TrickyState*)state)->substate = 1;
    case 1:
        currentBit = mainGetBit(GAMEBIT_NW_MammothTumbleweedCount);
        bitIndex = ((TrickyNibblePair*)&((TrickyState*)state)->scratch700)->hi;
        if (bitIndex != currentBit)
        {
            ((TrickyNibblePair*)&((TrickyState*)state)->scratch700)->hi++;
            **(u8**)state -= 2;
        }
        targetPos = fn_801CDE70((GameObject*)((TrickyState*)state)->followObj);
        trackedObj = tumbleweedbush_findNearestActive(targetPos);
        if (trackedObj != 0 && **(u8**)state != 0)
        {
            if (trackedObj != ((TrickyState*)state)->scratch710.obj &&
                ((TrickyState*)state)->targetPosPtr != (u8*)(state + 0x704))
            {
                ((TrickyState*)state)->targetPosPtr = (u8*)(state + 0x704);
                {
                    u32 m;
                    u32 f2 = ((TrickyState*)state)->stateFlags;
                    m = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                    ((TrickyState*)state)->stateFlags = f2 & m;
                }
                ((TrickyState*)state)->linkedWalkGroup = 0;
            }
            dx = *targetPos - obj->anim.worldPosX;
            dz = targetPos[2] - obj->anim.worldPosZ;
            distance = sqrtf(dx * dx + dz * dz);
            if (lbl_803E23DC != distance)
            {
                dx = dx / distance;
                dz = dz / distance;
            }
            distance = lbl_803E24D4;
            ((TrickyState*)state)->scratch704.f = -(distance * dx - trackedObj->anim.worldPosX);
            ((TrickyState*)state)->scratch708.f = trackedObj->anim.worldPosY;
            ((TrickyState*)state)->scratch70C.f = -(distance * dz - trackedObj->anim.worldPosZ);
            if (trickyFn_8013b368(obj, lbl_803E2488, (TrickyState*)state) == 0)
            {
                if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                {
                    inWater = 0;
                }
                else if (lbl_803E2410 == ((TrickyState*)state)->eventTime)
                {
                    inWater = 1;
                }
                else if (((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime > lbl_803E2414)
                {
                    inWater = 1;
                }
                else
                {
                    inWater = 0;
                }
                if (inWater != 0)
                {
                    objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                    ((TrickyState*)state)->cooldownC = lbl_803E2440;
                    ((TrickyState*)state)->particleTimer = lbl_803E23DC;
                    trickyDebugPrint(sInWaterMessage);
                }
                else
                {
                    objAnimFn_8013a3f0((int)obj, 0, lbl_803E2444, 0);
                    trickyDebugPrint(lbl_8031D478);
                }
            }
        }
        else
        {
            ((TrickyState*)state)->stateIndex = 1;
            ((TrickyState*)state)->substate = 0;
            resetTimer = lbl_803E23DC;
            ((TrickyState*)state)->cooldownA = resetTimer;
            ((TrickyState*)state)->cooldownB.f = resetTimer;
            TRICKY_CLEAR_RESET_FLAGS(state);
        }
        break;
    }
}

void fn_8013FEC0(int obj, int state)
{
    int inWater;
    int result;

    result = trickyFn_8013b368((GameObject*)obj, lbl_803E247C, (TrickyState*)state);
    if (result == 0)
    {
        if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
        {
            inWater = 0;
        }
        else if (lbl_803E2410 == ((TrickyState*)state)->eventTime)
        {
            inWater = 1;
        }
        else if (((TrickyState*)state)->currentTime - ((TrickyState*)state)->eventTime > lbl_803E2414)
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
            ((TrickyState*)state)->cooldownC = lbl_803E2440;
            ((TrickyState*)state)->particleTimer = lbl_803E23DC;
            trickyDebugPrint(sInWaterMessage);
        }
        else
        {
            objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
            trickyDebugPrint(lbl_8031D478);
        }
    }
}
