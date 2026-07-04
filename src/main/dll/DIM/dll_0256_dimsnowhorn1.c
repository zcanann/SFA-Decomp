/*
 * dll_0256_dimsnowhorn1 (DLL 0x256) - the rideable SnowHorn mammoth found in
 * DIM (Dinosaur InfernoMountain).  Fox can mount the mammoth and use it to
 * clear puzzle obstacles.  The object runs a 12-state BaddieState machine
 * (stateHandler00-0B); the riding sub-loop (fn_802BB4B4) handles stick/button
 * input and the air-meter while mounted, and DIMSnowHorn1_update coordinates
 * the full per-frame tick.
 */
#include "main/dll/DIM/dll_802B9780_shared.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/audio/sfx_trigger_ids.h"

#define OBJGROUP_SNOWHORN_PUZZLE   0x13  /* puzzle-target object group for nearest-object search */
#define GAMEBIT_SNOWHORN_RIDING    0x3e3 /* set while Fox is mounted on the SnowHorn */
#define GAMEBIT_SNOWHORN_AIR_DRAIN 0x3e2 /* set to drain the air meter each frame */
#define GAMEBIT_SNOWHORN_AIR_RESET 0x3e9 /* set to reset the air meter to full */
#define GAMEBIT_SNOWHORN_PUZZLE    0x170 /* puzzle-step trigger, counts pushes */
#define PAD_BUTTON_A               0x100 /* A button */

/* Per-object extra state (getExtraSize == 0xD0C); BaddieState is the prefix. */
typedef struct DIMSnowHorn1State
{
    BaddieState baddie;
    u8 lookController[0x96D - 0x35C]; /* dll_2E look-controller block at 0x35C (start evidenced; true extent unknown) */
    u8 unk96D;
    u8 pad96E[0x980 - 0x96E];
    u8 playerNearby; /* 0x980: 1 when player within mount range (mountMode==0); gates spawnPos capture */
    u8 pad981[3];
    f32 spawnPosX;
    f32 spawnPosY;
    f32 spawnPosZ;
    u8 pad990[0x9E8 - 0x990];
    f32 pathPosX; /* model-matrix offset vec */
    f32 pathPosY;
    f32 pathPosZ;
    u8 pad9F4[0xA84 - 0x9F4];
    s16 countdownTimer;
    s16 advanceCountThreshold; /* 0xA86: push-count at state+0x334 must reach this (=5) to advance state */
    s16 airMeterValue;
    u8 mountMode; /* 0=unmounted, 2=riding */
    u8 padA8B;
    u8 mode;
    u8 triggerMode;
    u8 flags; /* 0xA8E: bit0x2 riding (GAMEBIT_SNOWHORN_RIDING), bit0x8 hitvol-priority, bit0x20 sequence-triggered */
    u8 queryFlagA8F; /* 0xA8F: nonzero queried by DIMSnowHorn1_func14 (set cross-DLL) */
    u8 queryFlagA90; /* 0xA90: nonzero queried by DIMSnowHorn1_func11 (set cross-DLL) */
    u8 proximityPhase; /* 0xA91: 0/1/2 phase toggling linked objects by player distance (stateHandler05) */
    u8 padA92[0xD00 - 0xA92];
    u8 hitReactState; /* 0xD00: ObjHitReact_Update persistent state (in/out), gates fn_8003A168 */
    u8 padD01[0xB];
} DIMSnowHorn1State;

STATIC_ASSERT(sizeof(DIMSnowHorn1State) == 0xD0C);
STATIC_ASSERT(offsetof(DIMSnowHorn1State, countdownTimer) == 0xA84);

/* DIMSnowHorn1State.flags bits */
#define SNOWHORN1_FLAG_RIDING 0x2         /* GAMEBIT_SNOWHORN_RIDING active (set cross-DLL) */
#define SNOWHORN1_FLAG_HITVOL_PRIO 0x8    /* suppress hit-volume priority this frame */
#define SNOWHORN1_FLAG_SEQ_TRIGGERED 0x20 /* interaction sequence armed */

void DIMSnowHorn1_func23(void)
{
}

int DIMSnowHorn1_defaultStateHandler(void) { return 0x0; }

int DIMSnowHorn1_stateHandler04(int obj, int state)
{
    f32 k = lbl_803E8234;
    int idx;

    ((DIMSnowHorn1State*)state)->baddie.animSpeedC = k;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedB = k;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedA = k;
    ((GameObject*)obj)->anim.velocityX = k;
    ((GameObject*)obj)->anim.velocityY = k;
    ((GameObject*)obj)->anim.velocityZ = k;
    *(u32*)((char*)state) |= 0x200000;

    if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveJustStartedA != 0)
    {
        idx = randomGetRange(0, 1);
        ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803DC740[idx];
        ObjAnim_SetCurrentMove(obj, lbl_803DC73C[idx], lbl_803E8234, 0);
    }
    if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveDone != 0)
    {
        return -2;
    }
    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
    {
        (*gObjectTriggerInterface)->runSequence(
            randomGetRange(0, 2) + 6, (void*)obj, -1);
        buttonDisable(0, PAD_BUTTON_A);
    }
    return 0;
}

int DIMSnowHorn1_stateHandler00(int obj)
{
    DIMSnowHorn1State* inner = ((GameObject*)obj)->extra;

    switch (inner->mode)
    {
    case 0:
        if (GameBit_Get(0xf3))
        {
            inner->flags |= SNOWHORN1_FLAG_SEQ_TRIGGERED;
        }
        return 2;
    case 5:
        return 3;
    case 4:
        if (GameBit_Get(0x1db)) return 8;
        return 6;
    case 1:
        if (GameBit_Get(0x16f)) return 8;
        if (GameBit_Get(0x28)) return 7;
        if (GameBit_Get(0x27)) return 7;
        return 6;
    case 3:
        return 8;
    default:
        return 8;
    }
}

int DIMSnowHorn1_stateHandler02(int obj, int state, f32 fv)
{
    DIMSnowHorn1State* inner = ((GameObject*)obj)->extra;
    f32 k = lbl_803E8234;
    s16 v;

    ((DIMSnowHorn1State*)state)->baddie.animSpeedC = k;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedB = k;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedA = k;
    ((GameObject*)obj)->anim.velocityX = k;
    ((GameObject*)obj)->anim.velocityY = k;
    ((GameObject*)obj)->anim.velocityZ = k;
    *(u32*)((char*)state) |= 0x200000;
    ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803E827C;

    if (((GameObject*)obj)->anim.currentMove != lbl_803DC748)
    {
        ObjAnim_SetCurrentMove(obj, lbl_803DC748, k, 0);
    }

    inner->countdownTimer = randomGetRange(0x4b0, 0x960);
    v = inner->countdownTimer - (int)fv;
    inner->countdownTimer = v;
    if (v <= 0)
    {
        return -4;
    }
    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
    {
        (*gObjectTriggerInterface)->runSequence(
            randomGetRange(0, 2) + 6, (void*)obj, -1);
        buttonDisable(0, PAD_BUTTON_A);
    }
    return 0;
}

int DIMSnowHorn1_stateHandler03(int obj, int state)
{
    DIMSnowHorn1State* inner = ((GameObject*)obj)->extra;
    f32 k = lbl_803E8234;
    int idx;

    ((DIMSnowHorn1State*)state)->baddie.animSpeedC = k;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedB = k;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedA = k;
    ((GameObject*)obj)->anim.velocityX = k;
    ((GameObject*)obj)->anim.velocityY = k;
    ((GameObject*)obj)->anim.velocityZ = k;
    *(u32*)((char*)state) |= 0x200000;

    if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveJustStartedA != 0)
    {
        idx = randomGetRange(0, 1);
        ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803DC740[idx];
        ObjAnim_SetCurrentMove(obj, lbl_803DC73C[idx], lbl_803E8234, 0);
    }
    if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveDone != 0)
    {
        return -1;
    }
    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
    {
        if (inner->flags & SNOWHORN1_FLAG_SEQ_TRIGGERED)
        {
            (*gObjectTriggerInterface)->runSequence(
                randomGetRange(0, 2) + 6, (void*)obj, -1);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(
                5, (void*)obj, -1);
        }
        buttonDisable(0, PAD_BUTTON_A);
    }
    return 0;
}

int DIMSnowHorn1_stateHandler01(int obj, int state, f32 fv)
{
    DIMSnowHorn1State* inner = ((GameObject*)obj)->extra;
    f32 k = lbl_803E8234;
    s16 v;

    ((DIMSnowHorn1State*)state)->baddie.animSpeedC = k;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedB = k;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedA = k;
    ((GameObject*)obj)->anim.velocityX = k;
    ((GameObject*)obj)->anim.velocityY = k;
    ((GameObject*)obj)->anim.velocityZ = k;
    *(u32*)((char*)state) |= 0x200000;

    if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveJustStartedA != 0)
    {
        ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803E827C;
        if (((GameObject*)obj)->anim.currentMove != lbl_803DC748)
        {
            ObjAnim_SetCurrentMove(obj, lbl_803DC748, k, 0);
        }
        inner->countdownTimer = randomGetRange(0x4b0, 0x960);
    }

    v = inner->countdownTimer - (int)fv;
    inner->countdownTimer = v;
    if (v <= 0)
    {
        return -3;
    }
    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
    {
        if (inner->flags & SNOWHORN1_FLAG_SEQ_TRIGGERED)
        {
            (*gObjectTriggerInterface)->runSequence(
                randomGetRange(0, 2) + 6, (void*)obj, -1);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(
                5, (void*)obj, -1);
        }
        buttonDisable(0, PAD_BUTTON_A);
    }
    return 0;
}

int DIMSnowHorn1_stateHandler0B(int obj, int state)
{
    int sub;
    DIMSnowHorn1State* inner;
    f32 k;

    inner = ((GameObject*)obj)->extra;
    sub = *(int*)&((GameObject*)obj)->anim.hitReactState;
    *(u32*)((char*)state) |= 0x200000;
    k = lbl_803E8234;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedC = k;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedB = k;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedA = k;
    ((GameObject*)obj)->anim.velocityX = k;
    ((GameObject*)obj)->anim.velocityY = k;
    ((GameObject*)obj)->anim.velocityZ = k;

    if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveJustStartedA != 0)
    {
        inner->flags &= ~SNOWHORN1_FLAG_HITVOL_PRIO;
        ((ObjHitsPriorityState*)sub)->flags |= 0x200;
        ObjAnim_SetCurrentMove(obj, 0x204, k, 0);
        ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803E8238;
        Sfx_PlayFromObject(obj, SFXTRIG_thorntail_chew2);
    }
    if ((((ObjHitsPriorityState*)sub)->flags & 0x200) && (((ObjHitsPriorityState*)sub)->contactFlags & OBJHITS_CONTACT_FLAG_KIND_NONZERO))
    {
        inner->flags |= SNOWHORN1_FLAG_HITVOL_PRIO;
    }
    if (inner->flags & SNOWHORN1_FLAG_HITVOL_PRIO)
    {
        *(u8*)&((ObjHitsPriorityState*)sub)->hitVolumePriority = 0;
        *(u8*)&((ObjHitsPriorityState*)sub)->hitVolumeId = 0;
        ((ObjHitsPriorityState*)sub)->flags &= ~0x200;
    }
    else
    {
        *(u8*)&((ObjHitsPriorityState*)sub)->hitVolumePriority = 0xb;
        *(u8*)&((ObjHitsPriorityState*)sub)->hitVolumeId = 1;
        ((ObjHitsPriorityState*)sub)->flags |= 0x200;
    }
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E823C)
    {
        return 8;
    }
    return 0;
}

int DIMSnowHorn1_stateHandler09(int obj, int state, f32 fv)
{
    int near;
    DIMSnowHorn1State* inner;
    f32 sp = lbl_803E8240;
    s16 d;

    near = ObjGroup_FindNearestObject(OBJGROUP_SNOWHORN_PUZZLE, obj, &sp);
    inner = ((GameObject*)obj)->extra;
    *(u32*)((char*)state) |= 0x200000;

    if (*(s16*)((char*)state + 0x334) < inner->advanceCountThreshold ||
        lbl_803E8234 == ((DIMSnowHorn1State*)state)->baddie.inputMagnitude)
    {
        return 8;
    }

    if (((DIMSnowHorn1State*)state)->baddie.turnRate < -0xaf)
    {
        ((DIMSnowHorn1State*)state)->baddie.turnRate = -((DIMSnowHorn1State*)state)->baddie.turnRate;
    }
    d = ((DIMSnowHorn1State*)state)->baddie.turnRate;
    if (d > 0 && ((GameObject*)obj)->anim.currentMove != 0x201)
    {
        ObjAnim_SetCurrentMove(obj, 0x201, lbl_803E8234, 0);
    }
    else if (d <= 0)
    {
        if (((GameObject*)obj)->anim.currentMove != 0x200)
        {
            ObjAnim_SetCurrentMove(obj, 0x200, lbl_803E8234, 0);
        }
    }
    ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803E8278;
    (*(void (*)(int, int, f32, int))(*(int*)(*gPlayerInterface + 0x20)))(obj, state, fv, 8);

    if (*(int*)&((DIMSnowHorn1State*)state)->baddie.unk31C & 0x100)
    {
        if ((GameObject*)near == NULL || (*(u8*)&((GameObject*)near)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) == 0)
        {
            return 0xc;
        }
    }
    return 0;
}

int DIMSnowHorn1_stateHandler08(int obj, int state)
{
    DIMSnowHorn1State* inner = ((GameObject*)obj)->extra;

    *(u32*)((char*)state) |= 0x200000;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;

    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x206:
        if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveDone != 0)
        {
            if (((DIMSnowHorn1State*)state)->baddie.moveSpeed > lbl_803E8234)
            {
                ObjAnim_SetCurrentMove(obj, 0x205, lbl_803E8234, 0);
                ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803E827C;
            }
            else
            {
                return 8;
            }
        }
        if (inner->airMeterValue != 0 &&
            ((DIMSnowHorn1State*)state)->baddie.moveSpeed > lbl_803E8234)
        {
            if (*(int*)&((DIMSnowHorn1State*)state)->baddie.unk31C != 0 ||
                lbl_803E8234 != ((DIMSnowHorn1State*)state)->baddie.moveInputX ||
                lbl_803E8234 != ((DIMSnowHorn1State*)state)->baddie.moveInputZ)
            {
                ((DIMSnowHorn1State*)state)->baddie.moveSpeed = -((DIMSnowHorn1State*)state)->baddie.moveSpeed;
            }
        }
        break;
    case 0x205:
        if (inner->airMeterValue != 0)
        {
            if (*(int*)&((DIMSnowHorn1State*)state)->baddie.unk31C != 0 ||
                lbl_803E8234 != ((DIMSnowHorn1State*)state)->baddie.moveInputX ||
                lbl_803E8234 != ((DIMSnowHorn1State*)state)->baddie.moveInputZ)
            {
                ObjAnim_SetCurrentMove(obj, 0x207, lbl_803E8234, 0);
                ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803E8280;
            }
        }
        break;
    case 0x207:
        if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveDone != 0)
        {
            return 8;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0x206, lbl_803E8234, 0);
        ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803E8280;
        break;
    }
    return 0;
}

int DIMSnowHorn1_stateHandler07(int obj, int state)
{
    void* near;
    DIMSnowHorn1State* inner;
    f32 sp = lbl_803E8240;
    f32 fz;

    near = (void*)ObjGroup_FindNearestObject(OBJGROUP_SNOWHORN_PUZZLE, obj, &sp);
    inner = ((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    fz = lbl_803E8234;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedC = fz;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedB = fz;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedA = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(u32*)((char*)state) |= 0x200000;
    if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveJustStartedA != 0)
    {
        *(s16*)((char*)state + 0x338) = 0;
        ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803E827C;
        ((DIMSnowHorn1State*)state)->baddie.velSmoothTime = lbl_803E8284;
        if (((GameObject*)obj)->anim.currentMove != lbl_803DC748)
        {
            ObjAnim_SetCurrentMove(obj, lbl_803DC748, fz, 0);
        }
    }
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x209:
    case 0x20a:
        if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, lbl_803DC748, lbl_803E8234, 0);
            ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803E827C;
        }
        break;
    }
    if (((DIMSnowHorn1State*)state)->baddie.inputMagnitude < lbl_803E824C)
    {
        *(s16*)((char*)state + 0x334) = 0;
        ((DIMSnowHorn1State*)state)->baddie.turnRate = 0;
        ((DIMSnowHorn1State*)state)->baddie.inputMagnitude = lbl_803E8234;
    }
    {
        f32 v = *(f32*)&((DIMSnowHorn1State*)state)->baddie.trackedObj;
        if (v > lbl_803E8234 && ((DIMSnowHorn1State*)state)->baddie.inputMagnitude > lbl_803E8234 &&
            *(s16*)((char*)state + 0x334) >= inner->advanceCountThreshold)
        {
            return 0xa;
        }
        if (v > lbl_803E8288 && ((DIMSnowHorn1State*)state)->baddie.inputMagnitude > lbl_803E8288 &&
            *(s16*)((char*)state + 0x334) < inner->advanceCountThreshold)
        {
            return 0xb;
        }
    }
    if (*(int*)&((DIMSnowHorn1State*)state)->baddie.unk31C & 0x100)
    {
        if (near == NULL || (*(u8*)&((GameObject*)near)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) == 0)
        {
            return 0xc;
        }
    }
    if (GameBit_Get(GAMEBIT_SNOWHORN_RIDING) != 0)
    {
        if (RandomTimer_UpdateRangeTrigger((char*)inner + 0xd04, lbl_803E8244, lbl_803E8248) != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_hightop_call1);
        }
    }
    return 0;
}

int DIMSnowHorn1_stateHandler06(int obj, int state)
{
    DIMSnowHorn1State* inner;
    f32 fz;

    fz = lbl_803E8234;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedC = fz;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedB = fz;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedA = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    *(u32*)((char*)state) |= 0x200000;
    inner = ((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    ((GameObject*)obj)->hitVolumeIndex = GameBit_Get(GAMEBIT_SNOWHORN_PUZZLE) != 0;
    if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveJustStartedA != 0)
    {
        ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803E827C;
        if (((GameObject*)obj)->anim.currentMove != 0x13)
        {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E8234, 0);
        }
    }
    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE)
    {
        if ((*gGameUIInterface)->isEventReady(GAMEBIT_SNOWHORN_PUZZLE) != 0)
        {
            u8 bit170 = GameBit_Get(GAMEBIT_SNOWHORN_PUZZLE);
            if (GameBit_Get(0x28) == 0)
            {
                switch (bit170)
                {
                case 1:
                    GameBit_Set(0x28, 1);
                    inner->triggerMode = 2;
                    break;
                case 2:
                    inner->triggerMode = 4;
                    GameBit_Set(0x16f, 1);
                    break;
                }
            }
            else
            {
                inner->triggerMode = 4;
                GameBit_Set(0x16f, 1);
            }
            (*gObjectTriggerInterface)->runSequence(
                inner->triggerMode, (void*)obj, -1);
            GameBit_Set(GAMEBIT_SNOWHORN_PUZZLE, GameBit_Get(GAMEBIT_SNOWHORN_PUZZLE) - bit170);
            buttonDisable(0, PAD_BUTTON_A);
        }
        else
        {
            if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
            {
                if (GameBit_Get(0x28) != 0)
                {
                    inner->triggerMode = 3;
                }
                else
                {
                    inner->triggerMode = 1;
                }
                (*gObjectTriggerInterface)->runSequence(
                    inner->triggerMode, (void*)obj, -1);
                buttonDisable(0, PAD_BUTTON_A);
            }
        }
    }
    return 0;
}

int DIMSnowHorn1_stateHandler05(int obj, int state)
{
    void* player;
    DIMSnowHorn1State* inner;
    int bit_a, bit_b;
    int id_a, id_b, id_c, id_d;
    int* o1;
    int* o2;
    int v;
    f32 f;

    f = lbl_803E8234;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedC = f;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedB = f;
    ((DIMSnowHorn1State*)state)->baddie.animSpeedA = f;
    ((GameObject*)obj)->anim.velocityX = f;
    ((GameObject*)obj)->anim.velocityY = f;
    ((GameObject*)obj)->anim.velocityZ = f;
    *(int*)state |= 0x200000;

    inner = ((GameObject*)obj)->extra;
    player = (void*)Obj_GetPlayerObject();
    switch (inner->mode)
    {
    case 1:
        id_a = 0x1602;
        id_b = 0x454bc;
        id_c = 0x454b8;
        id_d = 0x454b9;
        bit_a = 0x172;
        bit_b = 0x9ed;
        break;
    case 4:
        id_a = 0x4963b;
        id_b = 0x4963c;
        id_c = 0x4963d;
        id_d = 0x4963e;
        bit_a = 0x8f9;
        bit_b = 0x85d;
        break;
    }

    if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveJustStartedA != 0)
    {
        ((DIMSnowHorn1State*)state)->baddie.moveSpeed = lbl_803E827C;
        if (((GameObject*)obj)->anim.currentMove != 0x13)
        {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E8234, 0);
        }
    }

    if (GameBit_Get(bit_a) != 0 && GameBit_Get(bit_b) != 0 && player != NULL &&
        Vec_distance((char*)player + 0x18, (void*)&((GameObject*)obj)->anim.worldPosX) < lbl_803E828C)
    {
        switch (inner->mode)
        {
        case 1:
            inner->triggerMode = 0;
            GameBit_Set(0x245, 1);
            GameBit_Set(0x27, 1);
            break;
        case 4:
            inner->triggerMode = 9;
            GameBit_Set(0x1db, 1);
            break;
        }
        (*gObjectTriggerInterface)->runSequence(
            inner->triggerMode, (void*)obj, -1);
        buttonDisable(0, PAD_BUTTON_A);
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        v = inner->proximityPhase;
        switch (v)
        {
        case 1:
            if (Vec_distance((char*)player + 0x18, (void*)&((GameObject*)obj)->anim.worldPosX) < lbl_803E8290)
            {
                o1 = ObjList_FindObjectById(id_a);
                if (o1 != NULL) fn_8014C63C(o1);
                o1 = ObjList_FindObjectById(id_b);
                if (o1 != NULL) fn_8014C63C(o1);
                inner->proximityPhase = 2;
            }
            break;
        case 0:
        case 2:
            if ((u32)v == 0 ||
                Vec_distance((char*)player + 0x18, (void*)&((GameObject*)obj)->anim.worldPosX) > lbl_803E8240)
            {
                o1 = ObjList_FindObjectById(id_a);
                o2 = ObjList_FindObjectById(id_c);
                if (o1 != NULL && o2 != NULL) fn_8014C66C(o1, (int)o2);
                o1 = ObjList_FindObjectById(id_b);
                o2 = ObjList_FindObjectById(id_d);
                if (o1 != NULL && o2 != NULL) fn_8014C66C(o1, (int)o2);
                inner->proximityPhase = 1;
            }
            else
            {
                if (RandomTimer_UpdateRangeTrigger((char*)inner + 0xd08,
                                                   lbl_803E8294, lbl_803E8284) != 0)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_thorntail_chew1);
                }
            }
            break;
        }
    }
    return 0;
}

int DIMSnowHorn1_stateHandler0A(int obj, int state, f32 t)
{
    int near;
    DIMSnowHorn1State* inner;
    int phase;
    int p2;
    int changed;
    int useNormal;
    f32 v;
    f32 target;
    f32 f2;
    f32 blend;
    f32 nearDist;

    nearDist = lbl_803E8240;
    near = ObjGroup_FindNearestObject(OBJGROUP_SNOWHORN_PUZZLE, obj, &nearDist);
    inner = ((GameObject*)obj)->extra;
    if (GameBit_Get(GAMEBIT_SNOWHORN_RIDING) != 0)
    {
        if (RandomTimer_UpdateRangeTrigger((char*)inner + 0xd04, lbl_803E8244, lbl_803E8248) != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_hightop_call1);
        }
    }
    *(int*)((char*)state + 0) |= 0x200000;
    if (((DIMSnowHorn1State*)state)->baddie.inputMagnitude < lbl_803E824C)
    {
        *(s16*)((char*)state + 0x334) = 0;
        ((DIMSnowHorn1State*)state)->baddie.turnRate = 0;
        ((DIMSnowHorn1State*)state)->baddie.inputMagnitude = lbl_803E8234;
    }
    if (*(s16*)((char*)state + 0x334) < 0x5a)
    {
        ((GameObject*)obj)->anim.rotX =
            lbl_803E8250 * ((f32)(s16) * &((DIMSnowHorn1State*)state)->baddie.turnRate * t / lbl_803E8254) +
            (f32)(s16) * &((GameObject*)obj)->anim.rotX;
    }
    else
    {
        return 8;
    }

    v = ((DIMSnowHorn1State*)state)->baddie.inputMagnitude;
    if (v < *(f32*)&lbl_803E8234)
    {
        v = lbl_803E8234;
    }
    if (v > lbl_803E8258)
    {
        v = lbl_803E8258;
    }
    if (inner->airMeterValue == 0)
    {
        v = lbl_803E8234;
    }
    target = lbl_803E825C * v;
    if (target < lbl_803E8234)
    {
        target = lbl_803E8234;
    }
    ((DIMSnowHorn1State*)state)->baddie.animSpeedC =
        t * ((target - ((DIMSnowHorn1State*)state)->baddie.animSpeedC) / ((DIMSnowHorn1State*)state)->baddie.velSmoothTime) +
        ((DIMSnowHorn1State*)state)->baddie.animSpeedC;

    if (((GameObject*)obj)->anim.rotY > 0)
    {
        target = target -
            lbl_803E8260 * mathSinf(lbl_803E8264 * (f32)(s16) * &((GameObject*)obj)->anim.rotY /
                lbl_803E8268);
    }
    else
    {
        target = target -
            lbl_803E826C * mathSinf(lbl_803E8264 * (f32)(s16) * &((GameObject*)obj)->anim.rotY /
                lbl_803E8268);
    }
    if (target < lbl_80335128[2])
    {
        target = lbl_80335128[2];
    }
    ((DIMSnowHorn1State*)state)->baddie.animSpeedA =
        t * ((target - ((DIMSnowHorn1State*)state)->baddie.animSpeedA) / ((DIMSnowHorn1State*)state)->baddie.velSmoothTime) +
        ((DIMSnowHorn1State*)state)->baddie.animSpeedA;

    changed = 0;
    blend = ((GameObject*)obj)->anim.currentMoveProgress;
    phase = 0;
    while ((&lbl_803DC748)[phase] != ((GameObject*)obj)->anim.currentMove && phase < 2)
    {
        phase++;
    }
    if (phase >= 2)
    {
        phase = 0;
    }
    if (((GameObject*)obj)->anim.currentMove == 0x208)
    {
        phase = 1;
    }

    f2 = ((DIMSnowHorn1State*)state)->baddie.animSpeedC;
    p2 = phase * 2;
    if (f2 < lbl_80335128[p2])
    {
        if (phase == 1)
        {
            return 8;
        }
        phase--;
        changed = 1;
    }
    else if (f2 >= lbl_80335128[p2 + 1])
    {
        if (phase == 0)
        {
            blend = lbl_803E8234;
        }
        phase++;
        changed = 1;
    }

    useNormal = 1;
    if (*(s8*)&((DIMSnowHorn1State*)state)->baddie.moveDone != 0 && ((GameObject*)obj)->anim.currentMove == 0x208)
    {
        changed = 1;
        useNormal = 0;
    }
    if (changed != 0)
    {
        if (phase == 1 && useNormal != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x208, blend, 0);
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, (&lbl_803DC748)[phase], blend, 0);
        }
    }

    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(
        obj, ((DIMSnowHorn1State*)state)->baddie.animSpeedA,
        &((DIMSnowHorn1State*)state)->baddie.moveSpeed);
    if ((*(int*)&((DIMSnowHorn1State*)state)->baddie.unk31C & 0x100) != 0)
    {
        if ((void*)near == NULL || (*(u8*)&((GameObject*)near)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) == 0)
        {
            return 0xc;
        }
    }
    return 0;
}

void DIMSnowHorn1_func21(void)
{
}

int DIMSnowHorn1_func20(void) { return 0; }

f32 DIMSnowHorn1_func19(int obj, f32* out)
{
    DIMSnowHorn1State* state = ((GameObject*)obj)->extra;
    if (state->baddie.controlMode == 0xa)
    {
        *out = -state->baddie.moveSpeed;
    }
    else
    {
        *out = lbl_803E827C;
    }
    return lbl_803E8234;
}

void DIMSnowHorn1_func18(void* unused, f32* out_f, int* out_i)
{
    (void)unused;
    *out_f = lbl_803E8234;
    *out_i = 0;
}

void DIMSnowHorn1_func17(int obj, int value)
{
    u8 mode = (u8)value;
    ((DIMSnowHorn1State*)((GameObject*)obj)->extra)->mountMode = mode;
}

int DIMSnowHorn1_func16(void) { return 0; }

void DIMSnowHorn1_func15(s16* packed, u32 outX, u32 outY, u32 outZ)
{
    extern void setMatrixFromObjectPos(void* matrix, void* packedTransform);
    extern void Matrix_TransformPoint(void* matrix, double x, double y, double z, u32 outX, u32 outY,
                                      u32 outZ);
    struct
    {
        s16 rotX;
        s16 rotY;
        s16 rotZ;
        s16 pad;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } transform;
    f32 matrix[16];

    transform.x = *(f32*)(packed + 6);
    transform.y = *(f32*)(packed + 8);
    transform.z = *(f32*)(packed + 10);
    transform.rotX = packed[0];
    transform.rotY = packed[1];
    transform.rotZ = packed[2];
    transform.scale = lbl_803E8258;
    setMatrixFromObjectPos(matrix, &transform);
    Matrix_TransformPoint(matrix, lbl_803E8234, lbl_803E8298, lbl_803E829C, outX, outY, outZ);
}

int DIMSnowHorn1_func14(int obj)
{
    if (((DIMSnowHorn1State*)((GameObject*)obj)->extra)->queryFlagA8F != 0)
    {
        return 2;
    }
    return 1;
}

int DIMSnowHorn1_render2(int obj)
{
    DIMSnowHorn1State* state = ((GameObject*)obj)->extra;
    if ((state->flags & SNOWHORN1_FLAG_RIDING) != 0)
    {
        GameBit_Set(GAMEBIT_SNOWHORN_RIDING, 0);
        state->flags = (u8)(state->flags & ~SNOWHORN1_FLAG_RIDING);
        return 1;
    }
    return 0;
}

void DIMSnowHorn1_modelMtxFn(int obj, f32* out_x, f32* out_y, f32* out_z)
{
    DIMSnowHorn1State* state = ((GameObject*)obj)->extra;
    *out_x = state->pathPosX;
    *out_y = state->pathPosY;
    *out_z = state->pathPosZ;
}

int DIMSnowHorn1_func11(int obj)
{
    if (((DIMSnowHorn1State*)((GameObject*)obj)->extra)->queryFlagA90 != 0)
    {
        return 1;
    }
    return 2;
}

int DIMSnowHorn1_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    DIMSnowHorn1State* state;
    int animState;
    int i;
    f32 fz;

    (void)unused;
    state = ((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;

    switch (state->mode)
    {
    case 0:
        animUpdate->sequenceEventActive = 0;
        if (((GameObject*)obj)->seqIndex == -1)
        {
            for (i = 0; i < (int)(u32)animUpdate->eventCount; i++)
            {
                GameBit_Set(0x17b, 1);
                state->flags |= SNOWHORN1_FLAG_SEQ_TRIGGERED;
            }
        }
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, (int)state, 1);
        break;
    case 5:
        animUpdate->sequenceEventActive = 0;
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, (int)state, 2);
        break;
    case 4:
        animUpdate->sequenceEventActive = 0;
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, (int)state, 7);
        break;
    case 1:
        animUpdate->sequenceEventActive = 0;
        if (((GameObject*)obj)->seqIndex != -1)
        {
            switch (state->triggerMode)
            {
            case 0:
            case 1:
            case 2:
            case 3:
                animState = 6;
                break;
            case 4:
            default:
                animState = 7;
                break;
            }
        }
        else
        {
            animState = 7;
        }
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, (int)state, animState);
        break;
    case 3:
        animUpdate->sequenceEventActive = 0;
        state->baddie.moveJustStartedA = 1;
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, (int)state, 7);
        break;
    default:
        break;
    }

    (*gPathControlInterface)->attachObject((void*)obj, (u8*)&state->baddie + 4);
    fz = lbl_803E8234;
    state->baddie.animSpeedC = fz;
    state->baddie.animSpeedB = fz;
    state->baddie.animSpeedA = fz;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = fz;
    ((GameObject*)obj)->anim.velocityZ = fz;
    return (u32)(-(s8)animUpdate->sequenceEventActive | (s8)animUpdate->sequenceEventActive) >> 0x1f;
}

void DIMSnowHorn1_func22(int obj, f32 scale)
{
    void* pathMtx;
    struct
    {
        s16 rotX;
        s16 rotY;
        s16 rotZ;
        s16 pad;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } transform;
    f32 x;
    f32 y;
    f32 z;

    pathMtx = (void*)ObjPath_GetPointModelMtx(obj, 1);
    ObjPath_GetPointLocalPosition(obj, 1, &x, &y, &z);
    transform.x = x;
    transform.y = y;
    transform.z = z;
    transform.rotX = 0;
    transform.rotY = 0;
    transform.rotZ = 0;
    transform.scale = scale / ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    setMatrixFromObjectPos((f32*)gDIMSnowHorn1ModelMtx, (s16*)&transform);
    mtx44_mult(gDIMSnowHorn1ModelMtx, pathMtx, gDIMSnowHorn1ModelMtx);
    fn_8003B950(gDIMSnowHorn1ModelMtx);
}

int DIMSnowHorn1_setScale(int obj)
{
    DIMSnowHorn1State* state;
    f32 range;
    void* nearest;

    state = ((GameObject*)obj)->extra;
    range = lbl_803E8240;

    switch (state->mode)
    {
    case 0:
    case 5:
        return 0;
    }
    if (state->baddie.controlMode != 7)
    {
        return 0;
    }
    if (((GameObject*)obj)->pendingParentObj != NULL)
    {
        return 0;
    }

    nearest = (void*)ObjGroup_FindNearestObject(OBJGROUP_SNOWHORN_PUZZLE, obj, &range);
    if ((nearest != NULL) && ((*(u8*)&((GameObject*)nearest)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0))
    {
        buttonDisable(0, PAD_BUTTON_A);
        return 1;
    }
    return 0;
}

#pragma dont_inline on
void fn_802BB998(int obj, int pointState, int inputState)
{
    extern u16 audioPickSoundEffect_8006ed24(u8 id, int bank);
    extern void Sfx_PlayFromObject(int obj, u16 sfxId);
    u8 flags;
    u8 pointIndex;
    u8 count;
    s32 inputFlags;
    u16 sfxId;
    struct
    {
        u32 unk0;
        u32 unk4;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } args;

    flags = 0;
    inputFlags = *(s32*)&((BaddieState*)inputState)->eventFlags;
    if ((inputFlags & 2) != 0)
    {
        flags |= 1;
    }
    if ((inputFlags & 4) != 0)
    {
        flags |= 2;
    }

    pointIndex = 0;
    while (flags != 0)
    {
        if ((flags & 1) != 0)
        {
            args.x = *(f32*)(pointState + 0x9b0 + pointIndex * 0xc);
            args.y = *(f32*)(pointState + 0x9b4 + pointIndex * 0xc);
            args.z = *(f32*)(pointState + 0x9b8 + pointIndex * 0xc);
            args.scale = lbl_803E82A0;

            count = (u8)randomGetRange(2, 6);
            while (count != 0)
            {
                ((EffectInterface*)*gPartfxInterface)
                    ->spawnObject((void*)obj, randomGetRange(0, 1) + 0x1f9, &args,
                                  0x10001, -1, NULL);
                count--;
            }

            sfxId = audioPickSoundEffect_8006ed24((u8)(s8)*(s8*)&((BaddieState*)inputState)->paletteSlot, 9);
            Sfx_PlayFromObject(obj, sfxId);
            doRumble(lbl_803E8244);
        }
        flags >>= 1;
        pointIndex++;
    }
}
#pragma dont_inline reset

int DIMSnowHorn1_getExtraSize(void) { return 0xd0c; }

int DIMSnowHorn1_getObjectTypeId(void) { return 0x43; }

void DIMSnowHorn1_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0xa);
}

void DIMSnowHorn1_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DIMSnowHorn1State* state = ((GameObject*)obj)->extra;

    if (visible == -1)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E8258);
        ObjPath_GetPointWorldPosition(obj, 1, &state->pathPosX, &state->pathPosY,
                                      &state->pathPosZ, 0);
        ObjPath_GetPointWorldPositionArray(obj, 2, 4, (f32*)((char*)state + 0x9b0));
    }

    if ((state->mountMode != 2) && (visible != 0))
    {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E8258);
        ObjPath_GetPointWorldPosition(obj, 1, &state->pathPosX, &state->pathPosY,
                                      &state->pathPosZ, 0);
        ObjPath_GetPointWorldPositionArray(obj, 2, 4, (f32*)((char*)state + 0x9b0));
    }
}

void DIMSnowHorn1_hitDetect(void)
{
}

void fn_802BB4B4(int obj, int a, int slot)
{
    extern u32 getButtonsJustPressed(int port);
    extern u32 getButtonsHeld(int port);
    int matchFrame = (slot != -1) ? ((framesThisStep - 1 - slot) == 0) : 1;
    int* viewSlot = (int*)Camera_GetCurrentViewSlot();
    DIMSnowHorn1State* state = ((GameObject*)obj)->extra;

    state->baddie.hitPoints = 0;
    *(u32*)state &= ~0x8000;

    if (state->mountMode == 2)
    {
        if (GameBit_Get(GAMEBIT_SNOWHORN_AIR_DRAIN) != 0)
        {
            state->airMeterValue -= 1;
        }
        else
        {
            state->airMeterValue = 0x3e8;
        }
        (*gGameUIInterface)->runAirMeter(state->airMeterValue);
        if (GameBit_Get(GAMEBIT_SNOWHORN_AIR_RESET) != 0)
        {
            GameBit_Set(GAMEBIT_SNOWHORN_AIR_RESET, 0);
            state->airMeterValue = 0x3e8;
        }
        if (state->airMeterValue < 0)
        {
            state->airMeterValue = 0;
            (*gMapEventInterface)->gotoRestartPoint();
        }
        state->baddie.moveInputX = (f32)(s8)
        padGetStickX(0);
        state->baddie.moveInputZ = (f32)(s8)
        padGetStickY(0);
        *(u32*)&state->baddie.unk31C = getButtonsJustPressed(0);
        *(u32*)&state->baddie.unk318 = getButtonsHeld(0);
        state->baddie.cameraYaw = *(s16*)viewSlot;
    }
    else
    {
        f32 zero = lbl_803E8234;
        state->baddie.moveInputX = zero;
        state->baddie.moveInputZ = zero;
        *(u32*)&state->baddie.unk31C = 0;
        *(u32*)&state->baddie.unk318 = 0;
        *(u16*)&state->baddie.cameraYaw = 0;
    }

    *(u32*)state |= 0x00400000;
    if (matchFrame != 0)
    {
        *(u32*)state &= ~0x00400000;
    }

    if (*(s8*)&state->baddie.physicsActive != 0)
    {
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - lbl_803E82A4 * (f32)a;
    }

    {
        f32 cur = ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityY =
            (cur < lbl_803E82A8) ? lbl_803E82A8 : ((cur > lbl_803E8234) ? lbl_803E8234 : cur);
    }

    (*(void (**)(int, int, f32, f32, int*, f32*))(*(int*)gPlayerInterface + 0x8))
        (obj, (int)state, timeDelta, timeDelta, gDIMSnowHorn1StateHandlers, &gDIMSnowHorn1DefaultStateHandler);
    fn_802BB998(obj, (int)state, (int)state);
}

#pragma opt_lifetimes off
void DIMSnowHorn1_update(int obj)
{
    f32 nearDist;
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 matrix[16];
    u8* base = (u8*)(int)gDIMSnowHorn1ConfigTable;
    int player = (int)Obj_GetPlayerObject();
    int data;
    s8 c = -1;
    s16 d;
    char* found;
    int statePtr;
    char* playerObj;
    u32 flip;
    int flags;

    data = *(int*)&((GameObject*)obj)->extra;
    ((DIMSnowHorn1State*)data)->advanceCountThreshold = 5;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->trackContactMask = 9;
    {
        u8* fp = base + 0x94;
        flags = fp[((DIMSnowHorn1State*)data)->baddie.controlMode];
    }
    if (!(flags & 8))
    {
        ObjHitReactEntry* arm;
        if (flags & 2)
        {
            arm = (ObjHitReactEntry*)(base + 0x80);
        }
        else
        {
            arm = (ObjHitReactEntry*)(base + 0x6c);
        }
        ((DIMSnowHorn1State*)data)->hitReactState = ((u8 (*)(int, ObjHitReactEntry*, u32, u32, f32*))ObjHitReact_Update)(
            obj, arm, 1, ((DIMSnowHorn1State*)data)->hitReactState, (f32*)((char*)data + 0xa94));
        if (((DIMSnowHorn1State*)data)->hitReactState != 0)
        {
            fn_8003A168(obj, data + 0x980);
            characterDoEyeAnims(obj, data + 0x980);
            return;
        }
    }
    if (((DIMSnowHorn1State*)data)->mountMode == 2)
    {
        ((DIMSnowHorn1State*)data)->baddie.physicsActive = 1;
        fn_802BB4B4(obj, framesThisStep, -1);
    }
    else
    {
        f32 fz;
        ((DIMSnowHorn1State*)data)->baddie.physicsActive = 0;
        fz = lbl_803E8234;
        ((DIMSnowHorn1State*)data)->baddie.animSpeedC = fz;
        ((DIMSnowHorn1State*)data)->baddie.animSpeedB = fz;
        ((DIMSnowHorn1State*)data)->baddie.animSpeedA = fz;
        ((GameObject*)obj)->anim.velocityX = fz;
        ((GameObject*)obj)->anim.velocityY = fz;
        ((GameObject*)obj)->anim.velocityZ = fz;
        (*gPathControlInterface)->attachObject((void*)obj,
                                               (u8*)&((DIMSnowHorn1State*)data)->baddie + 4);
        fn_802BB4B4(obj, framesThisStep, -1);
    }
    if (((DIMSnowHorn1State*)data)->mountMode == 0)
    {
        (*gNewCloudsInterface)->func0ANop(0);
    }
    else
    {
        (*gNewCloudsInterface)->func0ANop(1);
    }
    switch (((DIMSnowHorn1State*)data)->mode)
    {
    case 0:
    case 5:
        statePtr = *(int*)&((GameObject*)obj)->extra;
        playerObj = (char*)Obj_GetPlayerObject();
        if (playerObj != NULL
            && Vec_distance((void*)((int)playerObj + 0x18), (void*)&((GameObject*)obj)->anim.worldPosX) < lbl_803E8240
            && ((DIMSnowHorn1State*)statePtr)->mountMode == 0)
        {
            ((DIMSnowHorn1State*)statePtr)->playerNearby = 1;
            ((DIMSnowHorn1State*)statePtr)->spawnPosX = ((GameObject*)playerObj)->anim.localPosX;
            ((DIMSnowHorn1State*)statePtr)->spawnPosY = ((GameObject*)playerObj)->anim.localPosY;
            ((DIMSnowHorn1State*)statePtr)->spawnPosZ = ((GameObject*)playerObj)->anim.localPosZ;
        }
        else
        {
            ((DIMSnowHorn1State*)statePtr)->playerNearby = 0;
        }
        fn_8003B500(obj, data + 0x980, lbl_803E8234);
        break;
    }
    switch (((DIMSnowHorn1State*)data)->mode)
    {
    case 1:
    case 3:
    case 4:
        nearDist = lbl_803E8240;
        found = (char*)ObjGroup_FindNearestObject(OBJGROUP_SNOWHORN_PUZZLE, obj, &nearDist);
        if (((DIMSnowHorn1State*)data)->mountMode == 0 && ((DIMSnowHorn1State*)data)->baddie.controlMode == 7
            && getXZDistance(player + 0x18, (int)&((GameObject*)obj)->anim.worldPosX) < lbl_803E82B4)
        {
            if (found != NULL && (*(u8*)&((GameObject*)found)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE))
            {
                setAButtonIcon(0x14);
                if (*(u8*)&((GameObject*)found)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
                {
                    int layer = getCurMapLayer();
                    (*gMapEventInterface)->restartPoint((void*)(player + 0xc), 0x584, layer, 0);
                    buttonDisable(0, PAD_BUTTON_A);
                    GameBit_Set(GAMEBIT_SNOWHORN_RIDING, 1);
                    d = ((GameObject*)obj)->anim.rotX - (u16)((GameObject*)found)->anim.rotX;
                    if (d > 0x8000)
                    {
                        d = d - 0xffff;
                    }
                    if (d < -0x8000)
                    {
                        d = d + 0xffff;
                    }
                    if (d > 0x4000 || d < -0x4000)
                    {
                        GameBit_Set(0x18, 1);
                    }
                    else
                    {
                        GameBit_Set(0x5ba, 1);
                    }
                    if (((DIMSnowHorn1State*)data)->mode == 3)
                    {
                        ((DIMSnowHorn1State*)data)->airMeterValue = 1000;
                        (*gGameUIInterface)->initAirMeter(1000, 0x5d0);
                    }
                }
            }
        }
        else if (((DIMSnowHorn1State*)data)->mountMode == 2)
        {
            if (found != NULL && (*(u8*)&((GameObject*)found)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE))
            {
                setAButtonIcon(0x15);
                if (*(u8*)&((GameObject*)found)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
                {
                    buttonDisable(0, PAD_BUTTON_A);
                    GameBit_Set(GAMEBIT_SNOWHORN_RIDING, 0);
                    switch (((DIMSnowHorn1State*)data)->mode)
                    {
                    case 1:
                        c = 0;
                        break;
                    case 3:
                        c = 1;
                        break;
                    case 4:
                        c = 2;
                        break;
                    }
                    d = ((GameObject*)obj)->anim.rotX - (u16)((GameObject*)found)->anim.rotX;
                    if (d > 0x8000)
                    {
                        d = d - 0xffff;
                    }
                    if (d < -0x8000)
                    {
                        d = d + 0xffff;
                    }
                    if (c >= 0)
                    {
                        SnowHornEntry* tbl = (SnowHornEntry*)base;
                        int bit2;
                        int cc;
                        GameBit_Set(tbl[c].h1e, *(s16*)(*(int*)&((GameObject*)found)->anim.placementData + 0x1a));
                        bit2 = tbl[c].h20;
                        cc = c;
                        flip = 0;
                        if (d > 0x4000 || d < -0x4000)
                        {
                            flip = 1;
                        }
                        GameBit_Set(bit2, cc ^ flip);
                    }
                    if (d > 0x4000 || d < -0x4000)
                    {
                        GameBit_Set(0x19, 1);
                    }
                    else
                    {
                        GameBit_Set(0x5bb, 1);
                    }
                    *(int*)&((DIMSnowHorn1State*)data)->baddie.unk31C = 0;
                    (*gGameUIInterface)->airMeterSetShutdown();
                    (*gMapEventInterface)->clearRestartPoint();
                }
            }
            else
            {
                setAButtonIcon(0x13);
            }
        }
        break;
    }
    characterDoEyeAnims(obj, data + 0x980);
    v.mat[1] = ((GameObject*)obj)->anim.localPosX;
    v.mat[2] = ((GameObject*)obj)->anim.localPosY;
    v.mat[3] = ((GameObject*)obj)->anim.localPosZ;
    v.angles[0] = ((GameObject*)obj)->anim.rotX;
    v.angles[1] = ((GameObject*)obj)->anim.rotY;
    v.angles[2] = ((GameObject*)obj)->anim.rotZ;
    v.mat[0] = lbl_803E8258;
    setMatrixFromObjectPos(matrix, v.angles);
    Matrix_TransformPoint(matrix, lbl_803E8234, lbl_803E82AC, lbl_803E82B0,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosX,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosY,
                          &((GameObject*)obj)->anim.modelState->overrideWorldPosZ);
}
#pragma opt_lifetimes reset

#pragma opt_propagation off
void DIMSnowHorn1_release(void)
{
    void* zero;
    void** p;
    void* v;
    p = (void**)(int)&gDIMSnowHorn1Texture;
    zero = NULL;
    v = *p;
    if (v != NULL)
    {
        textureFree((int)v);
    }
    *p = zero;
}
#pragma opt_propagation reset

#pragma opt_propagation off
void DIMSnowHorn1_initialise(void)
{
    s16* src;
    void** dst;
    ((void**)gDIMSnowHorn1StateHandlers)[0] = (void*)DIMSnowHorn1_stateHandler00;
    ((void**)gDIMSnowHorn1StateHandlers)[1] = (void*)DIMSnowHorn1_stateHandler01;
    ((void**)gDIMSnowHorn1StateHandlers)[2] = (void*)DIMSnowHorn1_stateHandler02;
    ((void**)gDIMSnowHorn1StateHandlers)[3] = (void*)DIMSnowHorn1_stateHandler03;
    ((void**)gDIMSnowHorn1StateHandlers)[4] = (void*)DIMSnowHorn1_stateHandler04;
    ((void**)gDIMSnowHorn1StateHandlers)[5] = (void*)DIMSnowHorn1_stateHandler05;
    ((void**)gDIMSnowHorn1StateHandlers)[6] = (void*)DIMSnowHorn1_stateHandler06;
    ((void**)gDIMSnowHorn1StateHandlers)[7] = (void*)DIMSnowHorn1_stateHandler07;
    ((void**)gDIMSnowHorn1StateHandlers)[8] = (void*)DIMSnowHorn1_stateHandler08;
    ((void**)gDIMSnowHorn1StateHandlers)[9] = (void*)DIMSnowHorn1_stateHandler09;
    ((void**)gDIMSnowHorn1StateHandlers)[10] = (void*)DIMSnowHorn1_stateHandler0A;
    ((void**)gDIMSnowHorn1StateHandlers)[11] = (void*)DIMSnowHorn1_stateHandler0B;
    *(void* *)&gDIMSnowHorn1DefaultStateHandler = (void*)DIMSnowHorn1_defaultStateHandler;
    src = &gDIMSnowHorn1TextureId;
    dst = &gDIMSnowHorn1Texture;
    *dst = (void*)textureLoad(*src, 0);
}
#pragma opt_propagation reset

void DIMSnowHorn1_init(int obj, int p2, int p3)
{
    u8* base = gDIMSnowHorn1ConfigTable;
    int stk = lbl_803E8230;
    DIMSnowHorn1State* inner;
    u8* pathState;
    s8 idx;
    ((GameObject*)obj)->anim.rotX = (s16)((s8) * (s8*)((char*)p2 + 0x18) << 8);
    ((GameObject*)obj)->animEventCallback = (void*)DIMSnowHorn1_animEventCallback;
    ObjGroup_AddObject(obj, 0xa);
    inner = ((GameObject*)obj)->extra;
    inner->mode = *(u8*)((char*)p2 + 0x19);
    inner->advanceCountThreshold = 5;
    inner->airMeterValue = 0x3e8;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0xa10;
    }
    if (((GameObject*)obj)->anim.hitReactState != NULL)
    {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->trackContactMask = 9;
    }
    (*(void (*)(int, int, int, int))(*(int*)(*gPlayerInterface + 0x4)))(obj, (int)inner, 0xc, 1);
    inner->baddie.gravity = gDIMSnowHorn1Gravity;
    pathState = (u8*)&inner->baddie + 4;
    pathState[0x25b] = 0;
    switch (inner->mode)
    {
    case 1:
    case 3:
    case 4:
        (*gPathControlInterface)->init(pathState, 3, 0x200020, 1);
        (*gPathControlInterface)->setLocalPointCollision(pathState, 2, base + 0xe0,
                                                         &gDIMSnowHorn1PathCollisionData, 8);
        (*gPathControlInterface)->setup(pathState, 4, base + 0xa0, base + 0xd0, &stk);
        (*gPathControlInterface)->attachObject((void*)obj, pathState);
        break;
    case 2:
        break;
    }
    dll_2E_func05(obj, (int)inner->lookController, -0x2000, 0x2aaa, 3);
    inner->unk96D |= 8;
    if (p3 == 0)
    {
        idx = -1;
        switch (inner->mode)
        {
        case 1:
            if (GameBit_Get(0x16f))
            {
                idx = 0;
            }
            break;
        case 3:
            idx = 1;
            break;
        case 4:
            if (GameBit_Get(0x1db))
            {
                idx = 2;
            }
            break;
        }
        if (idx >= 0)
        {
            SnowHornEntry* tbl = (SnowHornEntry*)base;
            if (GameBit_Get(tbl[idx].h1e))
            {
                ((GameObject*)obj)->anim.localPosX = tbl[idx].f10;
                ((GameObject*)obj)->anim.localPosY = tbl[idx].f14;
                ((GameObject*)obj)->anim.localPosZ = tbl[idx].f18;
                ((GameObject*)obj)->anim.rotX = tbl[idx].h1c;
            }
            else
            {
                SnowHornEntry* e = &tbl[idx];
                ((GameObject*)obj)->anim.localPosX = e->f0;
                ((GameObject*)obj)->anim.localPosY = e->f4;
                ((GameObject*)obj)->anim.localPosZ = e->f8;
                ((GameObject*)obj)->anim.rotX = e->hc;
            }
            if (GameBit_Get(tbl[idx].h20))
            {
                ((GameObject*)obj)->anim.rotX += 0x8000;
            }
        }
    }
}

u8 gDIMSnowHorn1ConfigTable[] = {
    0xC5, 0xE0, 0xD0, 0x00, 0xC4, 0x9E, 0xA0, 0x00, 0x46, 0x49, 0xC4, 0x00,
    0x81, 0x10, 0x00, 0x00, 0xC5, 0xFD, 0xB8, 0x00, 0xC4, 0x97, 0x00, 0x00,
    0x46, 0x54, 0x7C, 0x00, 0xBD, 0x00, 0x01, 0x00, 0x01, 0x05, 0x00, 0x00,
    0xC5, 0xFA, 0x50, 0x00, 0xC4, 0x8F, 0xE0, 0x00, 0x46, 0x68, 0x88, 0x00,
    0x85, 0xAC, 0x00, 0x00, 0xC6, 0x1E, 0x14, 0x00, 0xC4, 0x40, 0xC0, 0x00,
    0x46, 0x6A, 0xBC, 0x00, 0x80, 0x9D, 0x01, 0x01, 0x01, 0x06, 0x00, 0x00,
    0xC6, 0x13, 0xB0, 0x00, 0xC5, 0x24, 0x30, 0x00, 0x46, 0x7E, 0x50, 0x00,
    0xBD, 0x36, 0x00, 0x00, 0xC6, 0x13, 0xB0, 0x00, 0xC5, 0x24, 0x30, 0x00,
    0x46, 0x7E, 0x50, 0x00, 0xBD, 0x36, 0x01, 0x01, 0x06, 0x43, 0x00, 0x00,
    0x02, 0xDA, 0x03, 0x75, 0x00, 0x30, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x3C, 0x44, 0x9B, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x02, 0xDA, 0x03, 0x75,
    0x00, 0x2F, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x44, 0x9B, 0xA6,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00,
    0x08, 0x08, 0x08, 0x08, 0xC1, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC1, 0xA0, 0x00, 0x00, 0x41, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC1, 0xA0, 0x00, 0x00, 0x41, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0xA0, 0x00, 0x00, 0xC1, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x42, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00, 0x00,
};
