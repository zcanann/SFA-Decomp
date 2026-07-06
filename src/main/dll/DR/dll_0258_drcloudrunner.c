/*
 * drcloudrunner (DLL 0x258) - the rideable CloudRunner creature on
 * Dinosaur Planet. A large baddie-derived state machine that the player
 * mounts and flies. flightState selects the high-level mode (0 = grounded
 * / scripted, 1 = transition, 2 = mounted free-flight); the eight state
 * handlers (gDRCloudRunnerStateHandlers[0..7]) drive idle, scripted-move,
 * flight, restart and hit responses, dispatched through the shared
 * baddie/player interface in fn_802C11BC.
 *
 * Free-flight (stateHandler05) integrates velocity from stick input,
 * gravity and a banking model, clamps speed/pitch/roll against the
 * per-move parameter table at gDRCloudRunnerMoveParamTable, and follows the wind-curve
 * collision path set up in fn_802BF0C8. The air meter and several map
 * game bits are managed across init/free/hitDetect.
 *
 * CloudRunnerState (its 'extra' block, 0xbc8 bytes) lives in
 * cloudrunner_state.h; the two structs below are this DLL's private
 * overlays for the placement record and for the few extra fields the
 * shared struct does not yet name.
 */
#include "main/dll/DR/cloudrunner_state.h"
#include "main/dll/DR/dr_802bbc10_shared.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#define DRCLOUDRUNNER_OBJGROUP 0xa
#define ARWARWING_OBJGROUP 0x26

#define DRCLOUDRUNNER_OBJFLAG_PARENT_SLACK 0x1000

STATIC_ASSERT(sizeof(CloudRunnerState) == 0xbc8);

/* CloudRunnerState::flightState high-level modes */
#define CLOUDRUNNER_FLIGHT_GROUNDED 0   /* grounded / scripted */
#define CLOUDRUNNER_FLIGHT_TRANSITION 1 /* mounting / dismounting */
#define CLOUDRUNNER_FLIGHT_MOUNTED 2    /* mounted free-flight */

/* placement record passed to init / read by the state handlers */
typedef struct DRCloudRunnerPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 airMeterCapacity; /* 0x1A: initial air meter capacity */
    u8 pad1C[0x1E - 0x1C];
    s16 enableGameBit;    /* 0x1E: game bit that enables the mount */
} DRCloudRunnerPlacement;

/* overlay onto CloudRunnerState for the fields it does not yet name */
typedef struct DRCloudRunnerState
{
    u8 pad0[0xAD5 - 0x0];
    u8 flagsAD5;
    u8 padAD6[0xB50 - 0xAD6];
    f32 unkB50;
    u8 padB54[0xBAE - 0xB54];
    s16 unkBAE;
    s16 altMoveEnabled; /* 0xBB0: from placement+0x1a; when set, move 0x203 switches to alternate move 0x20c */
    u8 padBB2[0xBB4 - 0xBB2];
    u8 spawnVariant;
    u8 padBB5[0xBC4 - 0xBB5];
    s8 unkBC4;
    u8 padBC5[0xBC8 - 0xBC5];
} DRCloudRunnerState;

STATIC_ASSERT(offsetof(DRCloudRunnerPlacement, airMeterCapacity) == 0x1A);
STATIC_ASSERT(offsetof(DRCloudRunnerPlacement, enableGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DRCloudRunnerState, flagsAD5) == 0xAD5);
STATIC_ASSERT(offsetof(DRCloudRunnerState, unkB50) == 0xB50);
STATIC_ASSERT(offsetof(DRCloudRunnerState, unkBAE) == 0xBAE);
STATIC_ASSERT(offsetof(DRCloudRunnerState, altMoveEnabled) == 0xBB0);
STATIC_ASSERT(offsetof(DRCloudRunnerState, spawnVariant) == 0xBB4);
STATIC_ASSERT(offsetof(DRCloudRunnerState, unkBC4) == 0xBC4);
STATIC_ASSERT(sizeof(DRCloudRunnerState) == 0xBC8);

typedef struct
{
    f32 x;
    f32 y;
    f32 z;
} Vec3x;

#define CLOUDRUNNER_ONCLOUD_GAMEBIT 0xed7 /* set while mounted/on cloudrunner */

int DR_CloudRunner_defaultStateHandler(void) { return 0x0; }

void DR_CloudRunner_func21(void)
{
}

int DR_CloudRunner_func20(void) { return 0x0; }

int DR_CloudRunner_func16(void) { return 0x0; }

int DR_CloudRunner_render2(void) { return 0x0; }

int DR_CloudRunner_setScale(void) { return 0x0; }

int DR_CloudRunner_getExtraSize(void) { return 0xbc8; }

int DR_CloudRunner_getObjectTypeId(void) { return 0x43; }

void DR_CloudRunner_release(void)
{
}

f32 DR_CloudRunner_func19(int obj, f32* out)
{
    *out = lbl_803E83E8;
    return lbl_803E83A4;
}

void DR_CloudRunner_func18(int obj, f32* a, int* b)
{
    *a = lbl_803E83A4;
    *b = 0;
}

int DR_CloudRunner_func11(int obj)
{
    CloudRunnerState * inner = ((GameObject*)obj)->extra;
    if (inner->unkBB8 != 0)
    {
        return 1;
    }
    return 2;
}

void DR_CloudRunner_func22(int obj)
{
    fn_8003B950(ObjPath_GetPointModelMtx(obj, 2));
}

int DR_CloudRunner_func14(int obj)
{
    CloudRunnerState * inner = ((GameObject*)obj)->extra;
    if (inner->unkBB7 != 0)
    {
        return 2;
    }
    return 1;
}

void DR_CloudRunner_modelMtxFn(int obj, int a, int b, int c)
{
    ObjPath_GetPointWorldPosition(obj, 2, a, b, c, 0);
}

int DR_CloudRunner_stateHandler07(int obj)
{
    CloudRunnerState * inner = ((GameObject*)obj)->extra;
    if (inner->airTimeRemaining == 0)
    {
        s32 a = ((GameObject*)obj)->anim.alpha;
        a -= framesThisStep;
        ((GameObject*)obj)->anim.alpha = a;
    }
    return 0;
}

void DR_CloudRunner_free(int obj)
{
    DRCloudRunnerState* inner = (DRCloudRunnerState*)((GameObject*)obj)->extra;
    GameBit_Set(0x7aa, inner->altMoveEnabled);
    ObjGroup_RemoveObject(obj, DRCLOUDRUNNER_OBJGROUP);
    ObjGroup_RemoveObject(obj, ARWARWING_OBJGROUP);
    (*gGameUIInterface)->airMeterSetShutdown();
}

void DR_CloudRunner_initialise(void)
{
    ((void**)gDRCloudRunnerStateHandlers)[0] = DR_CloudRunner_stateHandler00;
    ((void**)gDRCloudRunnerStateHandlers)[1] = DR_CloudRunner_stateHandler01;
    ((void**)gDRCloudRunnerStateHandlers)[2] = DR_CloudRunner_stateHandler02;
    ((void**)gDRCloudRunnerStateHandlers)[3] = DR_CloudRunner_stateHandler03;
    ((void**)gDRCloudRunnerStateHandlers)[4] = DR_CloudRunner_stateHandler04;
    ((void**)gDRCloudRunnerStateHandlers)[5] = DR_CloudRunner_stateHandler05;
    ((void**)gDRCloudRunnerStateHandlers)[6] = DR_CloudRunner_stateHandler06;
    ((void**)gDRCloudRunnerStateHandlers)[7] = DR_CloudRunner_stateHandler07;
    gDRCloudRunnerDefaultStateHandler = DR_CloudRunner_defaultStateHandler;
}

int DR_CloudRunner_stateHandler02(int obj, int p2)
{
    CloudRunnerState * inner = ((GameObject*)obj)->extra;
    *(int*)((char*)p2 + 0) |= 0x200000;
    if (*(s8*)&((CloudRunnerState*)p2)->baddie.moveJustStartedA != 0)
    {
        f32 fz = lbl_803E83A4;
        ((CloudRunnerState*)p2)->baddie.animSpeedC = fz;
        ((CloudRunnerState*)p2)->baddie.animSpeedB = fz;
        ((CloudRunnerState*)p2)->baddie.animSpeedA = fz;
        ((GameObject*)obj)->anim.velocityX = fz;
        ((GameObject*)obj)->anim.velocityY = fz;
        ((GameObject*)obj)->anim.velocityZ = fz;
        *(s16*)((char*)p2 + 0x338) = 0;
        ((CloudRunnerState*)p2)->baddie.moveSpeed = lbl_803E83F4;
        ((CloudRunnerState*)p2)->baddie.velSmoothTime = lbl_803E83F8;
        if (((GameObject*)obj)->anim.currentMove != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0, fz, 0);
        }
        if (((ByteFlags*)&inner->flagsBC0)->b20)
        {
            ((ByteFlags*)&inner->flagsBC0)->b20 = 0;
            ((CloudRunnerState*)p2)->baddie.physicsActive = 0;
        }
    }
    if (((CloudRunnerState*)p2)->baddie.inputMagnitude < lbl_803E83BC)
    {
        *(s16*)((char*)p2 + 0x334) = 0;
        ((CloudRunnerState*)p2)->baddie.turnRate = 0;
        ((CloudRunnerState*)p2)->baddie.inputMagnitude = lbl_803E83A4;
    }
    return 0;
}

int DR_CloudRunner_stateHandler01(int obj, int p2)
{
    CloudRunnerState * inner;
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    *(int*)((char*)p2 + 0) |= 0x200000;
    if (*(s8*)&((CloudRunnerState*)p2)->baddie.moveJustStartedA != 0)
    {
        f32 fz;
        ObjHits_DisableObject(obj);
        ((CloudRunnerState*)p2)->baddie.physicsActive = 0;
        ((CloudRunnerState*)p2)->baddie.moveSpeed = lbl_803E8408;
        fz = lbl_803E83A4;
        ((CloudRunnerState*)p2)->baddie.animSpeedC = fz;
        ((CloudRunnerState*)p2)->baddie.animSpeedB = fz;
        ((CloudRunnerState*)p2)->baddie.animSpeedA = fz;
        ((GameObject*)obj)->anim.velocityX = fz;
        ((GameObject*)obj)->anim.velocityY = fz;
        ((GameObject*)obj)->anim.velocityZ = fz;
        return 0;
    }
    inner = ((GameObject*)obj)->extra;
    Vec_distance((int)&((GameObject*)obj)->anim.worldPosX, (int)&((GameObject*)Obj_GetPlayerObject())->anim.worldPosX);
    if (RandomTimer_UpdateRangeTrigger((char*)inner + 0xb54, lbl_803E83F8, lbl_803E840C))
    {
        Sfx_PlayFromObject(obj, SFXTRIG_lfoot_taunt);
    }
    if ((u32)GameBit_Get(((DRCloudRunnerPlacement*)placement)->enableGameBit) != 0)
    {
        ((GameObject*)obj)->unkF4 = 0;
        ObjHits_EnableObject(obj);
        ObjHits_SyncObjectPositionIfDirty(obj);
        ((ByteFlags*)&inner->flagsBC0)->b10 = inner->airTimeRemaining > 0;
        ((GameObject*)obj)->anim.rotX = gDRCloudRunnerDefaultRotX;
        return 3;
    }
    return 0;
}

int DR_CloudRunner_stateHandler03(int obj, int p2)
{
    CloudRunnerState * inner = ((GameObject*)obj)->extra;
    if (*(s8*)&((CloudRunnerState*)p2)->baddie.moveJustStartedA != 0)
    {
        ((ByteFlags*)&inner->flagsBC0)->b10 = 0;
        ((GameObject*)obj)->anim.velocityY = lbl_803E83A4;
        if (((ByteFlags*)&inner->flagsBC0)->b20)
        {
            ((ByteFlags*)&inner->flagsBC0)->b20 = 0;
            fn_802BF0C8(obj, p2, ((ByteFlags*)&inner->flagsBC0)->b20);
        }
    }
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x203:
        if (((DRCloudRunnerState*)inner)->altMoveEnabled != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x20c, lbl_803E83A4, 0);
            ((CloudRunnerState*)p2)->baddie.moveSpeed = lbl_803E8408;
        }
        break;
    case 0x20c:
        if (*(s8*)&((CloudRunnerState*)p2)->baddie.moveDone != 0)
        {
            ((DRCloudRunnerState*)inner)->flagsAD5 &= ~2;
            return 3;
        }
        break;
    default:
        {
            f32 fz;
            ObjAnim_SetCurrentMove(obj, 0x203, lbl_803E83A4, 0);
            ((DRCloudRunnerState*)inner)->flagsAD5 |= 2;
            fz = lbl_803E83A4;
            ((CloudRunnerState*)p2)->baddie.animSpeedC = fz;
            ((CloudRunnerState*)p2)->baddie.animSpeedB = fz;
            ((CloudRunnerState*)p2)->baddie.animSpeedA = fz;
            ((GameObject*)obj)->anim.velocityX = fz;
            ((GameObject*)obj)->anim.velocityY = fz;
            ((GameObject*)obj)->anim.velocityZ = fz;
            ((CloudRunnerState*)p2)->baddie.moveSpeed = lbl_803E8408;
            break;
        }
    }
    return 0;
}

void DR_CloudRunner_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    CloudRunnerState * inner = ((GameObject*)p1)->extra;
    if (((GameObject*)p1)->unkF4 == 0)
    {
        if (vis == -1)
        {
            objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E83A8);
            ObjPath_GetPointWorldPosition(p1, 3, (char*)(int)((char*)inner + 0xae8), (char*)(int)((char*)inner + 0xaec),
                                          (char*)(int)((char*)inner + 0xaf0), 0);
        }
        if (inner->flightState != CLOUDRUNNER_FLIGHT_MOUNTED && vis != 0)
        {
            objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E83A8);
            dll_2E_func06(p1, (char*)(int)((char*)inner + 0x4c4), 0);
        }
    }
}

int DR_CloudRunner_stateHandler00(int obj)
{
    CloudRunnerState * inner = ((GameObject*)obj)->extra;
    switch (inner->spawnVariant)
    {
    case 0:
        return 2;
    default:
        break;
    }
    ObjHits_EnableObject(obj);
    ObjHits_SyncObjectPositionIfDirty(obj);
    ((ByteFlags*)&inner->flagsBC0)->b10 = inner->airTimeRemaining > 0;
    return 3;
}

void DR_CloudRunner_func17(int obj, int param)
{
    CloudRunnerState * inner = ((GameObject*)obj)->extra;
    inner->flightState = param;
    if (param == CLOUDRUNNER_FLIGHT_TRANSITION)
    {
        s16 seqIndex;
        inner->unk464 = 0;
        seqIndex = ((GameObject*)obj)->seqIndex;
        if (seqIndex != -1)
        {
            (*gObjectTriggerInterface)->endSequence(seqIndex);
        }
    }
    else
    {
        inner->unk464 = 1;
    }
    if (param == CLOUDRUNNER_FLIGHT_MOUNTED)
    {
        GameBit_Set(CLOUDRUNNER_ONCLOUD_GAMEBIT, 1);
    }
    else
    {
        GameBit_Set(CLOUDRUNNER_ONCLOUD_GAMEBIT, 0);
    }
}

#pragma opt_loop_invariants off
int DR_CloudRunner_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    CloudRunnerState * inner = ((GameObject*)obj)->extra;
    int local = 1;
    int i;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch ((int)animUpdate->eventIds[i])
        {
        case 1:
            (*gRomCurveInterface)->initCurve((char*)inner + 0x35c, (void*)obj, lbl_803E8410, &local, 0xf);
            break;
        default:
            break;
        }
    }
    ((ByteFlags*)&inner->flagsBC1)->b80 = 1;
    return 0;
}
#pragma opt_loop_invariants reset

void DR_CloudRunner_func15(int obj, f32* a, f32* b, f32* c)
{
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 matrix[16];
    void* src = Obj_GetPlayerObject();
    if (src == NULL)
    {
        src = (void*)obj;
    }
    v.mat[1] = ((GameObject*)src)->anim.localPosX;
    v.mat[2] = ((GameObject*)src)->anim.localPosY;
    v.mat[3] = ((GameObject*)src)->anim.localPosZ;
    v.angles[0] = ((GameObject*)src)->anim.rotX;
    v.angles[1] = ((GameObject*)src)->anim.rotY;
    v.angles[2] = ((GameObject*)src)->anim.rotZ;
    v.mat[0] = lbl_803E83A8;
    setMatrixFromObjectPos(matrix, v.angles);
    Matrix_TransformPoint(matrix, lbl_803E83A4, lbl_803DC78C, lbl_803DC790, a, b, c);
}

void DR_CloudRunner_init(int obj, int p2)
{
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } stk;
    int inner;
    int r;
    ((GameObject*)obj)->anim.rotX = (s16)((s8) * (s8*)((char*)p2 + 0x18) << 8);
    ((GameObject*)obj)->animEventCallback = DR_CloudRunner_SeqFn;
    ObjGroup_AddObject(obj, DRCLOUDRUNNER_OBJGROUP);
    inner = *(int*)&((GameObject*)obj)->extra;
    ((DRCloudRunnerState*)inner)->spawnVariant = *(u8*)((char*)p2 + 0x19);
    ((DRCloudRunnerState*)inner)->unkBAE = 5;
    ((DRCloudRunnerState*)inner)->altMoveEnabled = *(s16*)((char*)p2 + 0x1a);
    ((DRCloudRunnerState*)inner)->unkBC4 = -1;
    ((DRCloudRunnerState*)inner)->unkB50 = (f32) * (s16*)((char*)p2 + 0x1c) / lbl_803E8414;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0xa10;
    }
    r = GameBit_Get(0x7a9);
    if (r != 0)
    {
        dll_2E_func0A(r + 0x13, &stk);
        ((GameObject*)obj)->anim.localPosX = stk.mat[1];
        ((GameObject*)obj)->anim.localPosY = stk.mat[2];
        ((GameObject*)obj)->anim.localPosZ = stk.mat[3];
        ((GameObject*)obj)->anim.rotX = stk.angles[0];
    }
    (*(void (*)(int, int, int, int))(*(int*)(*gPlayerInterface + 0x4)))(obj, inner, 8, 1);
    ((CloudRunnerState*)inner)->baddie.gravity = lbl_803E8424;
    fn_802BF0C8(obj, inner, ((ByteFlags*)((char*)inner + 0xbc0))->b20);
    dll_2E_func05(obj, inner + 0x4c4, -0x11c7, 0x1555, 1);
    dll_2E_func08(inner + 0x4c4, 0x12c, 0x78);
    ObjGroup_AddObject(obj, ARWARWING_OBJGROUP);
    ((ByteFlags*)((char*)inner + 0xbc0))->b01 = 0;
}

int DR_CloudRunner_stateHandler05(int obj, int baddie, f32 f)
{
    Vec3x* vt = (Vec3x*)gDRCloudRunnerVecTable;
    u8* base = gDRCloudRunnerMoveParamTable;
    u32 idx;
    int needMove = 0;
    CloudRunnerState * inner;
    int moveId;
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } s1;
    Vec3x vecB;
    Vec3x vecC;
    Vec3x vecN;
    Vec3x vecD;
    Vec3x vecE;
    f32 speed;
    f32 accel;
    f32 grav;
    f32 d8;
    f32 mag;
    f32 adot;
    f32 animSpd;
    f32 spd;
    f32 dot;
    f32 dist;
    f32 t;
    f32* lim;
    vecB = vt[2];
    vecC = vt[3];
    vecD = vt[4];
    moveId = -1;
    inner = ((GameObject*)obj)->extra;
    *(int*)((char*)baddie + 0) |= 0x200000;
    ((CloudRunnerState*)baddie)->baddie.physicsActive = 0;
    if (*(s8*)&((CloudRunnerState*)baddie)->baddie.moveDone != 0)
    {
        ((ByteFlags*)&inner->flagsBC0)->b80 = 0;
        ((ByteFlags*)&inner->flagsBC0)->b08 = 0;
        needMove = 1;
    }
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(s8*)&((CloudRunnerState*)baddie)->baddie.moveJustStartedA != 0)
    {
        if (!((ByteFlags*)&inner->flagsBC0)->b20)
        {
            ((ByteFlags*)&inner->flagsBC0)->b20 = 1;
            fn_802BF0C8(obj, baddie, ((ByteFlags*)&inner->flagsBC0)->b20);
        }
        ObjAnim_SetCurrentMove(obj, *(s16*)(base + 0x68), lbl_803E83A4, 0);
        inner->pitchAngle = *(s16*)(base + 0x74);
        inner->headingAngle = ((GameObject*)obj)->anim.rotX;
        inner->rollAngle = ((GameObject*)obj)->anim.rotZ;
        {
            f32 fz = lbl_803E83A4;
            ((CloudRunnerState*)baddie)->baddie.animSpeedC = fz;
            ((CloudRunnerState*)baddie)->baddie.animSpeedB = fz;
            ((CloudRunnerState*)baddie)->baddie.animSpeedA = fz;
            ((GameObject*)obj)->anim.velocityX = fz;
            ((GameObject*)obj)->anim.velocityY = fz;
            ((GameObject*)obj)->anim.velocityZ = fz;
        }
        needMove = 1;
        ((ByteFlags*)&inner->flagsBC0)->b80 = 1;
        inner->lastPosX = ((GameObject*)obj)->anim.localPosX;
        inner->lastPosY = ((GameObject*)obj)->anim.localPosY;
        inner->lastPosZ = ((GameObject*)obj)->anim.localPosZ;
    }
    *(int*)((char*)baddie + 0) |= 0x1000000;
    if (((CloudRunnerState*)baddie)->baddie.inputMagnitude < lbl_803E83BC)
    {
        *(s16*)((char*)baddie + 0x334) = 0;
        ((CloudRunnerState*)baddie)->baddie.turnRate = 0;
        {
            f32 fz = lbl_803E83A4;
            ((CloudRunnerState*)baddie)->baddie.moveInputX = fz;
            ((CloudRunnerState*)baddie)->baddie.moveInputZ = fz;
            ((CloudRunnerState*)baddie)->baddie.inputMagnitude = fz;
        }
    }
    speed = ((GameObject*)obj)->anim.currentMoveProgress;
    {
        s16* p;
        for (idx = 0, p = (s16*)(base + 0x60); ((GameObject*)obj)->anim.currentMove != *p && idx < 6; idx++)
        {
            p += 1;
        }
    }
    if (idx >= 6)
    {
        idx = 4;
    }
    mag = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
        ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ);
    spd = (mag < *(f32*)&lbl_803E83A4) ? lbl_803E83A4 : ((mag > *(f32*)&lbl_803E83C0) ? lbl_803E83C0 : mag);
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + (accel = ((grav = lbl_803E83C4) * spd) /
        lbl_803E83C0);
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - grav;
    if (spd > lbl_803E83A4)
    {
        if ((int)idx >= 4)
        {
            s1.angles[2] = ((GameObject*)obj)->anim.rotZ;
            s1.angles[1] = inner->pitchAngle - 0x4000;
            s1.angles[0] = ((GameObject*)obj)->anim.rotX;
            s1.mat[1] = lbl_803E83A4;
            s1.mat[2] = lbl_803E83A4;
            s1.mat[3] = lbl_803E83A4;
            s1.mat[0] = lbl_803E83A8;
            vecD.z = lbl_803E83C8;
            vecRotateZXY(&s1, &vecC);
            vecRotateZXY(&s1, &vecD);
            vecC.x = vecC.x * accel;
            vecC.y = vecC.y * accel;
            vecC.z = vecC.z * accel;
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + vecC.x;
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + vecC.z;
        }
        else
        {
            s1.angles[2] = ((GameObject*)obj)->anim.rotZ;
            s1.angles[1] = inner->pitchAngle;
            s1.angles[0] = ((GameObject*)obj)->anim.rotX;
            s1.mat[1] = lbl_803E83A4;
            s1.mat[2] = lbl_803E83A4;
            s1.mat[3] = lbl_803E83A4;
            s1.mat[0] = lbl_803E83A8;
            vecRotateZXY(&s1, &vecD);
            vecN.x = -((GameObject*)obj)->anim.velocityX;
            vecN.y = -((GameObject*)obj)->anim.velocityY;
            vecN.z = -((GameObject*)obj)->anim.velocityZ;
            dot = vecD.z * vecN.z + (vecD.x * vecN.x + vecD.y * vecN.y);
            adot = dot >= lbl_803E83A4 ? dot : -dot;
            Vec3_Normalize(&vecN);
            vecN.x = vecN.x * (lbl_803E83CC * adot + lbl_803E83C4 * ((lbl_803E83D0 * adot) / lbl_803E83C0));
            vecN.y = vecN.y * (lbl_803E83CC * adot + lbl_803E83C4 * ((lbl_803E83D0 * adot) / lbl_803E83C0));
            vecN.z = vecN.z * (lbl_803E83CC * adot + lbl_803E83C4 * ((lbl_803E83D0 * adot) / lbl_803E83C0));
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + vecN.x;
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + vecN.y;
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + vecN.z;
        }
    }
    if (((CloudRunnerState*)baddie)->baddie.inputMagnitude > lbl_803E83BC)
    {
        s1.angles[2] = 0;
        s1.angles[1] = 0;
        s1.angles[0] = ((GameObject*)obj)->anim.rotX;
        s1.mat[1] = lbl_803E83A4;
        s1.mat[2] = lbl_803E83A4;
        s1.mat[3] = lbl_803E83A4;
        s1.mat[0] = lbl_803E83A8;
        vecC.x = ((CloudRunnerState*)baddie)->baddie.moveInputX * lbl_803E83D4 * *(f32*)(base + ((int)idx >> 1) * 4 + 0x90);
        vecC.y = -((CloudRunnerState*)baddie)->baddie.moveInputZ * lbl_803E83D4 * *(f32*)(base + ((int)idx >> 1) * 4 +
            0x9c);
        vecC.z = lbl_803E83A4;
        vecRotateZXY(&s1, &vecC);
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + vecC.x;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + vecC.y;
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + vecC.z;
    }
    if (((ByteFlags*)&inner->flagsBC0)->b80 & (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E83D8))
    {
        s1.angles[2] = ((GameObject*)obj)->anim.rotZ;
        s1.angles[1] = inner->pitchAngle;
        s1.angles[0] = ((GameObject*)obj)->anim.rotX;
        s1.mat[1] = lbl_803E83A4;
        s1.mat[2] = lbl_803E83A4;
        s1.mat[3] = lbl_803E83A4;
        s1.mat[0] = lbl_803E83A8;
        vecRotateZXY(&s1, &vecB);
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX + vecB.x;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + vecB.y;
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ + vecB.z;
    }
    mag = sqrtf(((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ +
        (((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
            ((GameObject*)obj)->anim.velocityY * ((GameObject*)obj)->anim.velocityY));
    lim = (f32*)(base + ((int)idx >> 1) * 4 + 0xa8);
    if (mag > *lim)
    {
        Vec3_Normalize((void*)(obj + 0x24));
        ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * ((mag + *lim) * (d8 = lbl_803E83D8));
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * (d8 * (mag + *lim));
        ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * (d8 * (mag + *lim));
    }
    else
    {
        lim = (f32*)(base + ((int)idx >> 1) * 4 + 0xb4);
        if (mag < *lim)
        {
            Vec3_Normalize((void*)(obj + 0x24));
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * ((mag + *lim) * (d8 =
                lbl_803E83D8));
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * (d8 * (mag + *lim));
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * (d8 * (mag + *lim));
        }
    }
    if ((int)idx >= 4)
    {
        inner->headingAngle = inner->headingAngle - (int)((CloudRunnerState*)baddie)->baddie.moveInputX;
        inner->rollAngle = inner->rollAngle - ((int)((CloudRunnerState*)baddie)->baddie.moveInputX << 3);
        ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY - (int)((CloudRunnerState*)baddie)->baddie.moveInputZ
            * 3;
        inner->pitchAngle = inner->pitchAngle - (int)((CloudRunnerState*)baddie)->baddie.moveInputZ * 3;
    }
    else
    {
        inner->headingAngle = inner->headingAngle - ((int)((CloudRunnerState*)baddie)->baddie.moveInputX << 3);
        inner->rollAngle = inner->rollAngle - (int)((CloudRunnerState*)baddie)->baddie.moveInputX;
        ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY - (int)((CloudRunnerState*)baddie)->baddie.moveInputZ
            * 6;
        inner->pitchAngle = inner->pitchAngle - ((int)((CloudRunnerState*)baddie)->baddie.moveInputZ << 2);
    }
    if ((int)idx >= 4)
    {
        s16 ang;
        s16 diff;
        ang = (s16)(getAngle(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityZ) + 0x8000);
        diff = ang - (u16)inner->headingAngle;
        if (diff > 0x8000)
        {
            diff = diff - 0xffff;
        }
        if (diff < -0x8000)
        {
            diff = diff + 0xffff;
        }
        inner->headingAngle += diff / 64;
        inner->rollAngle += diff / 128;
    }
    {
        s16 lim2;
        if (inner->rollAngle > (lim2 = *(s16*)((char*)&gDRCloudRunnerRollAngleLimits + (idx & 0xfffffffe))))
        {
            inner->rollAngle = lim2;
        }
        else
        {
            int neg = -lim2;
            if (inner->rollAngle < neg)
            {
                inner->rollAngle = neg;
            }
        }
    }
    if (inner->pitchAngle > 0x4000)
    {
        inner->pitchAngle = 0x4000;
    }
    else if (inner->pitchAngle < -0x4000)
    {
        inner->pitchAngle = -0x4000;
    }
    ((GameObject*)obj)->anim.rotX = inner->headingAngle;
    ((GameObject*)obj)->anim.rotZ = inner->rollAngle;
    mag = sqrtf(((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ +
        (((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
            ((GameObject*)obj)->anim.velocityY * ((GameObject*)obj)->anim.velocityY));
    if (((ByteFlags*)&inner->flagsBC0)->b80 == 0 && (*(int*)&((CloudRunnerState*)baddie)->baddie.unk31C & 0x200))
    {
        Sfx_PlayFromObject(obj, SFXTRIG_sliftloop11);
        ((ByteFlags*)&inner->flagsBC0)->b80 = 1;
        speed = lbl_803E83A4;
        needMove = 1;
    }
    if (*(int*)((char*)baddie + 0) & 0x400000)
    {
        vecE.x = ((GameObject*)obj)->anim.previousLocalPosX - inner->lastPosX;
        vecE.y = ((GameObject*)obj)->anim.previousLocalPosY - inner->lastPosY;
        vecE.z = ((GameObject*)obj)->anim.previousLocalPosZ - inner->lastPosZ;
        dist = sqrtf(vecE.z * vecE.z + (vecE.x * vecE.x + vecE.y * vecE.y));
        t = (dist < lbl_803E83A4) ? lbl_803E83A4 : ((dist > lbl_803E83DC) ? lbl_803E83DC : dist);
        Vec3_Normalize(&vecE);
        {
            f32 scale = ((t / lbl_803E83DC) * (lbl_803E83E0 + (mag / lbl_803E83C0) * (mag / lbl_803E83C0))) / f;
            vecE.x = vecE.x * scale;
            vecE.y = vecE.y * scale;
            vecE.z = vecE.z * scale;
        }
        if (vecE.y < lbl_803E83A4)
        {
            vecE.y = lbl_803E83A4;
        }
        vecE.y = vecE.y * lbl_803E83E4;
        t = (vecE.y >= *(f32*)&lbl_803E83A4) ? vecE.y : -vecE.y;
        t = (lbl_803E83E8 - t) / *(f32*)&lbl_803E83E8;
        if (t < *(f32*)(int)&lbl_803E83A4)
        {
            t = lbl_803E83A4;
        }
        vecE.x = vecE.x * t;
        vecE.y = vecE.y * t;
        vecE.z = vecE.z * t;
        ((GameObject*)obj)->anim.velocityX = vecE.x + ((GameObject*)obj)->anim.velocityX;
        ((GameObject*)obj)->anim.velocityY = vecE.y + ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityZ = vecE.z + ((GameObject*)obj)->anim.velocityZ;
        ((GameObject*)obj)->anim.localPosX = inner->lastPosX;
        ((GameObject*)obj)->anim.localPosY = inner->lastPosY;
        ((GameObject*)obj)->anim.localPosZ = inner->lastPosZ;
        objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
                ((GameObject*)obj)->anim.velocityZ);
        if ((*(s8*)((char*)baddie + 0x264) & 0x10) && (int)(idx & 0xfe) == 0)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E83EC;
            return 3;
        }
        inner->lastPosX = ((GameObject*)obj)->anim.localPosX;
        inner->lastPosY = ((GameObject*)obj)->anim.localPosY;
        inner->lastPosZ = ((GameObject*)obj)->anim.localPosZ;
    }
    else
    {
        objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
                ((GameObject*)obj)->anim.velocityZ);
    }
    if (((ByteFlags*)&inner->flagsBC0)->b08 == 0 && (*(int*)&((CloudRunnerState*)baddie)->baddie.unk31C & 0x100))
    {
        buttonDisable(0, 0x100);
        moveId = 0x20d;
        animSpd = lbl_803E83F0;
        ((ByteFlags*)&inner->flagsBC0)->b08 = 1;
        needMove = 1;
        speed = lbl_803E83A4;
    }
    if (needMove != 0)
    {
        if (moveId == -1)
        {
            int masked = idx & 0xfe;
            ObjAnim_SetCurrentMove(
                obj, *(s16*)((u8*)&base[0x60] + (masked + ((ByteFlags*)&inner->flagsBC0)->b80) * 2), speed,
                0);
            ((CloudRunnerState*)baddie)->baddie.moveSpeed = ((f32*)(base + 0xc0))[masked >> 1];
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, moveId, speed, 0);
            ((CloudRunnerState*)baddie)->baddie.moveSpeed = animSpd;
        }
    }
    return 0;
}

void fn_802BF0C8(int obj, int p2, int mode)
{
    u8* base = gDRCloudRunnerMoveParamTable;
    int stk = lbl_803E83A0;
    u8* pathState = (u8*)&((CloudRunnerState*)p2)->baddie + 4;
    u8 m;
    pathState[0x25b] = 1;
    m = mode;
    if (m == 1)
    {
        (*gPathControlInterface)->init(pathState, 0, 0x42087, 0);
        (*gPathControlInterface)->setLocalPointCollision(pathState, 1, base + 0x18, &lbl_803DC774, 8);
        (*gPathControlInterface)->setup(pathState, 1, base + 0xc, &lbl_803DC770, &stk);
    }
    else if (m == 2)
    {
        (*gPathControlInterface)->init(pathState, 3, 0x42087, 0);
        (*gPathControlInterface)->setLocalPointCollision(pathState, 2, base + 0x30, &lbl_803DC77C, 8);
        (*gPathControlInterface)->setup(pathState, 1, base + 0x24, &lbl_803DC778, &stk);
    }
    else if (m == 0)
    {
        (*gPathControlInterface)->init(pathState, 3, 0x42087, 0);
        (*gPathControlInterface)->setLocalPointCollision(pathState, 2, base + 0x48, &lbl_803DC784, 8);
        (*gPathControlInterface)->setup(pathState, 1, base + 0x3c, &lbl_803DC780, &stk);
    }
    (*gPathControlInterface)->attachObject((void*)obj, pathState);
}

void DR_CloudRunner_func23(int obj, int mode, int* out)
{
    struct gbids
    {
        s16 a[4];
    } bits;
    struct curveids
    {
        int a[4];
    } curve;
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } stk;
    CloudRunnerState * inner;
    Obj_GetPlayerObject();
    curve = *(struct curveids*)gDRCloudRunnerCurveIds;
    bits = *(struct gbids*)&gDRCloudRunnerGameBitIds;
    inner = ((GameObject*)obj)->extra;
    switch (mode)
    {
    case 2:
        if ((((GameObject*)obj)->objectFlags & DRCLOUDRUNNER_OBJFLAG_PARENT_SLACK) || ((ByteFlags*)&inner->flagsBC1)->b80)
        {
            *out = ((GameObject*)obj)->anim.rotX;
            gDRCloudRunnerSmoothedRotX = ((GameObject*)obj)->anim.rotX;
            ((ByteFlags*)&inner->flagsBC1)->b80 = 0;
        }
        else
        {
            s16* p;
            s16 ang;
            int i;
            s16 diff;
            s16 step;
            ang = ((GameObject*)obj)->anim.rotX;
            i = 0;
            p = bits.a;
            do
            {
                if ((u32)GameBit_Get(*p) != 0)
                {
                    break;
                }
                p += 1;
                i += 1;
            }
            while (i < 4);
            if (i != 4 && dll_2E_func0A(curve.a[i], &stk) != 0)
            {
                s16 tmp = getAngle(stk.mat[1] - ((GameObject*)obj)->anim.localPosX,
                                        stk.mat[3] - ((GameObject*)obj)->anim.localPosZ);
                ang = tmp + gDRCloudRunnerHeadingAngleOffset;
            }
            diff = ang - (u16)gDRCloudRunnerSmoothedRotX;
            if (diff > 0x8000)
            {
                diff = diff - 0xffff;
            }
            if (diff < -0x8000)
            {
                diff = diff + 0xffff;
            }
            step = diff / 16;
            if (step < -0x50)
            {
                step = -0x50;
            }
            else if (step > 0x50)
            {
                step = 0x50;
            }
            gDRCloudRunnerSmoothedRotX = gDRCloudRunnerSmoothedRotX + (s16)step;
            *out = gDRCloudRunnerSmoothedRotX;
        }
        break;
    case 3:
        if (((GameObject*)obj)->objectFlags & DRCLOUDRUNNER_OBJFLAG_PARENT_SLACK)
        {
            *out = 0;
        }
        else
        {
            *out = 1;
        }
        break;
    case 4:
        *out = 1;
        break;
    }
}

int DR_CloudRunner_stateHandler06(int obj, int p2)
{
    CloudRunnerState * inner = ((GameObject*)obj)->extra;
    int hitState = *(int*)&((GameObject*)obj)->anim.hitReactState;
    *(int*)((char*)p2 + 0) |= 0x200000;
    if (*(s8*)&((CloudRunnerState*)p2)->baddie.moveJustStartedA != 0)
    {
        f32 dir[3];
        struct
        {
            s16 angles[4];
            f32 mat[4];
        } s1;
        void* newObj;
        int setup;
        inner->flagsBB6 &= ~8;
        ((ObjHitsPriorityState*)hitState)->flags = ((ObjHitsPriorityState*)hitState)->flags | 0x200;
        ObjAnim_SetCurrentMove(obj, 0xd, lbl_803E83A4, 0);
        ((CloudRunnerState*)p2)->baddie.moveSpeed = lbl_803E83B8;
        if (Obj_IsLoadingLocked() == 0)
        {
            return 0;
        }
        Sfx_PlayFromObject(obj, SFXtr_cnflyby6);
        setup = Obj_AllocObjectSetup(0x18, 0x42a);
        ((ObjPlacement*)setup)->color[2] = 0xff;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        ((ObjPlacement*)setup)->color[0] = 2;
        ((ObjPlacement*)setup)->color[1] = 1;
        ((ObjPlacement*)setup)->posX = inner->spawnPosX;
        ((ObjPlacement*)setup)->posY = inner->spawnPosY;
        ((ObjPlacement*)setup)->posZ = inner->spawnPosZ;
        newObj = (void*)Obj_SetupObject(setup, 5, -1, -1, 0);
        if (newObj != NULL)
        {
            s1.mat[1] = lbl_803E83A4;
            s1.mat[2] = lbl_803E83A4;
            s1.mat[3] = lbl_803E83A4;
            s1.mat[0] = lbl_803E83A8;
            s1.angles[0] = ((GameObject*)obj)->anim.rotX;
            s1.angles[1] = (s16)((((GameObject*)obj)->anim.rotY - 0x190) >> 1);
            s1.angles[2] = 0;
            dir[0] = lbl_803E83A4;
            dir[1] = lbl_803E83A4;
            dir[2] = lbl_803E83AC;
            vecRotateZXY(s1.angles, dir);
            ((GameObject*)newObj)->anim.velocityX = dir[0];
            ((GameObject*)newObj)->anim.velocityY = dir[1];
            ((GameObject*)newObj)->anim.velocityZ = dir[2];
            ((GameObject*)newObj)->unkF4 = 0xb4;
            ((GameObject*)newObj)->unkF8 = obj;
            ((GameObject*)newObj)->anim.rotZ = 0;
            ((GameObject*)newObj)->anim.rotY = 0;
            ((GameObject*)newObj)->anim.rotX = 0;
            (*gPartfxInterface)->spawnObject(newObj, 0x66, NULL, 2, -1, NULL);
        }
    }
    return 0;
}

void DR_CloudRunner_hitDetect(int obj)
{
    CloudRunnerState * inner = ((GameObject*)obj)->extra;
    int hitResult;
    s16* hits[4];
    s16 diff;
    if (inner->airTimeRemaining != 0 && ((GameObject*)obj)->anim.currentMove != 0xf &&
        (hitResult = ObjHits_GetPriorityHit(obj, hits, 0, 0)) != 0 && hitResult != 0xf &&
        inner->flightState == CLOUDRUNNER_FLIGHT_MOUNTED)
    {
        diff = ((GameObject*)obj)->anim.rotX - (u16) * hits[0];
        if (diff > 0x8000)
        {
            diff = diff - 0xffff;
        }
        if (diff < -0x8000)
        {
            diff += 0xffff;
        }
        if (diff > 0x4000 || diff < -0x4000)
        {
            ((ByteFlags*)&inner->flagsBC0)->b40 = 0;
        }
        else
        {
            ((ByteFlags*)&inner->flagsBC0)->b40 = 1;
        }
        inner->airTimeRemaining -= 1;
        if (inner->airTimeRemaining <= 0)
        {
            (*gGameUIInterface)->airMeterSetShutdown();
            (*gObjectTriggerInterface)->runSequence(5, (void*)obj, -1);
            inner->airTimeRemaining = 1;
            (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, (int)inner, 7);
        }
        Sfx_PlayFromObject(obj, SFXTRIG_gscsc);
    }
}

void fn_802C11BC(int obj, f32 f, int p2)
{
    CloudRunnerState * inner;
    int flag;
    int slot;
    if (p2 != -1)
    {
        flag = (((framesThisStep - 1) - p2) == 0);
    }
    else
    {
        flag = 1;
    }
    slot = (int)Camera_GetCurrentViewSlot();
    inner = ((GameObject*)obj)->extra;
    inner->baddie.hitPoints = 0;
    *(int*)&inner->baddie &= ~0x8000;
    *(int*)&inner->baddie |= 0x200000;
    if (inner->flightState == CLOUDRUNNER_FLIGHT_MOUNTED)
    {
        inner->baddie.moveInputX = (f32)(s8)
        padGetStickX(0);
        inner->baddie.moveInputZ = (f32)(s8)
        padGetStickY(0);
        *(int*)&inner->baddie.unk31C = getButtonsJustPressed(0);
        *(int*)&inner->baddie.unk318 = getButtonsHeld(0);
        inner->baddie.cameraYaw = *(s16*)slot;
        if (((ByteFlags*)&inner->flagsBC0)->b01 != 0)
        {
            Obj_UpdateRomCurveFollowVelocity(obj, (int)((char*)inner + 0x35c), inner->pathFollowSpeed, lbl_803E83B4,
                                             lbl_803E8414, 1);
        }
    }
    else
    {
        f32 v = lbl_803E83A4;
        inner->baddie.moveInputX = v;
        inner->baddie.moveInputZ = v;
        *(int*)&inner->baddie.unk31C = 0;
        *(int*)&inner->baddie.unk318 = 0;
        inner->baddie.cameraYaw = 0;
    }
    *(int*)&inner->baddie |= 0x400000;
    if (flag != 0)
    {
        *(int*)&inner->baddie &= ~0x400000;
    }
    (*(void (*)(int, int, f32, f32, int, void*))(*(int*)(*gPlayerInterface + 0x8)))(
        obj, (int)inner, f, timeDelta, (int)gDRCloudRunnerStateHandlers, &gDRCloudRunnerDefaultStateHandler);
    if ((*(int*)&inner->baddie.eventFlags & 1) != 0)
    {
        fn_802BF4D8(obj);
    }
    if (((ByteFlags*)&inner->flagsBC0)->b02 != 0)
    {
        (*gGameUIInterface)->runAirMeter(inner->airTimeRemaining - gDRCloudRunnerAirMeterBaseline);
    }
}

void DR_CloudRunner_update(int obj)
{
    CloudRunnerState * inner;
    Obj_GetPlayerObject();
    inner = ((GameObject*)obj)->extra;
    inner->unkBAE = 5;
    fn_80137948(sOnCloudFormat, GameBit_Get(CLOUDRUNNER_ONCLOUD_GAMEBIT));
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    if (inner->flightState == CLOUDRUNNER_FLIGHT_MOUNTED)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        fn_802C11BC(obj, timeDelta, -1);
        ((ObjAnimComponent*)obj)->modelInstance->flags |= 0x200000LL;
    }
    else
    {
        inner->baddie.physicsActive = 0;
        fn_802C11BC(obj, timeDelta, -1);
        ((ObjAnimComponent*)obj)->modelInstance->flags &= ~0x200000LL;
    }
    if (inner->cooldownTimer != 0)
    {
        s8 v = inner->cooldownTimer - framesThisStep;
        inner->cooldownTimer = v;
        if (v < 0)
        {
            inner->cooldownTimer = 0;
        }
    }
    if (inner->flightState == CLOUDRUNNER_FLIGHT_MOUNTED)
    {
        ObjHits_MarkObjectPositionDirty(obj);
        inner->moveFlags |= 1;
    }
    else
    {
        inner->moveFlags &= ~1;
    }
    dll_2E_func03(obj, (int)((char*)inner + 0x4c4));
    objAnimFn_80038f38(obj, (int)((char*)inner + 0x494));
    fn_8003B500(obj, (int)((char*)inner + 0x464), lbl_803E83A4);
    characterDoEyeAnims(obj, (int)inner + 0x464);
    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
    {
        if (inner->flightState == CLOUDRUNNER_FLIGHT_GROUNDED)
        {
            if (((ByteFlags*)&inner->flagsBC0)->b10)
            {
                f32 vec[3];
                buttonDisable(0, 0x100);
                if ((*gMapEventInterface)->getRestartGameNotCleared() == 0)
                {
                    vec[0] = lbl_803E8418;
                    vec[1] = lbl_803E841C;
                    vec[2] = lbl_803E8420;
                    (*gMapEventInterface)->restartPoint(vec, 0, 0, 0);
                }
                (*gObjectTriggerInterface)->runSequence(4, (void*)obj, -1);
                inner->unkB04 = 0;
                inner->flagsBB6 |= 4;
                inner->moveFlags |= 1;
                (*(void (*)(int, int, int))(*(int*)(*gPlayerInterface + 0x14)))(obj, (int)inner, 4);
            }
            else
            {
                buttonDisable(0, 0x100);
                {
                    s8 t = inner->sequenceIndex;
                    if (t != -1)
                    {
                        (*gObjectTriggerInterface)->runSequence(t, (void*)obj, -1);
                    }
                }
            }
        }
    }
}

void fn_802BF4D8(int obj)
{
    f32 dir[3];
    f32 diff[3];
    f32 pos[3];
    f32 gC[2];
    f32 gB[2];
    f32 tr[2];
    f32* pdiff = diff;
    struct
    {
        s16 angles[4];
        f32 mat[4];
    } s1;
    CloudRunnerState * inner = ((GameObject*)obj)->extra;
    void* newObj;
    int setup;
    f32 dist;
    if (Obj_IsLoadingLocked(obj) == 0)
    {
        return;
    }
    Sfx_PlayFromObject(obj, SFXtr_cnflyby6);
    setup = Obj_AllocObjectSetup(0x24, 0x42a);
    ((ObjPlacement*)setup)->color[2] = 0xff;
    ((ObjPlacement*)setup)->color[3] = 0xff;
    ((ObjPlacement*)setup)->color[0] = 2;
    ((ObjPlacement*)setup)->color[1] = 1;
    ((ObjPlacement*)setup)->posX = inner->spawnPosX;
    ((ObjPlacement*)setup)->posY = inner->spawnPosY;
    ((ObjPlacement*)setup)->posZ = inner->spawnPosZ;
    newObj = (void*)Obj_SetupObject(setup, 5, -1, -1, 0);
    if (newObj == NULL)
    {
        return;
    }
    s1.mat[1] = lbl_803E83A4;
    s1.mat[2] = lbl_803E83A4;
    s1.mat[3] = lbl_803E83A4;
    s1.mat[0] = lbl_803E83A8;
    s1.angles[0] = ((GameObject*)obj)->anim.rotX;
    s1.angles[1] = (s16)((((GameObject*)obj)->anim.rotY - 0x190) >> 1);
    s1.angles[2] = 0;
    dir[0] = lbl_803E83A4;
    dir[1] = lbl_803E83A4;
    dir[2] = lbl_803E83AC;
    vecRotateZXY(s1.angles, dir);
    ((GameObject*)newObj)->anim.velocityX = dir[0];
    ((GameObject*)newObj)->anim.velocityY = dir[1];
    ((GameObject*)newObj)->anim.velocityZ = dir[2];
    pos[0] = lbl_803E83B0 * ((GameObject*)newObj)->anim.velocityX;
    pos[1] = lbl_803E83B0 * ((GameObject*)newObj)->anim.velocityY;
    pos[2] = lbl_803E83B0 * ((GameObject*)newObj)->anim.velocityZ;
    pos[0] = ((GameObject*)newObj)->anim.localPosX + pos[0];
    pos[1] = ((GameObject*)newObj)->anim.localPosY + pos[1];
    pos[2] = ((GameObject*)newObj)->anim.localPosZ + pos[2];
    voxmaps_worldToGrid((void*)&((GameObject*)obj)->anim.worldPosX, gC);
    voxmaps_worldToGrid(pos, gB);
    if (voxmaps_traceLine(gC, gB, tr, 0, 0) == 0)
    {
        voxmaps_gridToWorld(pos, tr);
        diff[0] = pos[0] - ((GameObject*)newObj)->anim.localPosX;
        diff[1] = pos[1] - ((GameObject*)newObj)->anim.localPosY;
        diff[2] = pos[2] - ((GameObject*)newObj)->anim.localPosZ;
        dist = sqrtf(pdiff[2] * pdiff[2] + (pdiff[0] * pdiff[0] + pdiff[1] * pdiff[1]));
    }
    else
    {
        dist = lbl_803E83B4;
    }
    ((GameObject*)newObj)->unkF4 = dist;
    ((GameObject*)newObj)->unkF8 = obj;
    ((GameObject*)newObj)->anim.rotZ = 0;
    ((GameObject*)newObj)->anim.rotY = 0;
    ((GameObject*)newObj)->anim.rotX = 0;
    (*gPartfxInterface)->spawnObject(newObj, 0x66, NULL, 2, -1, NULL);
}

int DR_CloudRunner_stateHandler04(int obj, int baddie)
{
    CloudRunnerState * inner = ((GameObject*)obj)->extra;
    *(int*)((char*)baddie + 0) |= 0x1204000;
    ((CloudRunnerState*)baddie)->baddie.physicsActive = 0;
    if (*(s8*)&((CloudRunnerState*)baddie)->baddie.moveJustStartedA != 0)
    {
        f32 fz = lbl_803E83A4;
        CloudRunnerState * inner2;
        int placement;
        ((CloudRunnerState*)baddie)->baddie.animSpeedC = fz;
        ((CloudRunnerState*)baddie)->baddie.animSpeedB = fz;
        ((CloudRunnerState*)baddie)->baddie.animSpeedA = fz;
        ((GameObject*)obj)->anim.velocityX = fz;
        ((GameObject*)obj)->anim.velocityY = fz;
        ((GameObject*)obj)->anim.velocityZ = fz;
        inner2 = ((GameObject*)obj)->extra;
        placement = *(int*)&((GameObject*)obj)->anim.placementData;
        ((ByteFlags*)&inner2->flagsBC0)->b02 = 1;
        (*gGameUIInterface)->initAirMeter(((DRCloudRunnerPlacement*)placement)->airMeterCapacity, 0x5de);
        (*gGameUIInterface)->runAirMeter(inner2->airTimeRemaining);
        *(s16*)((char*)baddie + 0x338) = 0;
        ((CloudRunnerState*)baddie)->baddie.moveSpeed = lbl_803E83F4;
        ((CloudRunnerState*)baddie)->baddie.velSmoothTime = lbl_803E83F8;
        ObjAnim_SetCurrentMove(obj, 1, lbl_803E83A4, 0);
        ((ByteFlags*)&inner->flagsBC0)->b01 = 1;
    }
    {
        f32 fz = lbl_803E83A4;
        ((CloudRunnerState*)baddie)->baddie.animSpeedC = fz;
        ((CloudRunnerState*)baddie)->baddie.animSpeedB = fz;
        ((CloudRunnerState*)baddie)->baddie.animSpeedA = fz;
        ((GameObject*)obj)->anim.velocityX = fz;
        ((GameObject*)obj)->anim.velocityY = fz;
        ((GameObject*)obj)->anim.velocityZ = fz;
    }
    ((GameObject*)obj)->anim.localPosX = inner->posX;
    ((GameObject*)obj)->anim.localPosY = inner->posY;
    ((GameObject*)obj)->anim.localPosZ = inner->posZ;
    {
    int a0;
    int a1;
    a0 = getAngle(-inner->pathPointX, -inner->pathPointZ) & 0xffff;
    a1 = getAngle(inner->pathPointY,
                  sqrtf(inner->pathPointX * inner->pathPointX +
                      inner->pathPointZ * inner->pathPointZ)) & 0xffff;
    a0 -= (u16)((GameObject*)obj)->anim.rotX;
    if (a0 > 0x8000)
    {
        a0 = a0 - 0xffff;
    }
    if (a0 < -0x8000)
    {
        a0 = a0 + 0xffff;
    }
    ((GameObject*)obj)->anim.rotX =
        (f32)(s32)((GameObject*)obj)->anim.rotX + interpolate((f32)(s32)a0, lbl_803E83FC, timeDelta);
    a1 -= (u16)((GameObject*)obj)->anim.rotY;
    if (a1 > 0x8000)
    {
        a1 = a1 - 0xffff;
    }
    if (a1 < -0x8000)
    {
        a1 = a1 + 0xffff;
    }
    ((GameObject*)obj)->anim.rotY =
        (f32)(s32)((GameObject*)obj)->anim.rotY + interpolate((f32)(s32)a1, lbl_803E83FC, timeDelta);
    ((GameObject*)obj)->anim.rotZ = (s16)(a0 >> 5);
    }
    {
        int v = ((GameObject*)obj)->anim.rotZ;
        if (v < -0x1000)
        {
            v = -0x1000;
        }
        else if (v > 0x1000)
        {
            v = 0x1000;
        }
        ((GameObject*)obj)->anim.rotZ = v;
    }
    return 0;
}

u8 gDRCloudRunnerMoveParamTable[] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xA0, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC1, 0xA0, 0x00, 0x00,
    0x01, 0x17, 0x01, 0x1C, 0x01, 0x18, 0x01, 0x1B, 0x01, 0x16, 0x01, 0x1E,
    0x23, 0x8E, 0xF8, 0xE4, 0x03, 0x8E, 0xCE, 0x39, 0xF5, 0x56, 0xB8, 0xE4,
    0x00, 0x00, 0x00, 0x00, 0x3F, 0xC3, 0xD7, 0x0A, 0x3F, 0xC3, 0xD7, 0x0A,
    0x40, 0x22, 0x8F, 0x5C, 0x40, 0x19, 0x99, 0x9A, 0x40, 0x96, 0x66, 0x66,
    0x3C, 0xA3, 0xD7, 0x0A, 0x3C, 0xF5, 0xC2, 0x8F, 0x3D, 0x75, 0xC2, 0x8F,
    0x3C, 0xA3, 0xD7, 0x0A, 0x3C, 0xF5, 0xC2, 0x8F, 0x3D, 0xCC, 0xCC, 0xCD,
    0x3F, 0xC0, 0x00, 0x00, 0x40, 0x86, 0x66, 0x66, 0x40, 0x93, 0x33, 0x33,
    0x00, 0x00, 0x00, 0x00, 0x3F, 0x33, 0x33, 0x33, 0x3F, 0x80, 0x00, 0x00,
    0x3C, 0xA3, 0xD7, 0x0A, 0x3C, 0xA3, 0xD7, 0x0A, 0x3D, 0x23, 0xD7, 0x0A,
    0x3C, 0x23, 0xD7, 0x0A,
};

ObjectDescriptor24 gDR_CloudRunnerObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_24_SLOTS,
    (ObjectDescriptorCallback)DR_CloudRunner_initialise,
    (ObjectDescriptorCallback)DR_CloudRunner_release,
    0,
    (ObjectDescriptorCallback)DR_CloudRunner_init,
    (ObjectDescriptorCallback)DR_CloudRunner_update,
    (ObjectDescriptorCallback)DR_CloudRunner_hitDetect,
    (ObjectDescriptorCallback)DR_CloudRunner_render,
    (ObjectDescriptorCallback)DR_CloudRunner_free,
    (ObjectDescriptorCallback)DR_CloudRunner_getObjectTypeId,
    DR_CloudRunner_getExtraSize,
    (ObjectDescriptorCallback)DR_CloudRunner_setScale,
    (ObjectDescriptorCallback)DR_CloudRunner_func11,
    (ObjectDescriptorCallback)DR_CloudRunner_modelMtxFn,
    (ObjectDescriptorCallback)DR_CloudRunner_render2,
    (ObjectDescriptorCallback)DR_CloudRunner_func14,
    (ObjectDescriptorCallback)DR_CloudRunner_func15,
    (ObjectDescriptorCallback)DR_CloudRunner_func16,
    (ObjectDescriptorCallback)DR_CloudRunner_func17,
    (ObjectDescriptorCallback)DR_CloudRunner_func18,
    (ObjectDescriptorCallback)DR_CloudRunner_func19,
    (ObjectDescriptorCallback)DR_CloudRunner_func20,
    (ObjectDescriptorCallback)DR_CloudRunner_func21,
    (ObjectDescriptorCallback)DR_CloudRunner_func22,
    (ObjectDescriptorCallback)DR_CloudRunner_func23,
};

char sOnCloudFormat[] = "ON CLOUD=%d\n";
