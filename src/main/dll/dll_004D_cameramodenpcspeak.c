/* DLL 0x004D (cameramodenpcspeak) — Camera mode NPC speak handlers [0x8010DB7C-0x8010E51C). */
#include "main/dll/CAM/camnpcspeak_state.h"
#include "main/mm.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/dll/CAM/cutCam.h"

extern s16 getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern float mathCosf(float x);
extern void Rcp_DisableBlurFilter(void);

extern CameraModeNpcSpeakState* lbl_803DD584;

extern f32 lbl_803E19D0;
extern f32 lbl_803E19D4;
extern f32 lbl_803E19D8;
extern f32 lbl_803E19DC;

void fn_8010DB7C(GameObject* target, f32* outX, f32* outY, f32* outZ);

extern int FUN_80017730();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern uint Obj_GetYawDeltaToObject();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 DAT_802c2910;
extern undefined4 DAT_802c2914;
extern undefined4 DAT_802c2918;
extern float* DAT_803de1fc;
extern f32 lbl_803E2658;
extern f32 lbl_803E265C;
extern f32 mathCosf(f32);
extern f32 mathSinf(f32);
extern f32 timeDelta;
extern CameraModeCloudRunnerState* lbl_803DD5B8;
extern int getFocusedNpc(void);
extern int randomGetRange(int lo, int hi);
extern void fn_8010DB7C(GameObject * target, f32 * a, f32 * b, f32 * c);
extern const f32 lbl_803E19E8;
extern f32 lbl_803E19EC;
extern f32 lbl_803E19F0;
extern f32 lbl_803E19F4;
extern f32 lbl_803E19F8;
extern f32 lbl_803E19FC;
extern f32 lbl_803E1A00;
extern f32 lbl_803E1A04;
extern f32 lbl_803E1A08;
extern f32 lbl_803E1A0C;
extern f32 lbl_803E1A10;
extern f32 lbl_803E1A14;
extern f32 lbl_803E1A18;
extern f32 lbl_803E1A1C;
extern f32 lbl_803E1A20;
extern f32 lbl_803DB9C0;
extern f32 lbl_803DB9A8;
extern f32 lbl_803DB9AC;
extern f32 lbl_803DB9B0;
extern f32 lbl_803DB9B4;
extern f32 lbl_803DB9B8;
extern int lbl_803DB9BC;
extern f32 lbl_803DD580;
extern void turnOnBlurFilter(f32 x, f32 y, f32 z, int a, int b);
extern f32 lbl_803DB9C4;
extern s16 getAngle(f32 x, f32 z);
extern f32 mathCosf(f32 x);

void CameraModeNpcSpeak_copyToCurrent_nop(void)
{
}

void CameraModeNpcSpeak_free(void)
{
    mm_free(lbl_803DD584);
    lbl_803DD584 = 0;
    Rcp_DisableBlurFilter();
}

#pragma scheduling on
#pragma peephole on
void FUN_8010de18_v11_drift(undefined4 param_1, undefined4 param_2, float* param_3, float* param_4)
{
    float fVar1;
    float* pfVar2;
    int iVar3;
    double dVar4;
    double dVar5;
    double dVar6;
    double dVar7;
    double dVar8;
    undefined8 uVar9;

    uVar9 = FUN_8028683c();
    pfVar2 = DAT_803de1fc;
    iVar3 = (int)((ulonglong)uVar9 >> 0x20);
    dVar7 = (double)(*(float*)(iVar3 + 0x18) - *DAT_803de1fc);
    dVar5 = (double)(*(float*)(iVar3 + 0x20) - DAT_803de1fc[2]);
    dVar4 = FUN_80293900((double)(float)(dVar7 * dVar7 + (double)(float)(dVar5 * dVar5)));
    FUN_80017730();
    dVar8 = (double)((float)(dVar7 * (double)DAT_803de1fc[0x11]) + *pfVar2);
    dVar6 = (double)((float)(dVar5 * (double)DAT_803de1fc[0x11]) + pfVar2[2]);
    dVar5 = (double)FUN_80293f90();
    dVar7 = (double)FUN_80294964();
    if (dVar4 < (double)DAT_803de1fc[0x10])
    {
        dVar4 = (double)DAT_803de1fc[0x10];
    }
    fVar1 = DAT_803de1fc[4];
    *(float*)uVar9 = (float)(dVar5 * (double)(float)(dVar4 + (double)fVar1) + dVar8);
    *param_3 = -(lbl_803E2658 * ((lbl_803E265C + *(float*)(iVar3 + 0x1c)) - pfVar2[1]) -
        (*(float*)(iVar3 + 0x1c) + DAT_803de1fc[0xc]));
    *param_4 = (float)(dVar7 * (double)(float)(dVar4 + (double)fVar1) + dVar6);
    FUN_80286888();
    return;
}

void FUN_801115e0(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9, int param_10)
{
    uint uVar1;
    undefined2* puVar2;
    undefined4 uVar3;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined2 uStack_1a;
    undefined4 local_18;
    undefined4 local_14;
    undefined2 local_10;

    local_18 = DAT_802c2910;
    local_14 = DAT_802c2914;
    local_10 = DAT_802c2918;
    if ((*(char*)(param_10 + 0x407) != *(char*)(param_10 + 0x409)) &&
        (((GameObject*)param_9)->anim.alpha != 0))
    {
        if (*(int*)&((GameObject*)param_9)->childObjs[0] != 0)
        {
            param_1 = FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                   *(int*)&((GameObject*)param_9)->childObjs[0]);
            *(undefined4*)&((GameObject*)param_9)->childObjs[0] = 0;
        }
        uVar1 = FUN_80017ae8();
        if ((uVar1 & 0xff) == 0)
        {
            *(u8*)(param_10 + 0x409) = 0;
        }
        else
        {
            if (0 < *(char*)(param_10 + 0x407))
            {
                puVar2 = FUN_80017aa4(0x18, (&uStack_1a)[*(char*)(param_10 + 0x407)]);
                uVar3 = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, puVar2,
                                     4, 0xff, 0xffffffff, *(uint**)&((GameObject*)param_9)->anim.parent, in_r8, in_r9,
                                     in_r10);
                *(undefined4*)&((GameObject*)param_9)->childObjs[0] = uVar3;
                *(ushort*)(*(int*)&((GameObject*)param_9)->childObjs[0] + 0xb0) = ((GameObject*)param_9)->objectFlags &
                    7;
            }
            *(u8*)(param_10 + 0x409) = *(u8*)(param_10 + 0x407);
        }
    }
    return;
}

#pragma scheduling off
#pragma peephole off
void CameraModeNpcSpeak_release(void)
{
}

void CameraModeNpcSpeak_initialise(void)
{
}

void CameraModeWorldMap_release(void);

void CameraModeForceBehind_func06_nop(void)
{
}

void CameraModeForceBehind_func05_nop(void)
{
}

void CameraModeForceBehind_release(void);

void fn_801101E4(void)
{
}

void CameraModeCloudRunner_release(void);

void fn_80110C80(void)
{
}

void CameraModePerv_release(void);

void fn_80110EC0(void)
{
}

void CameraModeArwing_release(void);

#pragma opt_common_subs off
#pragma opt_common_subs reset

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void CameraModeCloudRunner_free(void);

#pragma dont_inline on
#pragma dont_inline reset

typedef struct CameraModeNpcSpeakInitParams
{
    f32 anchorX;
    f32 anchorY;
    f32 anchorZ;
    u8 mode;
} CameraModeNpcSpeakInitParams;

#pragma opt_common_subs off
void CameraModeNpcSpeak_init(u8* obj, int unused, u8* p3)
{
    CameraObject* camera = (CameraObject*)obj;
#define target ((GameObject*)camera->anim.targetObj)
    int mode = 0;
    int yawA, yawB;
    int spd;
    int d1, d2;
    int npc;
    f32 vd[3], vc[3], vb[3], va[3];
    u8 traceWork[CAMCONTROL_TRACE_WORK_SIZE];

    if (lbl_803DD584 == NULL)
    {
        lbl_803DD584 = (CameraModeNpcSpeakState*)mmAlloc(sizeof(CameraModeNpcSpeakState), 15, 0);
    }

    if (p3 != NULL)
    {
        CameraModeNpcSpeakInitParams* params = (CameraModeNpcSpeakInitParams*)p3;
        lbl_803DD584->anchorX = params->anchorX;
        lbl_803DD584->anchorY = params->anchorY;
        lbl_803DD584->anchorZ = params->anchorZ;
        mode = params->mode;
    }
    else
    {
        GameObject* focus = (GameObject*)getFocusedNpc();
        f32* fpos;
        if (focus == NULL)
        {
            lbl_803DD584->anchorX = lbl_803E19E8;
            lbl_803DD584->anchorY = lbl_803E19E8;
            lbl_803DD584->anchorZ = lbl_803E19E8;
        }
        fpos = *(f32**)((u8*)focus + 0x74);
        if (fpos == NULL)
        {
            lbl_803DD584->anchorX = lbl_803E19E8;
            lbl_803DD584->anchorY = lbl_803E19E8;
            lbl_803DD584->anchorZ = lbl_803E19E8;
        }
        lbl_803DD584->anchorX = fpos[0];
        lbl_803DD584->anchorY = fpos[1];
        lbl_803DD584->anchorZ = fpos[2];
    }
    if (mode == 4)
    {
        mode = randomGetRange(0, 3);
    }
    {
        f32 a, b;
        lbl_803DD584->unk20 = 0;
        lbl_803DD584->mode = mode;
        lbl_803DD584->unk14 = lbl_803E19E8;
        a = lbl_803E19EC;
        lbl_803DD584->targetHeightOffset = a;
        lbl_803DD584->lookAtHeightOffset = lbl_803E19DC;
        lbl_803DD584->lookAtYScale = lbl_803E19F0;
        b = lbl_803E19F4;
        lbl_803DD584->anchorLerpScale = b;
        lbl_803DD584->lookAtXZScale = b;
        lbl_803DD584->minDistance = a;
    }
    lbl_803DD584->orbitAngleOffset = randomGetRange(0x2000, 0x2c00);

    switch (mode)
    {
    case 0:
        lbl_803DD584->distanceOffset = lbl_803E19F8;
        break;
    case 1:
        lbl_803DD584->distanceOffset = lbl_803E19FC;
        break;
    case 2:
        lbl_803DD584->distanceOffset = lbl_803E1A00;
        break;
    case 5:
        lbl_803DD584->distanceOffset = lbl_803E1A04;
        break;
    case 3:
        lbl_803DD584->distanceOffset = lbl_803DB9C0;
        lbl_803DD584->orbitAngleOffset = randomGetRange(0xf00, 0x1f00);
        lbl_803DD584->lookAtHeightOffset = lbl_803E19E8;
        break;
    case 6:
        lbl_803DD584->targetHeightOffset = lbl_803DB9A8;
        lbl_803DD584->lookAtHeightOffset = lbl_803DB9AC;
        lbl_803DD584->anchorLerpScale = lbl_803DD580;
        lbl_803DD584->lookAtYScale = lbl_803DB9B0;
        lbl_803DD584->orbitAngleOffset = lbl_803DB9BC;
        lbl_803DD584->lookAtXZScale = lbl_803DB9B4;
        lbl_803DD584->distanceOffset = lbl_803DB9B8;
        lbl_803DD584->orbitAngleVelocity = 0xb6;
        lbl_803DD584->minDistance = lbl_803E19E8;
        break;
    case 7:
        lbl_803DD584->distanceOffset = lbl_803E19F8;
        lbl_803DD584->targetHeightOffset = lbl_803E1A08;
        lbl_803DD584->anchorLerpScale = lbl_803E1A0C;
        lbl_803DD584->lookAtXZScale = lbl_803E1A10;
        lbl_803DD584->lookAtYScale = lbl_803E1A14;
        lbl_803DD584->orbitAngleOffset = randomGetRange(0x1800, 0x1c00);
        break;
    case 8:
        lbl_803DD584->distanceOffset = lbl_803E1A18;
        lbl_803DD584->lookAtHeightOffset = lbl_803E1A1C;
        break;
    default:
        lbl_803DD584->distanceOffset = lbl_803E19F8;
        break;
    }

    yawA = (u16)getAngle(camera->anim.worldPosX - lbl_803DD584->anchorX,
                         camera->anim.worldPosZ - lbl_803DD584->anchorZ);
    yawB = (u16)getAngle(target->anim.worldPosX - lbl_803DD584->anchorX,
                         target->anim.worldPosZ - lbl_803DD584->anchorZ);
    spd = lbl_803DD584->orbitAngleOffset;
    d1 = (yawB + spd) - yawA;
    if (d1 > 0x8000)
    {
        d1 -= 0xffff;
    }
    if (d1 < -0x8000)
    {
        d1 += 0xffff;
    }
    d2 = (yawB - spd) - yawA;
    if (d2 > 0x8000)
    {
        d2 -= 0xffff;
    }
    if (d2 < -0x8000)
    {
        d2 += 0xffff;
    }
    if (d1 < 0)
    {
        d1 = -d1;
    }
    if (d2 < 0)
    {
        d2 = -d2;
    }
    if (d2 < d1)
    {
        lbl_803DD584->orbitAngleOffset = -spd;
        lbl_803DD584->orbitAngleVelocity = -0x80;
    }

    if (mode != 6 && mode != 7 && (npc = getFocusedNpc()) != 0)
    {
        s16 sd;
        int dd;
        sd = (s16)(yawB - (u16)target->anim.rotX);
        if (sd > 0x8000)
        {
            sd -= 0xffff;
        }
        if (sd < -0x8000)
        {
            sd += 0xffff;
        }
        dd = sd - (u16)(s16)
        Obj_GetYawDeltaToObject((int)target, npc, 0);
        if (dd > 0x8000)
        {
            dd -= 0xffff;
        }
        if (dd < -0x8000)
        {
            dd += 0xffff;
        }
        if ((dd > 0x1000 && lbl_803DD584->orbitAngleOffset > 0) ||
            (dd < -0x1000 && lbl_803DD584->orbitAngleOffset < 0))
        {
            lbl_803DD584->orbitAngleOffset = -lbl_803DD584->orbitAngleOffset;
        }
    }

    fn_8010DB7C(target, va, vb, vc);
    camcontrol_traceMove(&camera->anim.worldPosX, va, (void*)&lbl_803DD584->cameraX, traceWork, 3, 1,
                         1, lbl_803E1A20);
}
#undef target
#pragma opt_common_subs reset

void CameraModeNpcSpeak_update(u8* obj)
{
    extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int mtx); /* #57 */
    CameraObject* camera = (CameraObject*)obj;
    CameraModeNpcSpeakState* speakState;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    f32 ex, ez, ey;
    f32 dx, dy, dz;

    if (target == NULL)
    {
        return;
    }
    speakState = lbl_803DD584;
    if (speakState->mode == 6)
    {
        speakState->orbitAngleOffset =
            (s32)((f32)speakState->orbitAngleVelocity * timeDelta + (f32)speakState->orbitAngleOffset);
        if (lbl_803DD584->orbitAngleVelocity > 0 && lbl_803DD584->orbitAngleOffset > 0xd6d8)
        {
            lbl_803DD584->orbitAngleOffset = 0xd6d8;
        }
        else if (lbl_803DD584->orbitAngleVelocity < 0 && lbl_803DD584->orbitAngleOffset < -0xd6d8)
        {
            lbl_803DD584->orbitAngleOffset = -0xd6d8;
        }
        fn_8010DB7C(target, &lbl_803DD584->cameraX, &lbl_803DD584->cameraY, &lbl_803DD584->cameraZ);
    }
    camera->anim.worldPosX = lbl_803DD584->cameraX;
    camera->anim.worldPosY = lbl_803DD584->cameraY;
    camera->anim.worldPosZ = lbl_803DD584->cameraZ;
    dx = target->anim.worldPosX - speakState->anchorX;
    dy = (target->anim.worldPosY + lbl_803DD584->lookAtHeightOffset) - speakState->anchorY;
    dz = target->anim.worldPosZ - speakState->anchorZ;
    dx *= lbl_803DD584->lookAtXZScale;
    dy *= lbl_803DD584->lookAtYScale;
    dz *= lbl_803DD584->lookAtXZScale;
    if (lbl_803DD584->mode == 3)
    {
        camera->anim.rotY = (s16)(s32)
        getAngle(lbl_803DB9C4 * dy, sqrtf(dx * dx + dz * dz));
    }
    dx += speakState->anchorX;
    dy += speakState->anchorY;
    dz += speakState->anchorZ;
    ex = camera->anim.worldPosX - dx;
    ey = camera->anim.worldPosY - dy;
    ez = camera->anim.worldPosZ - dz;
    camera->anim.rotX = (s16)(0x8000 - getAngle(ex, ez));
    if (lbl_803DD584->mode != 3)
    {
        camera->anim.rotY = (s16)(s32)
        getAngle(ey, sqrtf(ex * ex + ez * ez));
    }
    turnOnBlurFilter(speakState->anchorX, speakState->anchorY, speakState->anchorZ, 1, 0);
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}

int dll_19_func0F(int obj, char* state, char* st, int p4, int p5, s16 p6);

/* EN v1.0 0x80114184  size: 160b  Copies a curve point's position and packed
 * angle into the caller's record. */

/* EN v1.0 0x80114084  size: 256b  Copies a curve point's position into the
 * caller's record and aims its angle at the nearest group-8 object (falling
 * back to the point's packed angle). */

/* EN v1.0 0x80113864  size: 248b  Steps the movement blend factors toward the
 * current target and turns the yaw by the buffered turn rate. */

/* EN v1.0 0x80114F64  size: 280b  Initializes the movement-state block and
 * primes the animation channel tables. */

/* EN v1.0 0x80114DEC  size: 376b  Latches the path-relative start offset on
 * first use and refreshes the current path point position. */

/* EN v1.0 0x80113BD0  size: 396b  Computes the yaw step, signed yaw delta and
 * distance from an object to its target, updating the wide-turn flag. */

/* EN v1.0 0x80113D64  size: 544b  Probes the four compass directions around
 * the object for walkable space, returning a bitmask of clear directions. */

/* EN v1.0 0x801145BC  size: 512b  Advances the object along its movement
 * curve, snapping to ground and easing the yaw toward the path direction. */

/* EN v1.0 0x80114BB0  size: 572b  Object-sequence scripted-move step: phase 4
 * arms the move, phase 5 walks the setup/playback sub-phases. */

/* EN v1.0 0x8011395C  size: 628b  Constrains a follow point against the
 * object's facing plane and returns the lateral offset of the result. */

/* EN v1.0 0x801147BC  size: 864b  Homes the object toward its target at the
 * given speed, snapping when close, easing yaw and pacing the walk anim. */

void fn_8010DB7C(GameObject* target, f32* outX, f32* outY, f32* outZ)
{
    CameraModeNpcSpeakState* state = lbl_803DD584;
    f32 dx;
    f32 dz;
    f32 dist;
    u16 angle;
    f32 cosVal;
    f32 sinVal;

    dx = target->anim.worldPosX - state->anchorX;
    dz = target->anim.worldPosZ - state->anchorZ;
    dist = sqrtf(dx * dx + dz * dz);
    angle = (u16)getAngle(dx, dz);

    {
        f32 scale = lbl_803DD584->anchorLerpScale;
        dx *= scale;
        dz *= scale;
    }
    dx += state->anchorX;
    dz += state->anchorZ;

    cosVal = mathSinf(lbl_803E19D0 * (f32)(s32)(angle + lbl_803DD584->orbitAngleOffset) / lbl_803E19D4);
    sinVal = mathCosf(lbl_803E19D0 * (f32)(s32)(angle + lbl_803DD584->orbitAngleOffset) / lbl_803E19D4);

    if (dist < lbl_803DD584->minDistance)
    {
        dist = lbl_803DD584->minDistance;
    }
    dist += lbl_803DD584->distanceOffset;

    *outX = cosVal * dist + dx;
    *outY = (target->anim.worldPosY + lbl_803DD584->targetHeightOffset) - lbl_803E19D8 * ((lbl_803E19DC + target->anim.
        worldPosY) - state->anchorY);
    *outZ = sinVal * dist + dz;
}
