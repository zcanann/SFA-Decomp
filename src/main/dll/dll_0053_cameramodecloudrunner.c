/* DLL 0x0053 (cameramodecloudrunner) — Camera mode CloudRunner handlers [0x801101E4-0x801106B4). */
#include "main/mm.h"

extern s16 getAngle(f32 dx, f32 dz);
extern f32 mathSinf(f32 x);
extern float mathCosf(float x);

#include "main/camera_object.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/game_object.h"
#include "main/dll/player_motion.h"

extern int FUN_80017730();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
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

#pragma scheduling on
#pragma peephole on
extern f32 mathCosf(f32);
extern f32 mathSinf(f32);
extern CameraModeCloudRunnerState* lbl_803DD5B8;
extern int fn_802972A8(int state);
extern void setMatrixFromObjectPos(f32* matrix, void* objpos);
extern void Matrix_TransformPoint(f32* matrix, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern f32 lbl_803E1B20;
extern f32 lbl_803E1B24;
extern f32 lbl_803E1B28;
extern f32 lbl_803E1B2C;
extern f32 lbl_803E1B30;
extern f32 lbl_803E1B34;
extern f32 lbl_803DB9D0;
extern int lbl_803DB9D4;
extern s16 getAngle(f32 x, f32 z);
extern f32 mathCosf(f32 x);

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

void CameraModeNpcSpeak_release(void);

#pragma scheduling off
#pragma peephole off
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

void CameraModeCloudRunner_release(void)
{
}

void CameraModeCloudRunner_initialise(void)
{
}

void dll_54_func06_nop(void);

void fn_80110C80(void)
{
}

void CameraModePerv_release(void);

void fn_80110EC0(void)
{
}

void CameraModeArwing_release(void);

void CameraModeCloudRunner_copyToCurrent(void)
{
}

void CameraModePerv_copyToCurrent(void);

#pragma opt_common_subs off
#pragma opt_common_subs reset

void CameraModeCloudRunner_init(int* p1, int p2, f32* p3)
{
    int* p1_a4 = ((int**)p1)[0xA4 / 4];
    if (lbl_803DD5B8 == NULL)
    {
        lbl_803DD5B8 = (CameraModeCloudRunnerState*)mmAlloc(sizeof(CameraModeCloudRunnerState), 15, 0);
    }
    {
        f32 v;
        if (p3 != NULL)
        {
            lbl_803DD5B8->focusX = p3[0];
            lbl_803DD5B8->focusY = p3[1];
            lbl_803DD5B8->focusZ = p3[2];
            v = p3[3];
        }
        else
        {
            lbl_803DD5B8->focusX = ((GameObject*)p1_a4)->anim.worldPosX;
            lbl_803DD5B8->focusY = ((GameObject*)p1_a4)->anim.worldPosY;
            lbl_803DD5B8->focusZ = ((GameObject*)p1_a4)->anim.worldPosZ;
            v = (f32)p2;
        }
        lbl_803DD5B8->radius = v;
    }
    getAngle(
        ((GameObject*)p1)->anim.worldPosX - lbl_803DD5B8->focusX,
        ((GameObject*)p1)->anim.worldPosZ - lbl_803DD5B8->focusZ);
    {
        int* a4 = ((int**)p1)[0xA4 / 4];
        f32* q = (f32*)lbl_803DD5B8;
        getAngle(
            ((GameObject*)a4)->anim.worldPosX - q[0],
            ((GameObject*)a4)->anim.worldPosZ - q[2]);
    }
}

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void CameraModeCloudRunner_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void dll_54_func05(void);

#pragma dont_inline on
#pragma dont_inline reset

void CameraModeCloudRunner_update(u8* obj)
{
    extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int mtx); /* #57 */
    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    u8* curve;
    s16 tgtYaw;
    s16 tgtPitch;
    f32 baseX, baseY, baseZ;
    f32 cosYaw, sinYaw, sinPitch, cosPitch;
    f32 radius;
    f32 rx, ry, rz, rs;
    u8 mxin[24];
    f32 matrix[12];

    Player_GetAimAngles((int)target, &tgtYaw, &tgtPitch);
    curve = (u8*)fn_802972A8((int)target);
    if (curve != NULL)
    {
        if (*(s16*)(curve + 70) == 1049)
        {
            *(f32*)(mxin + 12) = *(f32*)(curve + 24);
            *(f32*)(mxin + 16) = *(f32*)(curve + 28);
            *(f32*)(mxin + 20) = *(f32*)(curve + 32);
            *(s16*)(mxin + 0) = *(s16*)(curve + 0);
            *(s16*)(mxin + 2) = *(s16*)(curve + 2);
            *(s16*)(mxin + 4) = *(s16*)(curve + 4);
            *(f32*)(mxin + 8) = lbl_803E1B20;
            setMatrixFromObjectPos(matrix, mxin);
            Matrix_TransformPoint(matrix, lbl_803E1B24, lbl_803E1B28, lbl_803E1B2C,
                                  &baseX, &baseY, &baseZ);
        }
        else
        {
            baseX = target->anim.worldPosX;
            baseY = target->anim.worldPosY + lbl_803DB9D0;
            baseZ = target->anim.worldPosZ;
        }
    }
    else
    {
        baseX = target->anim.worldPosX;
        baseY = target->anim.worldPosY + lbl_803DB9D0;
        baseZ = target->anim.worldPosZ;
    }

    tgtYaw = (s16)((0x8000 - target->anim.rotX) + tgtYaw);
    tgtYaw = (s16)(tgtYaw - (u16)camera->anim.rotX);
    if (tgtYaw > 0x8000)
    {
        tgtYaw -= 0xffff;
    }
    if (tgtYaw < -0x8000)
    {
        tgtYaw += 0xffff;
    }
    camera->anim.rotX = camera->anim.rotX + tgtYaw;

    tgtPitch = (s16)(tgtPitch - (u16)camera->anim.rotY);
    if (tgtPitch > 0x8000)
    {
        tgtPitch -= 0xffff;
    }
    if (tgtPitch < -0x8000)
    {
        tgtPitch += 0xffff;
    }
    camera->anim.rotY = camera->anim.rotY + tgtPitch;

    camera->anim.rotZ = (s16)(target->anim.rotZ * lbl_803DB9D4);

    cosYaw = mathSinf(lbl_803E1B30 * (f32)(s32)(camera->anim.rotX - 0x4000) / lbl_803E1B34);
    sinYaw = mathCosf(lbl_803E1B30 * (f32)(s32)(camera->anim.rotX - 0x4000) / lbl_803E1B34);
    sinPitch = mathCosf(lbl_803E1B30 * (f32)(s32)camera->anim.rotY / lbl_803E1B34);
    cosPitch = mathSinf(lbl_803E1B30 * (f32)(s32)camera->anim.rotY / lbl_803E1B34);
    radius = lbl_803DD5B8->radius;
    ry = radius * cosPitch;
    rs = radius * sinPitch;
    rx = rs * sinYaw;
    rz = rs * cosYaw;
    camera->anim.worldPosX = baseX + rx;
    camera->anim.worldPosY = baseY + ry;
    camera->anim.worldPosZ = baseZ + rz;
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}

void CameraModeForceBehind_update(u8* obj);

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
