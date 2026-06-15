/* DLL 0x54 - CameraModeNpcSpeak [8010DB7C-8010DD58) */
#include "main/mm.h"

extern s16 getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);

#include "main/camera_object.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/camera_mode_54_state.h"
#include "main/dll/CAM/camcloudrunner_state.h"


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
extern void* memset(void* dst, int val, u32 n);
extern f32 timeDelta;
extern CameraMode54State* lbl_803DD5C0;
extern f32 lbl_803E1B5C;
extern CameraModeCloudRunnerState* lbl_803DD5B8;
extern int Obj_GetPlayerObject(void);
extern int ObjList_GetObjects(int* idx, int* count);
extern f32 lbl_803E1B40;
extern f32 lbl_803E1B44;
extern f32 lbl_803E1B48;
extern f32 lbl_803E1B4C;
extern f32 lbl_803E1B50;
extern f32 lbl_803E1B54;
extern f32 lbl_803E1B58;
extern f32 lbl_803E1B60;
extern f32 lbl_803E1B64;
extern f32 lbl_803E1B68;
extern s16 getAngle(f32 x, f32 z);

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

void CameraModeCloudRunner_release(void);

void dll_54_func06_nop(void)
{
}

void dll_54_release_nop(void)
{
}

void dll_54_initialise_nop(void)
{
}

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

void dll_54_init(int* p1, int unused, int* p3)
{
    CameraObject* camera = (CameraObject*)p1;
    CameraObject* source = (CameraObject*)p3;

    if (lbl_803DD5C0 == NULL)
    {
        lbl_803DD5C0 = (CameraMode54State*)mmAlloc(sizeof(CameraMode54State), 15, 0);
    }
    memset(lbl_803DD5C0, 0, sizeof(CameraMode54State));
    lbl_803DD5C0->transitionTimer = lbl_803E1B5C;
    lbl_803DD5C0->transitionDone = 0;
    if (p3 != NULL)
    {
        camera->anim.localPosX = source->anim.worldPosX;
        camera->anim.localPosY = source->anim.worldPosY;
        camera->anim.localPosZ = source->anim.worldPosZ;
        camera->anim.rotX = source->anim.rotX;
        camera->anim.rotY = source->anim.rotY;
        camera->anim.rotZ = source->anim.rotZ;
        camera->fov = source->fov;
    }
    lbl_803DD5C0->startX = camera->anim.worldPosX;
    lbl_803DD5C0->startY = camera->anim.worldPosY;
    lbl_803DD5C0->startZ = camera->anim.worldPosZ;
    lbl_803DD5C0->startYaw = camera->anim.rotX;
    lbl_803DD5C0->startPitch = camera->anim.rotY;
    lbl_803DD5C0->startRoll = camera->anim.rotZ;
}

int dll_19_func1B(int p);

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void CameraModeCloudRunner_free(void);

void dll_54_func05(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5C0);
    lbl_803DD5C0 = NULL;
}

void CameraModePerv_free(void);

#pragma dont_inline on
#pragma dont_inline reset

void dll_54_update(u8* obj)
{
    extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int mtx); /* #57 */
    CameraObject* camera = (CameraObject*)obj;
    int i;
    int count;
    f32 zz, xx;
    f32 dx, dy, dz;
    f32 dist;
    f32 nx, nz;
    f32 fx, fz;
    f32 d2, h, t;
    f32 t2;
    f32 lim;
    s16 cur;
    s16 d;

    if (lbl_803DD5C0->exitRequested != 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
    }
    else
    {
        if (lbl_803DD5C0->lookAtObj == NULL)
        {
            int* arr = (int*)ObjList_GetObjects(&i, &count);
            for (; i < count; i++)
            {
                GameObject* o = (GameObject*)arr[i];
                if (o->anim.seqId == 0x2ab)
                {
                    lbl_803DD5C0->lookAtObj = o;
                }
                else if (o->anim.seqId == 0x4dc)
                {
                    lbl_803DD5C0->originObj = o;
                }
            }
        }
        if (lbl_803DD5C0->playerObj == NULL)
        {
            lbl_803DD5C0->playerObj = (GameObject*)Obj_GetPlayerObject();
        }
        {
            GameObject* a = lbl_803DD5C0->lookAtObj;
            dx = a->anim.worldPosX - lbl_803DD5C0->originObj->anim.worldPosX;
            dy = a->anim.worldPosY - lbl_803DD5C0->originObj->anim.worldPosY;
            dz = a->anim.worldPosZ - lbl_803DD5C0->originObj->anim.worldPosZ;
        }
        zz = dz * dz;
        xx = dx * dx;
        dist = sqrtf(zz + (dy * dy + xx));
        nx = dx / dist;
        nz = dz / dist;
        fx = -(lbl_803E1B40 * nx - lbl_803DD5C0->originObj->anim.worldPosX) -
            lbl_803DD5C0->playerObj->anim.worldPosX;
        fz = -(lbl_803E1B40 * nz - lbl_803DD5C0->originObj->anim.worldPosZ) -
            lbl_803DD5C0->playerObj->anim.worldPosZ;
        d2 = sqrtf(fx * fx + fz * fz);
        t = (lbl_803E1B44 - d2) / lbl_803E1B44;
        camera->fov = lbl_803E1B4C * t + lbl_803E1B48;
        h = lbl_803E1B54 * t + lbl_803E1B50;
        camera->anim.worldPosX = -(nx * h - lbl_803DD5C0->originObj->anim.worldPosX);
        camera->anim.worldPosY =
            lbl_803E1B5C * t + (lbl_803E1B58 + lbl_803DD5C0->originObj->anim.worldPosY);
        camera->anim.worldPosZ = -(nz * h - lbl_803DD5C0->originObj->anim.worldPosZ);
        camera->anim.rotX = -getAngle(dx, dz);
        camera->anim.rotY =
            -getAngle(-(lbl_803E1B60 * (dist / lbl_803E1B64) - dy), sqrtf(xx + zz));

        if (lbl_803DD5C0->transitionDone == 0)
        {
            t2 = lbl_803DD5C0->transitionTimer / lbl_803E1B5C;
            camera->anim.worldPosX =
                t2 * (lbl_803DD5C0->startX - camera->anim.worldPosX) + camera->anim.worldPosX;
            camera->anim.worldPosY =
                t2 * (lbl_803DD5C0->startY - camera->anim.worldPosY) + camera->anim.worldPosY;
            camera->anim.worldPosZ =
                t2 * (lbl_803DD5C0->startZ - camera->anim.worldPosZ) + camera->anim.worldPosZ;

            cur = camera->anim.rotX;
            d = (s16)(lbl_803DD5C0->startYaw - (u16)cur);
            if (d > 0x8000)
            {
                d = (s16)(d - 0xffff);
            }
            if (d < -0x8000)
            {
                d += 0xffff;
            }
            camera->anim.rotX = (f32)d * t2 + (f32)cur;

            cur = camera->anim.rotY;
            d = (s16)(lbl_803DD5C0->startPitch - (u16)cur);
            d = (d > 0x8000) ? (s16)(d - 0xffff) : d;
            d = (d < -0x8000) ? (s16)(d + 0xffff) : d;
            camera->anim.rotY = (f32)d * t2 + (f32)cur;

            lbl_803DD5C0->transitionTimer -= timeDelta;
            if (lbl_803DD5C0->transitionTimer < (lim = *(f32*)&lbl_803E1B68))
            {
                lbl_803DD5C0->transitionDone = 1;
                lbl_803DD5C0->transitionTimer = lim;
            }
        }
        Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                       &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                       *(int*)&camera->anim.parent);
    }
}

/* CameraModeNpcSpeak_init  addr=0x8010DFF0  size=0x524  linkage=global */

/* CameraModeTitle_update  addr=0x801116E0  size=0x58C  linkage=global */

/* CameraModeArwing_update  addr=0x80110EC4  size=0x5FC  linkage=global */

/* CameraModeWorldMap_update  addr=0x8010E5B4  size=0xC8C  linkage=global */

/* CameraModeNpcSpeak_update  addr=0x8010DD58  size=0x298  linkage=global */

/* segment pragma-stack balance (re-split): */

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
