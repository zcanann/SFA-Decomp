#include "main/mm.h"
#include "main/dll/CAM/cutCam.h"

extern s16 getAngle(f32 dx, f32 dz);
extern f32 mathSinf(f32 x);
extern float mathCosf(float x);

#include "main/camera_interface.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/dll/CAM/camcrawl_state.h"


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
extern CameraModeCrawlState* lbl_803DD598;
extern f32 mathCosf(f32);
extern f32 mathSinf(f32);
extern f32 timeDelta;
extern CameraModeCloudRunnerState* lbl_803DD5B8;
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern f32 lbl_803E1AC0;
extern f32 lbl_803E1AC4;
extern f32 lbl_803E1AD0;
extern f32 lbl_803E1AD4;
extern f32 lbl_803E1AD8;
extern f32 lbl_803E1ADC;
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
void CameraModeCrawl_release(void)
{
}

void CameraModeCrawl_initialise(void)
{
}

void CameraModeCannon_copyToCurrent_nop(void);

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

void CameraModeCrawl_init(void)
{
    if (lbl_803DD598 == NULL)
    {
        lbl_803DD598 = (CameraModeCrawlState*)mmAlloc(sizeof(CameraModeCrawlState), 15, 0);
        memset(lbl_803DD598, 0, sizeof(CameraModeCrawlState));
    }
}

#pragma opt_common_subs off
#pragma opt_common_subs reset

void CameraModeCrawl_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD598);
    lbl_803DD598 = NULL;
}

void CameraModeCannon_free(void);

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void CameraModeCloudRunner_free(void);

#pragma dont_inline on
#pragma dont_inline reset

void CameraModeCrawl_copyToCurrent(void* param1, int param2)
{
    extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int mtx); /* #57 */
    int obj;
    GameObject* target;
    int yaw;
    f32 c, s;
    f32 pos[3];
    int one;

    if (param1 == NULL)
    {
        return;
    }
    obj = (int)(*gCameraInterface)->getCamera();
    target = (GameObject*)((CameraObject*)obj)->anim.targetObj;
    yaw = target->anim.rotX;

    if (param2 == 0)
    {
        c = mathSinf(lbl_803E1AC0 * (f32)(s32)target->anim.rotX / lbl_803E1AC4);
        s = mathCosf(lbl_803E1AC0 * (f32)(s32)target->anim.rotX / lbl_803E1AC4);
    }
    else
    {
        c = -mathSinf(lbl_803E1AC0 * (f32)(s32)target->anim.rotX / lbl_803E1AC4);
        s = -mathCosf(lbl_803E1AC0 * (f32)(s32)target->anim.rotX / lbl_803E1AC4);
    }
    {
        extern int getAngle(f32 dx, f32 dz);
        target->anim.rotX = (s16)getAngle(c, s);
    }
    camcontrol_getTargetPosition((CameraObject*)obj, &target->anim, pos, NULL);
    target->anim.rotX = (s16)yaw;
    {
        f32 p;
        p = pos[0];
        ((CameraObject*)obj)->anim.worldPosX = p;
        ((CameraObject*)obj)->probePosX = p;
        p = pos[1];
        ((CameraObject*)obj)->anim.worldPosY = p;
        ((CameraObject*)obj)->probePosY = p;
        p = pos[2];
        ((CameraObject*)obj)->anim.worldPosZ = p;
        ((CameraObject*)obj)->probePosZ = p;
    }
    Obj_TransformWorldPointToLocal(((CameraObject*)obj)->anim.worldPosX, ((CameraObject*)obj)->anim.worldPosY,
                                   ((CameraObject*)obj)->anim.worldPosZ,
                                   &((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.localPosY,
                                   &((GameObject*)obj)->anim.localPosZ,
                                   *(int*)&((CameraObject*)obj)->anim.parent);
    one = 1;
    lbl_803DD598->flags.useDefaultHandler = one;
}

int dll_19_func17(int p1, u8* p2, u8* p3, s16 p4, u8* p5, s16 p6, s16 p7, s16 p8);

void CameraModeCrawl_update(u8* obj)
{
    extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int mtx); /* #57 */
    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    int delta;
    f32 v20, v16, v12, v8;
    int other;

    if (target == NULL)
    {
        return;
    }
    if (lbl_803DD598->flags.useDefaultHandler == 0)
    {
        camera->anim.worldPosX =
            lbl_803E1AD0 * mathSinf(lbl_803E1AC0 * (f32)(s32)target->anim.rotX / lbl_803E1AC4) +
            target->anim.worldPosX;
        camera->anim.worldPosZ =
            lbl_803E1AD0 * mathCosf(lbl_803E1AC0 * (f32)(s32)target->anim.rotX / lbl_803E1AC4) +
            target->anim.worldPosZ;
        camera->anim.worldPosY = lbl_803E1AD4 + target->anim.worldPosY;
        v20 = camera->anim.localPosX - target->anim.worldPosX;
        v12 = camera->anim.localPosZ - target->anim.worldPosZ;
        delta = (0x8000 - (u16)getAngle(v20, v12)) - (u16)camera->anim.rotX;
        delta = (delta > 0x8000) ? delta - 0xffff : delta;
        delta = (delta < -0x8000) ? delta + 0xffff : delta;
        camera->anim.rotX = (s32)((f32)(s32)camera->anim.rotX +
                                  interpolate((f32)(s32)delta, lbl_803E1AD8, timeDelta));
        camera->anim.rotX = (s16)(0x8000 - getAngle(v20, v12));
        camera->anim.rotY = 2048;
    }
    else
    {
        other = (int)(*gCameraInterface)->getDefaultHandlerEntry();
        (*(void (**)(u8*, f32*, f32*, f32*, f32*, f32, int))(*(int*)gCameraInterface + 56))(
            obj, &v20, &v16, &v12, &v8, lbl_803E1ADC, 0);
        delta = (0x8000 - (u16)getAngle(v20, v12)) - (u16)camera->anim.rotX;
        delta = (delta > 0x8000) ? delta - 0xffff : delta;
        delta = (delta < -0x8000) ? delta + 0xffff : delta;
        camera->anim.rotX = (s16)(camera->anim.rotX + delta);
        (*(void (**)(u8*, f32, f32))(*(int*)(*(int*)(other + 4)) + 24))(
            obj, target->anim.worldPosY, v8);
    }
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}

/* CameraModeCloudRunner_update  addr=0x80110214  size=0x36C  linkage=global */

/* CameraModeForceBehind_update  addr=0x8010FC7C  size=0x43C  linkage=global */

/* dll_54_update  addr=0x801106E4  size=0x490  linkage=global */

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
