/* DLL 0x004F — Camera mode misc handler [0x8010F2F8-0x8010F540). */
#include "main/mm.h"

extern float mathSinf(float x);
extern float mathCosf(float x);

#include "main/camera_object.h"
#include "main/dll/CAM/camera_mode_4f_state.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"










extern u32 FUN_80294964();

extern u32 DAT_802c2910;
extern u32 DAT_802c2914;
extern u32 DAT_802c2918;
extern float* DAT_803de1fc;
extern f32 lbl_803E2658;
extern f32 lbl_803E265C;

#pragma scheduling on
#pragma peephole on
extern f32 lbl_803E1A88;
extern CameraMode4FState* lbl_803DD590;
extern f32 Curve_EvalHermite(f32* pts, f32 t, int mode);
extern f32 timeDelta;
extern f32 lbl_803E1A8C;
extern f32 lbl_803E1A90;
extern f32 lbl_803E1A94;
extern f32 lbl_803E1A98;
extern const f32 lbl_803E1A9C;
extern const f32 lbl_803E1AA0;
extern const f32 lbl_803E1AA4;
extern f32 lbl_803E1AA8;
extern f32 lbl_803E1AAC;
extern f32 lbl_803E1AB0;
extern f32 lbl_803E1AB4;
extern CameraModeCloudRunnerState* lbl_803DD5B8;

void FUN_8010de18_v11_drift(u32 param_1, u32 param_2, float* param_3, float* param_4)
{
    float fVar1;
    float* pfVar2;
    int iVar3;
    double dVar4;
    double dVar5;
    double dVar6;
    double dVar7;
    double dVar8;
    u64 uVar9;

    uVar9 = FUN_8028683c();
    pfVar2 = DAT_803de1fc;
    iVar3 = (int)((u64)uVar9 >> 0x20);
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

void FUN_801115e0(u64 param_1, double param_2, double param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  int param_9, int param_10)
{
    u32 uVar1;
    u16* puVar2;
    u32 uVar3;
    u32 in_r8;
    u32 in_r9;
    u32 in_r10;
    u16 uStack_1a;
    u32 local_18;
    u32 local_14;
    u16 local_10;

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
            *(u32*)&((GameObject*)param_9)->childObjs[0] = 0;
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
                                     4, 0xff, 0xffffffff, *(u32**)&((GameObject*)param_9)->anim.parent, in_r8, in_r9,
                                     in_r10);
                *(u32*)&((GameObject*)param_9)->childObjs[0] = uVar3;
                *(u16*)(*(int*)&((GameObject*)param_9)->childObjs[0] + 0xb0) = ((GameObject*)param_9)->objectFlags &
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
void dll_4F_func06_nop(void)
{
}

void dll_4F_release_nop(void)
{
}

void dll_4F_initialise_nop(void)
{
}

void CameraModeCrawl_release(void);

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

void dll_4F_init(void)
{
    if (lbl_803DD590 == NULL)
    {
        lbl_803DD590 = (CameraMode4FState*)mmAlloc(sizeof(CameraMode4FState), 15, 0);
    }
    lbl_803DD590->blendProgress = lbl_803E1A88;
}

void dll_4F_update(int* obj)
{
    CameraObject* camera;
    GameObject* target;
    f32 pts[4];
    f32 fz;
    f32 sn;
    f32 cs;
    s16 a;

    camera = (CameraObject*)obj;
    pts[0] = lbl_803E1A88;
    pts[1] = lbl_803E1A8C;
    pts[2] = lbl_803E1A88;
    pts[3] = lbl_803E1A88;
    fz = Curve_EvalHermite(pts, lbl_803DD590->blendProgress, 0);
    target = (GameObject*)camera->anim.targetObj;
    a = (s16)(0x8000 - target->anim.rotX);
    a = (s16)(a + (s32)(lbl_803E1A90 * fz));
    {
        f32 t = (lbl_803E1A94 * (f32)(s32)
        a
        )
        /
        lbl_803E1A98;
        sn = mathCosf(t);
        cs = mathSinf(t);
    }
    camera->anim.localPosX = target->anim.worldPosX + (lbl_803E1A9C * sn - lbl_803E1AA0 * cs);
    camera->anim.localPosZ = target->anim.worldPosZ + (lbl_803E1A9C * cs + lbl_803E1AA0 * sn);
    camera->anim.localPosY = (lbl_803E1AA4 + target->anim.worldPosY) - lbl_803E1AA8 * fz;
    camera->anim.rotY = (s16)(0x11c6 - (s32)(lbl_803E1AA4 * (lbl_803E1AAC * fz)));
    camera->anim.rotX = (s16)(a + 0x1ffe);
    camera->anim.rotZ = 0;
    camera->letterboxTargetOffset = 0;
    camera->fov = lbl_803E1AB0;
    lbl_803DD590->blendProgress = lbl_803E1AB4 * timeDelta + lbl_803DD590->blendProgress;
    if (lbl_803DD590->blendProgress > *(f32*)&lbl_803E1A8C)
    {
        lbl_803DD590->blendProgress = lbl_803E1A8C;
    }
}

void CameraModeCrawl_init(void);

#pragma opt_common_subs off
#pragma opt_common_subs reset

void dll_4F_func05(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD590);
    lbl_803DD590 = NULL;
}

void CameraModeCrawl_free(void);

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void CameraModeCloudRunner_free(void);

#pragma dont_inline on
#pragma dont_inline reset

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
