/* DLL 0x0051 — camera mode: cannon [8010DB7C-8010DD58) */
#include "main/dll/CAM/camnpcspeak_state.h"
#include "main/game_object.h"
#include "main/mm.h"

extern f32 mathSinf(f32 x);
extern float mathCosf(float x);

#include "ghidra_import.h"
#include "main/dll/baddieControl.h"
#include "main/camera_object.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/camera_mode_54_state.h"
#include "main/dll/CAM/camera_mode_4f_state.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/dll/CAM/camcrawl_state.h"
#include "main/dll/CAM/camera_mode_cannon_state.h"
#include "main/dll/CAM/camnpcspeak_state.h"
#include "main/dll/CAM/camperv_state.h"
#include "main/dll/CAM/camworldmap_state.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/mapEvent.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/screen_transition.h"

#include "main/dll/dll19_state.h"
#include "main/objanim.h"
#include "main/dll/baddie_state.h"

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
extern CameraModeCannonState* lbl_803DD5A0;
extern CameraModeCloudRunnerState* lbl_803DD5B8;
extern s16* objModelGetVecFn_800395d8(int obj, int idx);
extern f32 lbl_803E1AE0;
extern f32 lbl_803E1AE4;
extern f32 lbl_803E1AE8;
extern f32 lbl_803E1AEC;
extern f32 lbl_803E1AF0;
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
void CameraModeCannon_copyToCurrent_nop(void)
{
}

void CameraModeCannon_release(void)
{
}

void CameraModeCannon_initialise(void)
{
}

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

void CameraModeCannon_init(int* p1, int unused, int* p3)
{
    CameraObject* camera = (CameraObject*)p1;

    if (lbl_803DD5A0 == NULL)
    {
        lbl_803DD5A0 = (CameraModeCannonState*)mmAlloc(sizeof(CameraModeCannonState), 15, 0);
    }
    if (p3 != NULL)
    {
        lbl_803DD5A0->target = (GameObject*)*p3;
    }
    else
    {
        lbl_803DD5A0->target = NULL;
    }
    camera->anim.rotY = 2800;
}

#pragma opt_common_subs off
#pragma opt_common_subs reset

void CameraModeCannon_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5A0);
    lbl_803DD5A0 = NULL;
}

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void CameraModeCloudRunner_free(void);

#pragma dont_inline on
#pragma dont_inline reset

void CameraModeCannon_update(u8* obj)
{
    CameraObject* camera = (CameraObject*)obj;
    s16* vec;
    s16 yaw;
    s16 delta;

    vec = objModelGetVecFn_800395d8((int)lbl_803DD5A0->target, 0);
    if (lbl_803DD5A0->target == NULL)
    {
        return;
    }
    yaw = camera->anim.rotX;
    delta = (s16)((0x8000 - lbl_803DD5A0->target->anim.rotX) - vec[1] - yaw);
    camera->anim.rotX = (s16)(s32)((f32)(s32)yaw + (f32)(s32)delta / lbl_803E1AE0);
    camera->anim.localPosX =
        lbl_803DD5A0->target->anim.worldPosX -
        lbl_803E1AE4 * mathSinf(lbl_803E1AE8 * (f32)(s32)(-camera->anim.rotX) / lbl_803E1AEC);
    camera->anim.localPosY = lbl_803E1AF0 + lbl_803DD5A0->target->anim.worldPosY;
    camera->anim.localPosZ =
        lbl_803DD5A0->target->anim.worldPosZ -
        lbl_803E1AE4 * mathCosf(lbl_803E1AE8 * (f32)(s32)(-camera->anim.rotX) / lbl_803E1AEC);
}

/* dll_19_func14  addr=0x80112E94  size=0x2A8  linkage=global */

/* dll_19_func16  addr=0x801126E0  size=0x348  linkage=global */

/* dll_19_func15  addr=0x80112A28  size=0x358  linkage=global */

/* dll_19_func18  addr=0x80112098  size=0x47C  linkage=global */

/* CameraModeCrawl_update  addr=0x8010F74C  size=0x2B8  linkage=global */

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
