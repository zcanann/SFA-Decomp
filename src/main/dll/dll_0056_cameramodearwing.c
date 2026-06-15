/* DLL 0x56 — camera mode arwing [8010DB7C-8010DD58) */
#include "main/dll/CAM/camnpcspeak_state.h"
#include "main/game_object.h"
#include "main/mm.h"

extern s16 getAngle(f32 dx, f32 dz);

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

typedef struct CameraArwingWork
{
    f32 unk0;
    f32 unk4;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    f32 unk14;
    u8 pad18[0x24 - 0x18];
    f32 xScale;
    f32 yScale;
    f32 unk2C;
    u8 pad30[0x38 - 0x30];
    f32 unk38;
    f32 unk3C;
    f32 unk40;
    f32 yawScale;
    f32 pitchScale;
    f32 rollScale;
    f32 rollRate;
    s16 inputYaw;
    s16 inputPitch;
    s16 inputRoll;
    u8 unk5A;
    u8 unk5B;
    u8 pad5C[0x5E - 0x5C];
    u8 unk5E;
    u8 pad5F[0x60 - 0x5F];
} CameraArwingWork;

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
extern f32 timeDelta;
extern f32 lbl_803A43C0[];
extern void PSVECAdd(f32 * a, f32 * b, f32 * out);
extern f32 lbl_803E1BA4;
extern f32 lbl_803E1BC0;
extern f32 lbl_803E1BC4;
extern f32 lbl_803E1BC8;
extern f32 lbl_803E1BCC;
extern f32 lbl_803E1BD0;
extern f32 lbl_803E1BD4;
extern f32 lbl_803E1BD8;
extern f32 lbl_803E1BDC;
extern CameraModeCloudRunnerState* lbl_803DD5B8;
extern int arwarwing_isDead(int state);
extern int arwarwing_isExplodingOrWarping(int state);
extern f32 lbl_803E1BA0;
extern f32 lbl_803E1BA8;
extern f32 lbl_803E1BAC;
extern f32 lbl_803E1BB0;
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

void fn_80110C80(void)
{
}

void CameraModePerv_release(void);

void fn_80110EC0(void)
{
}

void CameraModeArwing_release(void)
{
}

void CameraModeArwing_initialise(void)
{
}

void CameraModeTitle_release(void);

void CameraModeArwing_free(void)
{
}

void CameraModeArwing_copyToCurrent(void* p1, u32 kind)
{
    if (kind == 12)
    {
        lbl_803A43C0[0] = ((f32*)p1)[0];
        lbl_803A43C0[1] = ((f32*)p1)[1];
        lbl_803A43C0[2] = ((f32*)p1)[2];
        return;
    }
    if (kind == 6)
    {
        ((CameraArwingWork*)lbl_803A43C0)->inputYaw = ((s16*)p1)[0];
        ((CameraArwingWork*)lbl_803A43C0)->inputPitch = ((s16*)p1)[1];
        ((CameraArwingWork*)lbl_803A43C0)->inputRoll = ((s16*)p1)[2];
        return;
    }
    if (kind == 4)
    {
        ((CameraArwingWork*)lbl_803A43C0)->unk38 = ((f32*)p1)[0];
        return;
    }
    ((CameraArwingWork*)lbl_803A43C0)->unk3C = ((f32*)p1)[0];
    ((CameraArwingWork*)lbl_803A43C0)->unk40 = ((f32*)p1)[1];
}

#pragma opt_common_subs off
void CameraModeArwing_init(int* obj, int mode, int unused)
{
    int* a4 = ((int**)obj)[0xA4 / 4];
    char* base;
    f32* p;
    f32 fc;
    f32 fc2;
    if (mode != 1)
    {
        ((CameraArwingWork*)lbl_803A43C0)->unkC = *(f32*)((char*)a4 + 0x18);
        ((CameraArwingWork*)lbl_803A43C0)->unk10 = *(f32*)((char*)a4 + 0x1C);
        ((CameraArwingWork*)lbl_803A43C0)->unk14 = *(f32*)((char*)a4 + 0x20);
    }
    base = (char*)lbl_803A43C0;
    p = (f32*)(base + 48);
    *p = lbl_803E1BA4;
    *(f32*)(base + 52) = lbl_803E1BC0;
    *(f32*)(base + 56) = lbl_803E1BC4;
    PSVECAdd(&((GameObject*)a4)->anim.worldPosX, p, &((GameObject*)obj)->anim.worldPosX);
    ((CameraArwingWork*)lbl_803A43C0)->unk5E = 1;
    ((CameraArwingWork*)lbl_803A43C0)->yawScale = lbl_803E1BC8;
    ((CameraArwingWork*)lbl_803A43C0)->pitchScale = lbl_803E1BCC;
    ((CameraArwingWork*)lbl_803A43C0)->rollScale = lbl_803E1BD0;
    ((CameraArwingWork*)lbl_803A43C0)->xScale = lbl_803E1BD4;
    ((CameraArwingWork*)lbl_803A43C0)->yScale = lbl_803E1BD8;
    fc = lbl_803E1BA4;
    ((CameraArwingWork*)lbl_803A43C0)->unk2C = fc;
    fc2 = lbl_803E1BDC;
    ((CameraArwingWork*)lbl_803A43C0)->unk40 = fc2;
    ((CameraArwingWork*)lbl_803A43C0)->unk3C = fc2;
    ((CameraArwingWork*)lbl_803A43C0)->unk5B = 90;
    ((CameraArwingWork*)lbl_803A43C0)->unk5A = 100;
    ((CameraArwingWork*)lbl_803A43C0)->unk8 = fc;
    ((CameraArwingWork*)lbl_803A43C0)->unk4 = fc;
    ((CameraArwingWork*)lbl_803A43C0)->unk0 = fc;
    ((GameObject*)obj)->anim.worldPosX = *(f32*)((char*)a4 + 0x18);
    ((GameObject*)obj)->anim.worldPosY = *(f32*)((char*)a4 + 0x1C);
    ((GameObject*)obj)->anim.worldPosZ = *(f32*)((char*)a4 + 0x20) + *(f32*)(base + 56);
}
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

void CameraModeArwing_update(u8* obj)
{
    extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int mtx); /* #57 */
    u8* state = *(u8**)&((GameObject*)obj)->anim.targetObj;
    int yaw0, pitch0;
    int d;

    ((GameObject*)obj)->anim.worldPosX = lbl_803A43C0[0] * ((CameraArwingWork*)lbl_803A43C0)->xScale;
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.worldPosX + ((CameraArwingWork*)lbl_803A43C0)->unkC;
    ((GameObject*)obj)->anim.worldPosY = lbl_803A43C0[1] * ((CameraArwingWork*)lbl_803A43C0)->yScale;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.worldPosY + ((CameraArwingWork*)lbl_803A43C0)->unk10;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)state)->anim.worldPosZ + ((CameraArwingWork*)lbl_803A43C0)->
        unk38;

    if ((s8)state[0xac] != 0x26)
    {
        f32 t = ((CameraArwingWork*)lbl_803A43C0)->unk40 / ((CameraArwingWork*)lbl_803A43C0)->unk3C -
            lbl_803E1BA0;
        if (t < lbl_803E1BA4)
        {
            ((GameObject*)obj)->anim.worldPosZ =
                (f32) - (s32)((CameraArwingWork*)lbl_803A43C0)->unk5A * t + ((GameObject*)obj)->anim.worldPosZ;
        }
        else
        {
            ((GameObject*)obj)->anim.worldPosZ =
                (f32) - (s32)((CameraArwingWork*)lbl_803A43C0)->unk5B * t + ((GameObject*)obj)->anim.worldPosZ;
        }
    }

    yaw0 = (s32)((f32)((CameraArwingWork*)lbl_803A43C0)->inputYaw *
        ((CameraArwingWork*)lbl_803A43C0)->yawScale);
    pitch0 = (s32)((f32)((CameraArwingWork*)lbl_803A43C0)->inputPitch *
        ((CameraArwingWork*)lbl_803A43C0)->pitchScale);

    if (arwarwing_isDead((int)state) != 0)
    {
        f32 vd, vc, vb, va;
        int step;
        ((CameraArwingWork*)lbl_803A43C0)->rollRate = lbl_803E1BA8;
        (*(void (**)(u8*, f32*, f32*, f32*, f32*, f32, int))(*(int*)gCameraInterface + 56))(
            obj, &va, &vb, &vc, &vd, lbl_803E1BA4, 0);
        ((GameObject*)obj)->anim.rotZ = ((CameraArwingWork*)lbl_803A43C0)->rollRate * timeDelta +
            (f32)((GameObject*)obj)->anim.rotZ;
        d = 0x8000 - (u16)getAngle(va, vc);
        pitch0 = (u16)getAngle(vb, vd);
        d -= (u16) * (s16*)obj;
        if (d > 0x8000)
        {
            d -= 0xffff;
        }
        if (d < -0x8000)
        {
            d += 0xffff;
        }
        step = (s32)((f32)d * timeDelta);
        *(s16*)obj = (f32)step * lbl_803E1BAC + (f32) * (s16*)obj;
        d = pitch0 - (u16)((GameObject*)obj)->anim.rotY;
        if (d > 0x8000)
        {
            d -= 0xffff;
        }
        if (d < -0x8000)
        {
            d += 0xffff;
        }
        step = (s32)((f32)d * timeDelta);
        ((GameObject*)obj)->anim.rotY = (f32)step * lbl_803E1BAC + (f32)((GameObject*)obj)->anim.rotY;
    }
    else if (arwarwing_isExplodingOrWarping((int)state) != 0)
    {
        f32 nv = ((CameraArwingWork*)lbl_803A43C0)->rollRate * lbl_803E1BB0;
        ((CameraArwingWork*)lbl_803A43C0)->rollRate = nv;
        ((GameObject*)obj)->anim.rotZ = nv * timeDelta + (f32)((GameObject*)obj)->anim.rotZ;
    }
    else
    {
        int roll0 = (s32)((f32)((CameraArwingWork*)lbl_803A43C0)->inputRoll *
            ((CameraArwingWork*)lbl_803A43C0)->rollScale);
        d = roll0 - (u16)((GameObject*)obj)->anim.rotZ;
        if (d > 0x8000)
        {
            d -= 0xffff;
        }
        if (d < -0x8000)
        {
            d += 0xffff;
        }
        ((GameObject*)obj)->anim.rotZ = (f32)d * timeDelta * lbl_803E1BAC + (f32)((GameObject*)obj)->anim.rotZ;
        d = yaw0 - (u16) * (s16*)obj;
        if (d > 0x8000)
        {
            d -= 0xffff;
        }
        if (d < -0x8000)
        {
            d += 0xffff;
        }
        *(s16*)obj = (f32)d * timeDelta * lbl_803E1BAC + (f32) * (s16*)obj;
        d = pitch0 - (u16)((GameObject*)obj)->anim.rotY;
        if (d > 0x8000)
        {
            d -= 0xffff;
        }
        if (d < -0x8000)
        {
            d += 0xffff;
        }
        ((GameObject*)obj)->anim.rotY = (f32)d * timeDelta * lbl_803E1BAC + (f32)((GameObject*)obj)->anim.rotY;
    }
    Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                                   ((GameObject*)obj)->anim.worldPosZ,
                                   &((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.localPosY,
                                   &((GameObject*)obj)->anim.localPosZ,
                                   *(int*)&((GameObject*)obj)->anim.parent);
}

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
