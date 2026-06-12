/* === moved from main/dll/CAM/camDebug.c [8010DB7C-8010DD58) (TU re-split, docs/boundary_audit.md) === */
#include "ghidra_import.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camclimb_state.h"
#include "main/dll/CAM/camnpcspeak_state.h"
#include "main/game_object.h"
#include "main/mm.h"
#include "main/object_transform.h"

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

void CameraModeNpcSpeak_copyToCurrent_nop(void)
{
}

void CameraModeNpcSpeak_free(void)
{
    mm_free(lbl_803DD584);
    lbl_803DD584 = 0;
    Rcp_DisableBlurFilter();
}

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
#include "main/objanim.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/mapEvent.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/screen_transition.h"

#include "main/dll/dll19_state.h"


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


typedef struct Dll19Placement
{
    u8 pad0[0x22 - 0x0];
    s16 unk22;
    u8 pad24[0x32 - 0x24];
    u8 unk32;
    u8 pad33[0x3E8 - 0x33];
    f32 unk3E8;
    f32 unk3EC;
    u8 pad3F0[0x400 - 0x3F0];
    u16 unk400;
    u8 pad402[0x408 - 0x402];
} Dll19Placement;


extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_80017730();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern uint Obj_GetYawDeltaToObject();
extern u8* getSaveFileStruct();
extern int camcontrol_traceMove(void* a, void* b, void* c, void* d, int e, int f, int g, f32 h);
extern undefined4 camcontrol_traceFromTarget();
extern undefined4 camcontrol_getTargetPosition();
extern void Movie_SetVolumeFade();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_802c2910;
extern undefined4 DAT_802c2914;
extern undefined4 DAT_802c2918;
extern ScreenTransitionInterface** gScreenTransitionInterface;
extern void** gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy
extern float* DAT_803de1fc;
extern f32 lbl_803E2658;
extern f32 lbl_803E265C;

/*
 * --INFO--
 *
 * Function: CameraModeNpcSpeak_update
 * EN v1.0 Address: 0x8010DD58
 * EN v1.0 Size: 388b
 * EN v1.1 Address: 0x8010DE18
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_8010dedc
 * EN v1.0 Address: 0x8010DEDC
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x8010DFC4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8010df40
 * EN v1.0 Address: 0x8010DF40
 * EN v1.0 Size: 3168b
 * EN v1.1 Address: 0x8010E850
 * EN v1.1 Size: 3212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8010eba0
 * EN v1.0 Address: 0x8010EBA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010F4DC
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8010ebd0
 * EN v1.0 Address: 0x8010EBD0
 * EN v1.0 Size: 432b
 * EN v1.1 Address: 0x8010F5C4
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8010ed80
 * EN v1.0 Address: 0x8010ED80
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x8010F78C
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8010edc4
 * EN v1.0 Address: 0x8010EDC4
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x8010F7DC
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8010eec0
 * EN v1.0 Address: 0x8010EEC0
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010F9BC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8010eeec
 * EN v1.0 Address: 0x8010EEEC
 * EN v1.0 Size: 660b
 * EN v1.1 Address: 0x8010F9E8
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8010f180
 * EN v1.0 Address: 0x8010F180
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x8010FCA0
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8010f1f0
 * EN v1.0 Address: 0x8010F1F0
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x8010FD20
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8010f8bc
 * EN v1.0 Address: 0x8010F8BC
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80110484
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8010f8e8
 * EN v1.0 Address: 0x8010F8E8
 * EN v1.0 Size: 680b
 * EN v1.1 Address: 0x801104B0
 * EN v1.1 Size: 876b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8010fc88
 * EN v1.0 Address: 0x8010FC88
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80110954
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8010fcb4
 * EN v1.0 Address: 0x8010FCB4
 * EN v1.0 Size: 1272b
 * EN v1.1 Address: 0x80110980
 * EN v1.1 Size: 1168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801101ac
 * EN v1.0 Address: 0x801101AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80110E10
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_80110320
 * EN v1.0 Address: 0x80110320
 * EN v1.0 Size: 1828b
 * EN v1.1 Address: 0x80111160
 * EN v1.1 Size: 1532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_80110b8c
 * EN v1.0 Address: 0x80110B8C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80111880
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_80110b94
 * EN v1.0 Address: 0x80110B94
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x80111888
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_80110c58
 * EN v1.0 Address: 0x80110C58
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80111944
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_80110c90
 * EN v1.0 Address: 0x80110C90
 * EN v1.0 Size: 1840b
 * EN v1.1 Address: 0x8011197C
 * EN v1.1 Size: 1588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801113c0
 * EN v1.0 Address: 0x801113C0
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x80111FB0
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_80111558
 * EN v1.0 Address: 0x80111558
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801120E4
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801115e0
 * EN v1.0 Address: 0x801115E0
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x80112150
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/*
 * --INFO--
 *
 * Function: FUN_80111858
 * EN v1.0 Address: 0x80111858
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80112334
 * EN v1.1 Size: 1148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_80111890
 * EN v1.0 Address: 0x80111890
 * EN v1.0 Size: 604b
 * EN v1.1 Address: 0x801127E0
 * EN v1.1 Size: 412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void CameraModeNpcSpeak_release(void)
{
}

void CameraModeNpcSpeak_initialise(void)
{
}

void CameraModeWorldMap_release(void)
{
}

void CameraModeWorldMap_initialise(void)
{
}

void dll_4F_func06_nop(void)
{
}

void dll_4F_release_nop(void)
{
}

void dll_4F_initialise_nop(void)
{
}

void CameraModeCrawl_release(void)
{
}

void CameraModeCrawl_initialise(void)
{
}

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

void CameraModeForceBehind_release(void)
{
}

void CameraModeForceBehind_initialise(void)
{
}

void fn_801101E4(void)
{
}

void CameraModeCloudRunner_release(void)
{
}

void CameraModeCloudRunner_initialise(void)
{
}

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

void CameraModePerv_release(void)
{
}

void CameraModePerv_initialise(void)
{
}

void fn_80110EC0(void)
{
}

void CameraModeArwing_release(void)
{
}

void CameraModeArwing_initialise(void)
{
}

void CameraModeTitle_release(void)
{
}

void CameraModeTitle_initialise(void)
{
}

void CameraModeForceBehind_copyToCurrent(void)
{
}

void CameraModeForceBehind_free(void)
{
}

void CameraModeCloudRunner_copyToCurrent(void)
{
}

void CameraModePerv_copyToCurrent(void)
{
}

void CameraModeArwing_free(void)
{
}

extern void* mmAlloc(int size, int heap, int flags);
extern void* memset(void* dst, int val, u32 n);
extern void audioSetVolumes(int volume, int p1, int p2, int p3, int p4);
extern f32 lbl_803E1A88;
extern CameraMode4FState* lbl_803DD590;
extern CameraModeCrawlState* lbl_803DD598;

void CameraModeTitle_loadVolumes(void)
{
    u8* save = getSaveFileStruct();
    audioSetVolumes(save[10], 1000, 1, 0, 0);
}

void dll_4F_init(void)
{
    if (lbl_803DD590 == NULL)
    {
        lbl_803DD590 = (CameraMode4FState*)mmAlloc(sizeof(CameraMode4FState), 15, 0);
    }
    lbl_803DD590->blendProgress = lbl_803E1A88;
}

extern f32 Curve_EvalHermite(f32* pts, int mode, f32 t);
extern f32 mathCosf(f32);
extern f32 mathSinf(f32);
extern f32 timeDelta;
extern f32 lbl_803E1A8C;
extern f32 lbl_803E1A90;
extern f32 lbl_803E1A94;
extern f32 lbl_803E1A98;
extern f32 lbl_803E1A9C;
extern f32 lbl_803E1AA0;
extern f32 lbl_803E1AA4;
extern f32 lbl_803E1AA8;
extern f32 lbl_803E1AAC;
extern f32 lbl_803E1AB0;
extern f32 lbl_803E1AB4;

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
    fz = Curve_EvalHermite(pts, 0, lbl_803DD590->blendProgress);
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
    camera->unk13B = 0;
    camera->fov = lbl_803E1AB0;
    lbl_803DD590->blendProgress = lbl_803E1AB4 * timeDelta + lbl_803DD590->blendProgress;
    if (lbl_803DD590->blendProgress > *(f32*)&lbl_803E1A8C)
    {
        lbl_803DD590->blendProgress = lbl_803E1A8C;
    }
}

void CameraModeCrawl_init(void)
{
    if (lbl_803DD598 == NULL)
    {
        lbl_803DD598 = (CameraModeCrawlState*)mmAlloc(sizeof(CameraModeCrawlState), 15, 0);
        memset(lbl_803DD598, 0, sizeof(CameraModeCrawlState));
    }
}

extern CameraModeCannonState* lbl_803DD5A0;
extern CameraModePervState* lbl_803DD5C8;
extern f32 lbl_803E1B98;
extern f32 lbl_803E1B9C;
extern CameraModeWorldMapState* lbl_803DD588;

void CameraModePerv_init(int* obj)
{
    CameraObject* camera = (CameraObject*)obj;

    if (lbl_803DD5C8 == NULL)
    {
        lbl_803DD5C8 = (CameraModePervState*)mmAlloc(sizeof(CameraModePervState), 15, 0);
    }
    lbl_803DD5C8->timer = lbl_803E1B98;
    lbl_803DD5C8->cameraY = ((GameObject*)camera->anim.targetObj)->anim.worldPosY - lbl_803E1B9C;
}

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

extern f32 lbl_803E1A40;
extern f32 lbl_803E1A28;
extern f32 lbl_803E1A80;

void CameraModeWorldMap_init(int* obj)
{
    register u32 bitval;
    if (lbl_803DD588 == NULL)
    {
        lbl_803DD588 = (CameraModeWorldMapState*)mmAlloc(sizeof(CameraModeWorldMapState), 15, 0);
    }
    lbl_803DD588->distance = lbl_803E1A40;
    lbl_803DD588->distanceVelocity = lbl_803E1A28;
    bitval = 0;
    lbl_803DD588->mode = bitval;
    lbl_803DD588->previousMode = bitval;
    lbl_803DD588->flags.transitionActive = 0;
    lbl_803DD588->settleFrames = 1;
    lbl_803DD588->focusBlendTimer = 0;
    lbl_803DD588->focusObjectId = 0;
    *(f32*)((char*)obj + 0xB4) = lbl_803E1A80;
    *(s16*)obj = -32768;
}

void CameraModeWorldMap_copyToCurrent(int* p1, int kind)
{
    switch (kind)
    {
    case 0:
        if (p1 == NULL) return;
        lbl_803DD588->mode = *(u8*)p1;
        return;
    case 1:
    case 2:
        if (p1 == NULL) return;
        lbl_803DD588->focusObjectId = *p1;
        if (kind == 1)
        {
            lbl_803DD588->focusBlendTimer = 20;
        }
        else
        {
            lbl_803DD588->focusBlendTimer = 1;
        }
        return;
    }
}

extern f32 lbl_803A43C0[];

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

typedef struct CameraModeTitlePose
{
    f32 x, y, z;
    u16 yaw, pitch, roll;
} CameraModeTitlePose;

extern CameraModeTitlePose lbl_80319FB8[];
extern u8 lbl_803DD5D2;
extern u8 lbl_803DD5D1;
extern u8 lbl_803DD5D0;
extern f32 lbl_803E1BE0;
extern f32 titleScreenCamProgress;

void CameraModeTitle_init(CameraObject* camera)
{
    lbl_803DD5D2 = 4;
    lbl_803DD5D1 = 4;
    titleScreenCamProgress = lbl_803E1BE0;
    lbl_803DD5D0 = 0;

    camera->anim.localPosX = lbl_80319FB8[4].x;
    camera->anim.localPosY = lbl_80319FB8[lbl_803DD5D2].y;
    camera->anim.localPosZ = lbl_80319FB8[lbl_803DD5D2].z;
    camera->anim.rotX = lbl_80319FB8[lbl_803DD5D2].yaw;
    camera->anim.rotY = lbl_80319FB8[lbl_803DD5D2].pitch;
    camera->anim.rotZ = lbl_80319FB8[lbl_803DD5D2].roll;
}

extern CameraMode54State* lbl_803DD5C0;
extern f32 lbl_803E1B5C;

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

int dll_19_func1B(int p)
{
    s16 v = *(s16*)((char*)p + 0x46);
    switch (v)
    {
    case 341:
    case 365:
    case 368:
    case 474:
    case 512:
    case 588:
    case 589:
    case 635:
    case 636:
    case 653:
    case 658:
    case 683:
    case 697:
    case 714:
    case 774:
    case 823:
    case 864:
    case 905:
    case 906:
    case 1021:
    case 1197:
    case 1209:
    case 1235:
    case 1276:
    case 1286:
        return 1;
    }
    return 0;
}

extern void Sfx_StopObjectChannel(int* p1, int channel);
extern void voxmaps_freeRouteWork(void* p);

void dll_19_func12(int* p1, int* p2, u8 flag)
{
    extern void mm_free(u32); /* #57 */
    Sfx_StopObjectChannel(p1, 127);
    if ((*(u8*)((char*)p2 + 1028) & flag) == 0)
    {
        s16 v;
        v = *(s16*)((char*)p2 + 1020);
        if (v != 0)
        {
            (*(void(**)(int*, u16, int, int, int))((char*)*gTitleMenuControlInterface + 8))(p1, (u16)v, 0, 0, 0);
        }
        v = *(s16*)((char*)p2 + 1018);
        if (v != 0)
        {
            (*(void(**)(int*, u16, int, int, int))((char*)*gTitleMenuControlInterface + 8))(p1, (u16)v, 0, 0, 0);
        }
    }
    voxmaps_freeRouteWork((char*)p2 + 900);
    if (*(u32*)((char*)p2 + 988) != 0)
    {
        mm_free(*(u32*)((char*)p2 + 988));
        *(int*)((char*)p2 + 988) = 0;
    }
}

extern CameraModeCloudRunnerState* lbl_803DD5B8;
extern s16 getAngle(f32 dx, f32 dz);

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

extern f32 lbl_803E1BE4;
extern void Movie_SetVolumeFade(int p1, int p2);
extern void Music_Trigger(int id, int mode);

void CameraModeTitle_moveCam(u8 newCam)
{
    if (newCam == lbl_803DD5D2) return;
    if (lbl_803DD5D1 == 4)
    {
        if (lbl_803E1BE0 != titleScreenCamProgress)
        {
            u8* save = getSaveFileStruct();
            Movie_SetVolumeFade(0, 1000);
            audioSetVolumes(save[10], 1000, 1, 0, 0);
        }
        else
        {
            Music_Trigger(190, 1);
            Music_Trigger(193, 1);
        }
    }
    lbl_803DD5D1 = lbl_803DD5D2;
    lbl_803DD5D2 = newCam;
    titleScreenCamProgress = lbl_803E1BE4;
    lbl_803DD5D0 = 1;
}

/* misc 8b leaves */
f32 titleScreenGetCamProgress(void) { return titleScreenCamProgress; }

/* fn_X(lbl); lbl = 0; */
void CameraModeWorldMap_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD588);
    lbl_803DD588 = NULL;
}

void dll_4F_func05(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD590);
    lbl_803DD590 = NULL;
}

void CameraModeCrawl_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD598);
    lbl_803DD598 = NULL;
}

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

void CameraModeCloudRunner_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void dll_54_func05(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5C0);
    lbl_803DD5C0 = NULL;
}

void CameraModePerv_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5C8);
    lbl_803DD5C8 = NULL;
}

void dll_19_func11(void)
{
    (void)(*gCameraInterface)->getOverrideTarget();
}

/* baddie spawn/visibility predicate */
extern int objPosToMapBlockIdx(double x, double y, double z);

int dll_19_func0E(int p1, int p2, u8 b)
{
    if (b != 0 && (s8) * (u8*)(p2 + 0x354) <= 0 && ((GameObject*)p1)->anim.alpha == 0)
    {
        return 0;
    }
    if (*(void**)&((GameObject*)p1)->anim.parent == NULL)
    {
        if (objPosToMapBlockIdx((double)((GameObject*)p1)->anim.localPosX,
                                (double)((GameObject*)p1)->anim.localPosY,
                                (double)((GameObject*)p1)->anim.localPosZ) < 0)
        {
            return 0;
        }
    }
    return 1;
}

/* compute progress ratio (signed numerator / unsigned denominator) */
extern f32 lbl_803E1C2C;

f32 dll_19_func1A(int obj)
{
    int p_b8 = *(int*)&((GameObject*)obj)->extra;
    int p_4c = *(int*)&((GameObject*)obj)->anim.placementData;
    u8 denom = ((Dll19Placement*)p_4c)->unk32;
    if (denom != 0)
    {
        s8 numer = ((Dll19State*)p_b8)->progressNumerator;
        if (numer != 0)
        {
            return (f32)numer / (f32)denom;
        }
    }
    return lbl_803E1C2C;
}

/* baddie state reset */
extern void ObjHits_SetHitVolumeSlot(void* obj, int animObjId, int frame, int flags);

void dll_19_func0D(int p1, int p2, f32 fval, s8 b)
{
    f32 fz;
    *(u32*)p2 |= 0x8000;
    *(u16*)(p2 + 0x330) = 0;
    if (*(void**)(p1 + 0x54) != NULL)
    {
        ObjHits_SetHitVolumeSlot((void*)p1, 0, 0, -1);
    }
    if (b != -1)
    {
        *(s8*)(p2 + 0x25f) = b;
    }
    *(f32*)(p2 + 0x2a4) = fval;
    fz = lbl_803E1C2C;
    *(f32*)(p2 + 0x290) = fz;
    *(f32*)(p2 + 0x28c) = fz;
    *(int*)(p2 + 0x31c) = 0;
    *(int*)(p2 + 0x318) = 0;
}

extern void Obj_FreeObject(void* obj);
extern u8 Obj_IsLoadingLocked(void);
extern ObjPlacement* Obj_AllocObjectSetup(int size, int id);
extern GameObject* Obj_SetupObject(ObjPlacement* setup, int mode, int mapLayer, int objIndex, int parent);
extern u8 lbl_802C2190[];

/* dll_19_func19  addr=0x80111EB4  size=0x100  linkage=global */
void dll_19_func19(u8* cam, u8* ctx)
{
    struct Cfg8
    {
        u32 w0;
        u32 w1;
    };
    s16 buf[5];

    *(struct Cfg8*)&buf[0] = *(struct Cfg8*)lbl_802C2190;
    *(u16*)&buf[4] = *(u16*)(lbl_802C2190 + 8);

    if ((s8)ctx[1031] == (s8)ctx[1033])
    {
        return;
    }
    if (((GameObject*)cam)->anim.alpha == 0)
    {
        return;
    }
    if (*(void**)&((GameObject*)cam)->childObjs[0] != NULL)
    {
        Obj_FreeObject(*(void**)&((GameObject*)cam)->childObjs[0]);
        *(int*)&((GameObject*)cam)->childObjs[0] = 0;
    }
    if (Obj_IsLoadingLocked() != 0)
    {
        if ((s8)ctx[1031] > 0)
        {
            ObjPlacement* setup = Obj_AllocObjectSetup(24, buf[(s8)ctx[1031] - 1]);
            *(int*)&((GameObject*)cam)->childObjs[0] = (int)Obj_SetupObject(
                setup, 4, -1, -1, *(int*)&((GameObject*)cam)->anim.parent);
            *(u16*)(*(int*)&((GameObject*)cam)->childObjs[0] + 0xb0) = ((GameObject*)cam)->objectFlags & 7;
        }
        ctx[1033] = ctx[1031];
    }
    else
    {
        ctx[1033] = 0;
    }
}


extern int* gPlayerInterface;

/* dll_19_func0C  addr=0x80112D80  size=0x114  linkage=global */
#pragma dont_inline on
void dll_19_func0C(int p1, u8* p2, u8* p3, s16 p4, u8* p5, s16 p6, s16 p7, int p8, s8 p9)
{
    if (p3 != NULL)
    {
        p3[0x24] = 0;
        p3[0x25] = 0;
        p3[0x26] = 4;
        p3[0x27] = 20;
    }
    if (p6 != -1)
    {
        *(s16*)(p2 + 0x270) = p6;
        p2[0x27b] = 1;
    }
    if (p7 != -1)
    {
        (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(p1, p2, p7);
    }
    if (p5 != NULL)
    {
        p5[0] = 2;
    }
    if (p8 != 0)
    {
        ObjAnim_SetCurrentMove(p1, p8, lbl_803E1C2C, 0);
    }
    (*gPathControlInterface)->attachObject((void*)p1, p2 + 4);
    if (p9 != -1)
    {
        p2[0x25f] = p9;
    }
    if (p4 != -1)
    {
        GameBit_Set(p4, 1);
    }
}
#pragma dont_inline reset

extern f32 lbl_803E1B78;
extern f32 lbl_803E1B7C;
extern f32 lbl_803E1B80;
extern f32 lbl_803E1B84;
extern f32 lbl_803E1B88;

/* CameraModePerv_update  addr=0x80110CB0  size=0x10C  linkage=global */
void CameraModePerv_update(u8* obj)
{
    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;

    lbl_803DD5C8->timer -= lbl_803E1B78 * timeDelta;
    if (lbl_803DD5C8->timer < *(f32*)&lbl_803E1B7C)
    {
        lbl_803DD5C8->timer = lbl_803E1B7C;
    }
    camera->anim.localPosX =
        target->anim.worldPosX -
        lbl_803E1B80 * mathSinf(lbl_803E1B84 * (f32)(s32)target->anim.rotX / lbl_803E1B88);
    camera->anim.localPosY = lbl_803DD5C8->cameraY;
    camera->anim.localPosZ =
        target->anim.worldPosZ -
        lbl_803E1B80 * mathCosf(lbl_803E1B84 * (f32)(s32)target->anim.rotX / lbl_803E1B88);
    camera->anim.rotX = 0;
    camera->anim.rotY = -0x4000;
    camera->anim.rotZ = 0;
}

extern f32 lbl_803E1B00;
extern f32 lbl_803E1B04;
extern f32 lbl_803E1B08;
extern f32 lbl_803E1B1C;
extern f32 lbl_803DB9C8;
extern f32 lbl_803DD5AC;
extern f32 lbl_803DD5B0;
extern f32 sqrtf(f32 x);

extern f32 lbl_803DD5A8;
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern void fn_8029697C(int state, s16* a, s16* b);
extern f32 lbl_803E1B18;


/* CameraModeForceBehind_init  addr=0x801100B8  size=0x124  linkage=global */
void CameraModeForceBehind_init(u8* obj, int p2, f32* p3)
{
    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    f32 angle;
    f32 cosv, sinv;
    f32 baseX, baseZ;
    f32 pos[3];
    f32 extra;
    f32 dx, dz;

    {
        int a = target->anim.rotX;
        angle = lbl_803E1B00 * (f32)a / lbl_803E1B04;
    }
    cosv = mathSinf(angle);
    sinv = mathCosf(angle);
    pos[0] = cosv * lbl_803DB9C8 + (baseX = target->anim.worldPosX);
    pos[1] = lbl_803E1B08 + target->anim.worldPosY;
    baseZ = target->anim.worldPosZ;
    pos[2] = sinv * lbl_803DB9C8 + baseZ;
    camcontrol_traceFromTarget(pos, target, pos, &extra);
    dx = pos[0] - baseX;
    dz = pos[2] - baseZ;
    lbl_803DD5B0 = sqrtf(dx * dx + dz * dz);
    if (p3 != NULL)
    {
        lbl_803DB9C8 = p3[0];
        lbl_803DD5AC = p3[1];
    }
    else
    {
        lbl_803DB9C8 = lbl_803E1B1C;
        lbl_803DD5AC = lbl_803E1B08;
    }
}

extern int Obj_GetPlayerObject(void);
extern int fn_80295A04(int obj, int a);
extern int fn_80296AE8(int obj);
extern f32 lbl_803E1C48;

/* dll_19_func13  addr=0x8011313C  size=0x13C  linkage=global */
int dll_19_func13(int p1, u8* p2, f32 f, int p4)
{
    extern f32 lbl_803E1C68; /* #57 */
    extern int objBboxFn_800640cc(int a, f32* pos, f32 b, int c, f32* out, int d, int e, int g, int h, int i); /* #57 */
    int player = Obj_GetPlayerObject();
    int result = 0;

    if ((s8)p2[838] != 0)
    {
        if (*(int*)(p2 + 720) != player)
        {
            result = 1;
        }
        else if ((s8)p2[852] == 0)
        {
            result = 1;
        }
        else if (*(f32*)(p2 + 704) > f && p4 != 0)
        {
            result = 1;
        }
        else if (fn_80295A04(player, 1) == 0)
        {
            result = 1;
        }
        else if (fn_80296AE8(player) <= 0)
        {
            result = 1;
        }
        else
        {
            f32 pos[3];
            f32 out[2];
            pos[0] = ((GameObject*)player)->anim.localPosX;
            pos[1] = lbl_803E1C68 + ((GameObject*)player)->anim.localPosY;
            pos[2] = ((GameObject*)player)->anim.localPosZ;
            if (objBboxFn_800640cc(p1 + 0xc, pos, lbl_803E1C48, 0, out, p1, 4, -1, 0, 0) != 0)
            {
                result = 1;
            }
        }
    }
    return result;
}

extern f32 lbl_803E1C6C;

/* dll_19_func10  addr=0x80113398  size=0x16C  linkage=global */
int dll_19_func10(int p1, u8* p2, int p3, int p4, s16 p5, f32* p6, f32* p7, int* p8)
{
    extern f32 lbl_803E1C68; /* #57 */
    f32 dx, dz, dist;
    f32 zero;

    if (p2[897] != 0)
    {
        zero = lbl_803E1C2C;
        *(int*)(p2 + 792) = 0;
        *(int*)(p2 + 796) = 0;
        *(s16*)(p2 + 816) = 0;
        *(f32*)(p2 + 656) = zero;
        *(f32*)(p2 + 652) = zero;
        *p8 = 1;
        dx = *p6 - *(f32*)(p1 + 12);
        dz = *p7 - *(f32*)(p1 + 20);
        dist = sqrtf(dx * dx + dz * dz);
        if (dist < lbl_803E1C68)
        {
            *p8 = 0;
        }
        else
        {
            dx /= dist;
            dz /= dist;
            *(f32*)(p2 + 656) = lbl_803E1C6C * -dx;
            *(f32*)(p2 + 652) = lbl_803E1C6C * dz;
            *(f32*)(p1 + 12) += dist * dx;
            *(f32*)(p1 + 20) += dist * dz;
            (*(void (**)(int, u8*, f32, f32, int, int))(*(int*)gPlayerInterface + 8))(
                p1, p2, timeDelta, timeDelta, p3, p4);
        }
        if (*p8 == 0)
        {
            p2[1029] = 0;
            *(s16*)(p2 + 628) = p5;
            *(int*)(p2 + 720) = 0;
            p2[607] = 0;
            GameBit_Set(*(s16*)(p2 + 1012), 0);
        }
        return 1;
    }
    return 0;
}

extern f32 lbl_803E1AC0;
extern f32 lbl_803E1AC4;

/* CameraModeCrawl_copyToCurrent  addr=0x8010F540  size=0x1E0  linkage=global */
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
    camcontrol_getTargetPosition(obj, target, pos, 0);
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

/* dll_19_func17  addr=0x80112544  size=0x19C  linkage=global */
int dll_19_func17(int p1, u8* p2, u8* p3, s16 p4, u8* p5, s16 p6, s16 p7, s16 p8)
{
    u32 msgData;
    int msgType;
    int extra;

    extra = 0;
    while (ObjMsg_Pop(p1, &msgType, &msgData, &extra) != 0)
    {
        switch (msgType)
        {
        case 4:
            ObjMsg_SendToObject(msgData, 5, p1, 0);
            break;
        case 0xE0000:
            if (msgData == *(int*)(p2 + 720))
            {
                *(s16*)(p2 + 624) = p6;
                *(int*)(p2 + 720) = 0;
                p2[841] = 0;
            }
            break;
        case 11:
            p2[846] = (s8)extra;
            break;
        case 1:
        case 0xA0001:
            if (*(s16*)(p2 + 624) != p7)
            {
                dll_19_func0C(p1, p2, p3, p4, p5, p6, p8, 0, 1);
                *(s16*)(p2 + 624) = p7;
                p2[841] = 0;
                *(int*)(p2 + 720) = msgData;
                return 1;
            }
            break;
        case 3:
            if (*(s16*)(p2 + 624) == p7)
            {
                p2[841] = 0;
                *(int*)(p2 + 720) = 0;
                *(s16*)(p2 + 624) = p6;
                return 2;
            }
            break;
        }
    }
    return 0;
}

extern s16* objModelGetVecFn_800395d8(int obj, int idx);
extern f32 lbl_803E1AE0;
extern f32 lbl_803E1AE4;
extern f32 lbl_803E1AE8;
extern f32 lbl_803E1AEC;
extern f32 lbl_803E1AF0;

/* CameraModeCannon_update  addr=0x8010FA84  size=0x168  linkage=global */
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

extern f32 fn_8029610C(int obj);
extern void voxmaps_worldToGrid(f32* pos, int* grid);
extern f32 lbl_803E1C64;

/* dll_19_func14  addr=0x80112E94  size=0x2A8  linkage=global */
int dll_19_func14(u8* p1, u8* p2, f32 frange, int p4)
{
    extern f32 lbl_803E1C68; /* #57 */
    extern int objBboxFn_800640cc(int a, f32* pos, f32 b, int c, f32* out, int d, int e, int g, int h, int i); /* #57 */
    extern int voxmaps_traceLine(int* a, int* b, int c, u8* out, int e); /* #57 */
    f32 bboxOut[20];
    int objs[2];
    f32 diff[3];
    f32 gridIn[3];
    int gridB[2];
    int gridA[2];
    u8 losOut;
    f32* dp = diff;
    int* list;
    int obj;
    int found = 0;
    int negP4;
    int newangle;
    int delta;
    u8 traced;

    objs[0] = Obj_GetPlayerObject();
    objs[1] = 0;
    list = objs;
    negP4 = -p4;

    while ((obj = *list) != 0)
    {
        dp[0] = ((GameObject*)obj)->anim.worldPosX - *(f32*)(p1 + 0x18);
        dp[1] = ((GameObject*)obj)->anim.worldPosY - *(f32*)(p1 + 0x1c);
        dp[2] = ((GameObject*)obj)->anim.worldPosZ - *(f32*)(p1 + 0x20);
        if (sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1])) < frange)
        {
            if ((s8)p2[852] != 0)
            {
                if (fn_8029610C(obj) > lbl_803E1C64)
                {
                    found = 1;
                }
                newangle = (u16)getAngle(-dp[0], -dp[2]);
                if (*(void**)(p1 + 0x30) != NULL)
                {
                    delta = newangle - (u16)(*(s16*)p1 + *(s16*)(*(int*)(p1 + 0x30)));
                    if (delta > 0x8000)
                    {
                        delta -= 0xffff;
                    }
                    if (delta < -0x8000)
                    {
                        delta += 0xffff;
                    }
                }
                else
                {
                    delta = newangle - (u16) * (s16*)p1;
                    if (delta > 0x8000)
                    {
                        delta -= 0xffff;
                    }
                    if (delta < -0x8000)
                    {
                        delta += 0xffff;
                    }
                }
                if (delta < p4 && delta > negP4)
                {
                    found = 1;
                }
                if (fn_80295A04(obj, 1) == 0)
                {
                    found = 0;
                }
                if (fn_80296AE8(obj) <= 0)
                {
                    found = 0;
                }
                else
                {
                    gridIn[0] = *(f32*)(p1 + 12);
                    gridIn[1] = lbl_803E1C68 + *(f32*)(p1 + 16);
                    gridIn[2] = *(f32*)(p1 + 20);
                    voxmaps_worldToGrid(gridIn, gridA);
                    gridIn[0] = ((GameObject*)obj)->anim.localPosX;
                    gridIn[1] = lbl_803E1C68 + ((GameObject*)obj)->anim.localPosY;
                    gridIn[2] = ((GameObject*)obj)->anim.localPosZ;
                    voxmaps_worldToGrid(gridIn, gridB);
                    traced = voxmaps_traceLine(gridB, gridA, 0, &losOut, 0);
                    if (losOut == 1 || traced != 0)
                    {
                        if (objBboxFn_800640cc((int)(p1 + 12), gridIn, lbl_803E1C48, 0, bboxOut,
                                               (int)p1, 4, -1, 0, 0) != 0)
                        {
                            found = 0;
                        }
                    }
                    else
                    {
                        found = 0;
                    }
                }
            }
        }
        list++;
        if (found != 0)
        {
            break;
        }
    }
    return obj;
}

extern MapEventInterface** gMapEventInterface;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E1C30;
extern f32 lbl_803E1C40;
extern f32 lbl_803E1C44;
extern f32 lbl_803E1C4C;
extern f32 lbl_803E1C50;

/* dll_19_func16  addr=0x801126E0  size=0x348  linkage=global */
int dll_19_func16(u8* p1, u8* p2, int p3, int p4, int* p5, u8* p6, s16 p7, u8* p8)
{
    u8* state = *(u8**)(p1 + 184);
    int player = Obj_GetPlayerObject();
    int hit;
    int v28;
    int v24;
    int hitId;
    f32 posX;
    f32 posY;
    f32 posZ;

    if (*(f32*)(state + 1000) > lbl_803E1C2C)
    {
        *(f32*)(state + 1000) = timeDelta * *(f32*)(state + 1004) + *(f32*)(state + 1000);
        if ((*(u16*)(state + 1024) & 0x20) != 0)
        {
            *(u16*)(state + 1024) = *(u16*)(state + 1024) & ~0x20;
            *(u16*)(state + 1024) = *(u16*)(state + 1024) | 0x40;
            if (*(f32*)(state + 1000) > lbl_803E1C40)
            {
                *(f32*)(state + 1000) = lbl_803E1C2C;
                *(u16*)(state + 1024) = *(u16*)(state + 1024) & ~0x40;
            }
        }
        else if ((*(u16*)(state + 1024) & 0x40) != 0)
        {
            if (*(f32*)(state + 1000) > lbl_803E1C40)
            {
                int other = *(int*)(p1 + 76);
                *(f32*)(state + 1000) = lbl_803E1C2C;
                *(u16*)(state + 1024) = *(u16*)(state + 1024) & ~0x40;
                p2[852] = 0;
                p1[54] = 0;
                *(int*)(p1 + 244) = 1;
                *(s16*)(p1 + 6) = *(s16*)(p1 + 6) | 0x4000;
                (*gMapEventInterface)->startTimedEvent(
                    *(int*)(other + 20),
                    (f32)(s32)(*(s16*)(other + 44) * 60) - lbl_803E1C30);
            }
        }
        else
        {
            if (*(f32*)(state + 1000) < lbl_803E1C2C)
            {
                *(f32*)(state + 1000) = lbl_803E1C2C;
            }
            else if (*(f32*)(state + 1000) > lbl_803E1C44)
            {
                *(f32*)(state + 1000) = lbl_803E1C44 - (*(f32*)(state + 1000) - lbl_803E1C44);
                *(f32*)(state + 1004) = -*(f32*)(state + 1004);
            }
        }
    }

    if ((s8)p2[852] == 0)
    {
        return 0;
    }
    hit = ObjHits_GetPriorityHitWithPosition(p1, &hitId, &v28, &v24, &posX, &posY, &posZ);
    state[1034] = (s8)v28;
    if (hit == 0)
    {
        return hit;
    }
    if (p8 != NULL)
    {
        *(f32*)(p8 + 12) = posX + playerMapOffsetX;
        *(f32*)(p8 + 16) = posY;
        *(f32*)(p8 + 20) = posZ + playerMapOffsetZ;
    }
    if (p6 != NULL)
    {
        if ((s8) * (s8*)(p6 + hit - 2) != -1)
        {
            v24 = (s8) * (s8*)(p6 + hit - 2);
        }
    }
    else
    {
        v24 = 0;
    }
    p2[852] = (s8)(p2[852] - v24);
    if ((s8)p2[852] < 1)
    {
        *(u16*)(state + 1024) = *(u16*)(state + 1024) | 0x20;
        *(f32*)(state + 1000) = lbl_803E1C48;
        *(f32*)(state + 1004) = lbl_803E1C4C;
        *(s16*)(p2 + 624) = p7;
        p2[852] = 0;
    }
    else
    {
        if (v24 != 0)
        {
            if (*(int*)(p2 + 720) == 0)
            {
                if (fn_80295A04(player, 1) != 0)
                {
                    *(int*)(p2 + 720) = player;
                    p2[841] = 0;
                }
            }
            *(f32*)(state + 1000) = lbl_803E1C48;
            *(f32*)(state + 1004) = lbl_803E1C50;
            if (p5 != NULL)
            {
                if (p5[hit - 2] != -1)
                {
                    (*(void (**)(u8*, u8*))(*(int*)gPlayerInterface + 20))(p1, p2);
                    *(s16*)(p2 + 624) = p7;
                }
            }
            p2[847] = (s8)hit;
        }
        Sfx_StopObjectChannel((int*)p1, 16);
        ObjMsg_SendToObject(hitId, 0xe0001, p1, 0);
    }
    return hit;
}

extern u32 lbl_803E1C18;
extern u32 lbl_803E1C1C;
extern u32 lbl_803E1C20;
extern u32 lbl_803E1C24;
extern f32 lbl_803E1C54;
extern f32 lbl_803E1C58;
extern f32 lbl_803E1C5C;
extern f32 lbl_803E1C60;
extern GameObject* lbl_803DD5E4;

/* dll_19_func15  addr=0x80112A28  size=0x358  linkage=global */
int dll_19_func15(u8* p1, int p2, int p3, int p4)
{
    GameObject* source = (GameObject*)p1;
    u8* state = *(u8**)&((GameObject*)p1)->anim.placementData;
    ObjPlacement* setup;
    f32 scale;
    u16 ids1[4];
    u16 ids2[4];
    int idx;
    f32 savedX, savedY, savedZ;
    f32 nearDist;

    scale = lbl_803E1C2C;
    *(u32*)&ids1[0] = lbl_803E1C18;
    *(u32*)&ids1[2] = lbl_803E1C1C;
    *(u32*)&ids2[0] = lbl_803E1C20;
    *(u32*)&ids2[2] = lbl_803E1C24;
    if (p2 == 0)
    {
        return 0;
    }
    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }
    if ((((Dll19Placement*)state)->unk22 & 0xf00) != 0)
    {
        idx = ((p2 & 0xf00) >> 8) - 1;
        if (idx > 3)
        {
            idx = 3;
        }
        setup = Obj_AllocObjectSetup(48, ids1[idx]);
        scale = lbl_803E1C54;
    }
    if ((((Dll19Placement*)state)->unk22 & 0xf000) != 0)
    {
        idx = ((p2 & 0xf000) >> 12) - 1;
        if (idx > 3)
        {
            idx = 3;
        }
        setup = Obj_AllocObjectSetup(48, ids2[idx]);
        scale = lbl_803E1C54;
    }
    if ((u8)((Dll19Placement*)state)->unk22 != 0)
    {
        switch (p2)
        {
        case 1:
            setup = Obj_AllocObjectSetup(48, 717);
            scale = lbl_803E1C54;
            break;
        case 2:
            setup = Obj_AllocObjectSetup(48, 9);
            scale = lbl_803E1C54;
            break;
        case 3:
            setup = Obj_AllocObjectSetup(48, 11);
            scale = lbl_803E1C54;
            break;
        case 4:
            setup = Obj_AllocObjectSetup(48, 717);
            scale = lbl_803E1C54;
            break;
        case 5:
            savedX = source->anim.worldPosX;
            savedY = source->anim.worldPosY;
            savedZ = source->anim.worldPosZ;
            if (state != NULL)
            {
                source->anim.worldPosX = ((ObjPlacement*)state)->posX;
                source->anim.worldPosY = ((ObjPlacement*)state)->posY;
                source->anim.worldPosZ = ((ObjPlacement*)state)->posZ;
            }
            nearDist = lbl_803E1C58;
            lbl_803DD5E4 = (GameObject*)ObjGroup_FindNearestObject(4, p1, &nearDist);
            source->anim.worldPosX = savedX;
            source->anim.worldPosY = savedY;
            source->anim.worldPosZ = savedZ;
            if (lbl_803DD5E4 != NULL)
            {
                lbl_803DD5E4->anim.worldPosX = source->anim.localPosX;
                lbl_803DD5E4->anim.localPosX = source->anim.localPosX;
                lbl_803DD5E4->anim.worldPosY = source->anim.localPosY + lbl_803E1C5C;
                lbl_803DD5E4->anim.localPosY = source->anim.localPosY + lbl_803E1C5C;
                lbl_803DD5E4->anim.worldPosZ = source->anim.localPosZ;
                lbl_803DD5E4->anim.localPosZ = source->anim.localPosZ;
            }
            return (int)lbl_803DD5E4;
        case 6:
            setup = Obj_AllocObjectSetup(48, 1702);
            *(u8*)((u8*)setup + 27) = 0;
            *(u8*)((u8*)setup + 34) = 0;
            *(u8*)((u8*)setup + 35) = 64;
            scale = lbl_803E1C60;
            break;
        default:
            return 0;
        }
    }
    *(u8*)((u8*)setup + 26) = 20;
    *(s16*)((u8*)setup + 44) = -1;
    *(s16*)((u8*)setup + 28) = -1;
    *(s16*)((u8*)setup + 36) = -1;
    setup->posX = source->anim.localPosX;
    setup->posY = source->anim.localPosY + scale;
    setup->posZ = source->anim.localPosZ;
    if ((u8)p4 != 0)
    {
        *(s16*)((u8*)setup + 46) = 2;
    }
    else
    {
        *(s16*)((u8*)setup + 46) = 1;
    }
    *(u8*)((u8*)setup + 4) = state[4];
    *(u8*)((u8*)setup + 6) = state[6];
    *(u8*)((u8*)setup + 5) = state[5];
    *(u8*)((u8*)setup + 7) = state[7];
    lbl_803DD5E4 = Obj_SetupObject(setup, 5, (s8)p1[172], -1, *(int*)&source->anim.parent);
    return (int)lbl_803DD5E4;
}

extern int GameBit_Get(int bit);
extern void voxmaps_allocRouteWork(u8 * work);
extern u32 lbl_803E1C28;
extern f32 lbl_803E1C38;
extern u8 lbl_8031A054[];
extern u8 lbl_8031A048[];
extern u32 lbl_803DB9E0;
extern u32 lbl_803DD5E0;

/* dll_19_func18  addr=0x80112098  size=0x47C  linkage=global */
void dll_19_func18(int p1, u8* p2, u8* p3, int p4, int p5, int p6, f32 fparam, int p7)
{
    u8 flags = (u8)p7;
    int b1 = flags & 1;
    u8* path = p3 + 4;
    int curveLocal;
    u8 byteLocal;

    curveLocal = lbl_803E1C28;
    byteLocal = 1;
    *(int*)(p3 + 1036) = (int)(p3 + 1040);
    *(s16*)(p3 + 1026) = 0;

    if (b1 == 0 && (flags & 0x20) == 0)
    {
        ObjGroup_AddObject(p1, 3);
        ObjMsg_AllocQueue(p1, 4);
    }
    (*(void (**)(int, u8*, int, int))(*(int*)gPlayerInterface + 4))(p1, p3, p4, p5);
    *(int*)(p3 + 0) = 0;
    p3[841] = 0;
    *(f32*)(p3 + 640) = lbl_803E1C2C;
    *(f32*)(p3 + 644) = lbl_803E1C2C;
    if ((s8)p2[50] != 0)
    {
        p3[852] = (s8)p2[50];
    }
    else
    {
        p3[852] = 6;
    }
    *(s16*)(p3 + 1012) = *(s16*)(p2 + 48);
    *(s16*)(p3 + 1014) = *(s16*)(p2 + 26);
    *(s16*)(p3 + 1016) = *(s16*)(p2 + 28);
    if (*(s16*)(p3 + 1012) != -1)
    {
        GameBit_Set(*(s16*)(p3 + 1012), 0);
    }
    if ((flags & 2) != 0)
    {
        (*gPathControlInterface)->init(path, 0, p6 | 0x200000, 1);
    }
    else
    {
        (*gPathControlInterface)->init(path, 0, 0, 0);
    }
    (*gPathControlInterface)->setLocalPointCollision(path, 1, lbl_8031A054, (void*)lbl_803DB9E0, 4);
    if ((flags & 4) != 0)
    {
        (*gPathControlInterface)->setup(path, 1, lbl_8031A048, (void*)lbl_803DD5E0, &byteLocal);
    }
    (*gPathControlInterface)->attachObject((void*)p1, path);
    p3[1028] = p2[43];
    *(s16*)(p3 + 1008) = *(s16*)(p2 + 34);
    p3[1030] = p2[47];
    p3[1031] = p2[39];
    p3[1032] = p2[40];
    *(s16*)(p1 + 176) = *(u16*)(p1 + 176) | ((s8)p3[1032] & 7);
    if ((flags & 8) != 0)
    {
        *(s16*)(p3 + 1018) = *(s16*)(p2 + 32);
        *(s16*)(p3 + 1020) = *(s16*)(p2 + 30);
    }
    else
    {
        *(s16*)(p3 + 1018) = 0;
        *(s16*)(p3 + 1020) = 0;
    }
    *(s16*)(p3 + 1024) = 0;
    *(s16*)(p3 + 1022) = (u16)(p2[41] << 3);
    p3[1029] = 0;
    *(f32*)(p3 + 996) = fparam;
    *(s16*)(p1 + 0) = (s16)((s8)p2[42] << 8);
    *(u8*)(p1 + 54) = 255;
    *(u8*)(p1 + 175) = *(u8*)(p1 + 175) & ~0x8;
    *(s16*)(p3 + 1010) = *(s16*)(p2 + 24);
    if (*(s16*)(p3 + 1010) != -1)
    {
        if (*(s16*)(p1 + 70) == 636)
        {
            *(int*)(p1 + 244) = (GameBit_Get(*(s16*)(p3 + 1010)) == 0);
        }
        else
        {
            *(int*)(p1 + 244) = GameBit_Get(*(s16*)(p3 + 1010));
        }
    }
    else
    {
        *(int*)(p1 + 244) = 0;
    }
    if ((*gMapEventInterface)->isTimedEventActive(*(int*)(p2 + 20)) == 0)
    {
        *(int*)(p1 + 244) = 1;
    }
    if (*(int*)(p1 + 244) != 0)
    {
        ObjHits_DisableObject(p1);
        *(s16*)(p1 + 6) = *(s16*)(p1 + 6) | 0x4000;
    }
    else
    {
        *(s16*)(p1 + 6) = *(s16*)(p1 + 6) & ~0x4000;
        ObjHits_EnableObject(p1);
    }
    if ((s8)p2[46] == -1)
    {
        *(int*)(p1 + 248) = 1;
    }
    else
    {
        *(int*)(p1 + 248) = 0;
    }
    if (b1 == 0 && (flags & 0x20) == 0)
    {
        voxmaps_allocRouteWork(p3 + 900);
        p3[898] = 4;
        p3[899] = 20;
    }
    if ((flags & 0x10) != 0)
    {
        if (*(int*)(p3 + 988) == 0 && (flags & 0x20) == 0)
        {
            *(int*)(p3 + 988) = (int)mmAlloc(264, 26, 0);
        }
        if (*(int*)(p3 + 988) != 0)
        {
            memset((void*)*(int*)(p3 + 988), 0, 264);
        }
        if ((*gRomCurveInterface)->initCurve((void*)*(int*)(p3 + 988), (void*)p1,
                                             (f32)(s32) * (u16*)(p3 + 1022) - lbl_803E1C38,
                                             &curveLocal, -1) == 0)
        {
            *(s16*)(p3 + 1024) = *(u16*)(p3 + 1024) | 8;
        }
    }
    else
    {
        *(int*)(p3 + 988) = 0;
    }
}

extern f32 lbl_803E1AD0;
extern f32 lbl_803E1AD4;
extern f32 lbl_803E1AD8;
extern f32 lbl_803E1ADC;

/* CameraModeCrawl_update  addr=0x8010F74C  size=0x2B8  linkage=global */
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

/* CameraModeCloudRunner_update  addr=0x80110214  size=0x36C  linkage=global */
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

    fn_8029697C((int)target, &tgtYaw, &tgtPitch);
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


/* CameraModeForceBehind_update  addr=0x8010FC7C  size=0x43C  linkage=global */
void CameraModeForceBehind_update(u8* obj)
{
    extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int mtx); /* #57 */
    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    s16 extra;
    s16 pitch;
    s16 yaw;
    f32 pos[3];
    f32 angle;
    f32 cosv, sinv;
    f32 sx, sz;
    f32 baseX, baseY, baseZ;
    f32 cosYaw, sinYaw, sinPitch, cosPitch;
    f32 radius;

    angle = lbl_803E1B00 * (f32)(0x8000 - camera->anim.rotX) / lbl_803E1B04;
    cosv = mathSinf(angle);
    sinv = mathCosf(angle);
    sx = target->anim.worldPosX;
    pos[0] = cosv * lbl_803DB9C8 + sx;
    pos[1] = lbl_803E1B08 + target->anim.worldPosY;
    sz = target->anim.worldPosZ;
    pos[2] = sinv * lbl_803DB9C8 + sz;
    camcontrol_traceFromTarget(pos, target, pos, &extra);
    lbl_803DD5A8 = lbl_803DD5B0 = sqrtf((pos[0] - sx) * (pos[0] - sx) + (pos[2] - sz) * (pos[2] - sz));

    fn_8029697C((int)target, &yaw, &pitch);
    yaw = (s16)((0x8000 - target->anim.rotX) + (yaw >> 1));
    pitch = (s16)(pitch >> 1);
    baseX = target->anim.worldPosX;
    baseY = target->anim.worldPosY + lbl_803DD5AC;
    baseZ = target->anim.worldPosZ;

    yaw = (s16)(yaw - (u16)camera->anim.rotX);
    if (yaw > 0x8000)
    {
        yaw -= 0xffff;
    }
    if (yaw < -0x8000)
    {
        yaw += 0xffff;
    }
    camera->anim.rotX = (s16)(s32)((f32)(s32)camera->anim.rotX + interpolate((f32)yaw, lbl_803E1B18, timeDelta));

    pitch = (s16)(pitch - (u16)camera->anim.rotY);
    if (pitch > 0x8000)
    {
        pitch -= 0xffff;
    }
    if (pitch < -0x8000)
    {
        pitch += 0xffff;
    }
    camera->anim.rotY = (s16)(s32)((f32)(s32)camera->anim.rotY +
                                   interpolate((f32)pitch, lbl_803E1B18, timeDelta));

    cosYaw = mathSinf(lbl_803E1B00 * (f32)(s32)(camera->anim.rotX - 0x4000) / lbl_803E1B04);
    sinYaw = mathCosf(lbl_803E1B00 * (f32)(s32)(camera->anim.rotX - 0x4000) / lbl_803E1B04);
    sinPitch = mathCosf(lbl_803E1B00 * (f32)(s32)camera->anim.rotY / lbl_803E1B04);
    cosPitch = mathSinf(lbl_803E1B00 * (f32)(s32)camera->anim.rotY / lbl_803E1B04);
    radius = lbl_803DD5A8;
    camera->anim.worldPosX = baseX + radius * sinPitch * sinYaw;
    camera->anim.worldPosY = baseY + radius * cosPitch;
    camera->anim.worldPosZ = baseZ + radius * sinPitch * cosYaw;
    camcontrol_traceFromTarget(&camera->anim.worldPosX, target, &camera->anim.worldPosX, &camera->anim.rotY);
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}

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

/* dll_54_update  addr=0x801106E4  size=0x490  linkage=global */
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

extern int getFocusedNpc(void);
extern int randomGetRange(int lo, int hi);
extern void fn_8010DB7C(GameObject * target, f32 * a, f32 * b, f32 * c);
extern CameraModeNpcSpeakState* lbl_803DD584;
extern f32 lbl_803E19E8;
extern f32 lbl_803E19EC;
extern f32 lbl_803E19DC;
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

typedef struct CameraModeNpcSpeakInitParams
{
    f32 anchorX;
    f32 anchorY;
    f32 anchorZ;
    u8 mode;
} CameraModeNpcSpeakInitParams;

/* CameraModeNpcSpeak_init  addr=0x8010DFF0  size=0x524  linkage=global */
void CameraModeNpcSpeak_init(u8* obj, int unused, u8* p3)
{
    CameraObject* camera = (CameraObject*)obj;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    int mode = 0;
    int yawA, yawB;
    int spd;
    int d1, d2;
    int npc;
    f32 vd[3], vc[3], vb[3], va[3];
    CameraModeNpcSpeakState* speakState;

    if (lbl_803DD584 == NULL)
    {
        lbl_803DD584 = (CameraModeNpcSpeakState*)mmAlloc(sizeof(CameraModeNpcSpeakState), 15, 0);
    }
    speakState = lbl_803DD584;
    if (p3 != NULL)
    {
        CameraModeNpcSpeakInitParams* params = (CameraModeNpcSpeakInitParams*)p3;
        speakState->anchorX = params->anchorX;
        speakState->anchorY = params->anchorY;
        speakState->anchorZ = params->anchorZ;
        mode = params->mode;
    }
    else
    {
        GameObject* focus = (GameObject*)getFocusedNpc();
        f32* fpos;
        if (focus == NULL)
        {
            speakState->anchorX = lbl_803E19E8;
            speakState->anchorY = lbl_803E19E8;
            speakState->anchorZ = lbl_803E19E8;
        }
        fpos = *(f32**)((u8*)focus + 0x74);
        if (fpos == NULL)
        {
            speakState->anchorX = lbl_803E19E8;
            speakState->anchorY = lbl_803E19E8;
            speakState->anchorZ = lbl_803E19E8;
        }
        speakState->anchorX = fpos[0];
        speakState->anchorY = fpos[1];
        speakState->anchorZ = fpos[2];
    }
    if (mode == 4)
    {
        mode = randomGetRange(0, 3);
    }
    {
        f32 a, b;
        speakState->unk20 = 0;
        speakState->mode = mode;
        speakState->unk14 = lbl_803E19E8;
        a = lbl_803E19EC;
        speakState->targetHeightOffset = a;
        speakState->lookAtHeightOffset = lbl_803E19DC;
        speakState->lookAtYScale = lbl_803E19F0;
        b = lbl_803E19F4;
        speakState->anchorLerpScale = b;
        speakState->lookAtXZScale = b;
        speakState->minDistance = a;
    }
    speakState->orbitAngleOffset = randomGetRange(0x2000, 0x2c00);

    switch (mode)
    {
    case 0:
        speakState->distanceOffset = lbl_803E19F8;
        break;
    case 1:
        speakState->distanceOffset = lbl_803E19FC;
        break;
    case 2:
        speakState->distanceOffset = lbl_803E1A00;
        break;
    case 5:
        speakState->distanceOffset = lbl_803E1A04;
        break;
    case 3:
        speakState->distanceOffset = lbl_803DB9C0;
        speakState->orbitAngleOffset = randomGetRange(0xf00, 0x1f00);
        speakState->lookAtHeightOffset = lbl_803E19E8;
        break;
    case 6:
        speakState->targetHeightOffset = lbl_803DB9A8;
        speakState->lookAtHeightOffset = lbl_803DB9AC;
        speakState->anchorLerpScale = lbl_803DD580;
        speakState->lookAtYScale = lbl_803DB9B0;
        speakState->orbitAngleOffset = lbl_803DB9BC;
        speakState->lookAtXZScale = lbl_803DB9B4;
        speakState->distanceOffset = lbl_803DB9B8;
        speakState->orbitAngleVelocity = 0xb6;
        speakState->minDistance = lbl_803E19E8;
        break;
    case 7:
        speakState->distanceOffset = lbl_803E19F8;
        speakState->targetHeightOffset = lbl_803E1A08;
        speakState->anchorLerpScale = lbl_803E1A0C;
        speakState->lookAtXZScale = lbl_803E1A10;
        speakState->lookAtYScale = lbl_803E1A14;
        speakState->orbitAngleOffset = randomGetRange(0x1800, 0x1c00);
        break;
    case 8:
        speakState->distanceOffset = lbl_803E1A18;
        speakState->lookAtHeightOffset = lbl_803E1A1C;
        break;
    default:
        speakState->distanceOffset = lbl_803E19F8;
        break;
    }

    yawA = (u16)getAngle(camera->anim.worldPosX - speakState->anchorX,
                         camera->anim.worldPosZ - speakState->anchorZ);
    yawB = (u16)getAngle(target->anim.worldPosX - speakState->anchorX,
                         target->anim.worldPosZ - speakState->anchorZ);
    spd = speakState->orbitAngleOffset;
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
        speakState->orbitAngleOffset = -spd;
        speakState->orbitAngleVelocity = -0x80;
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
        if ((dd > 0x1000 && speakState->orbitAngleOffset > 0) ||
            (dd < -0x1000 && speakState->orbitAngleOffset < 0))
        {
            speakState->orbitAngleOffset = -speakState->orbitAngleOffset;
        }
    }

    fn_8010DB7C(target, va, vb, vc);
    camcontrol_traceMove(&camera->anim.worldPosX, va, (void*)&speakState->cameraX, vd, 3, 1, 1,
                         lbl_803E1A20);
}

extern CameraModeTitlePose lbl_803A4420;
extern f32 lbl_803E1BE8;
extern f32 lbl_803E1BEC;
extern f32 lbl_803E1BF0;
extern f32 lbl_803E1BF4;
extern f32 lbl_803E1BF8;
extern f32 lbl_803E1BFC;
extern f32 lbl_803E1C00;

/* CameraModeTitle_update  addr=0x801116E0  size=0x58C  linkage=global */
void CameraModeTitle_update(CameraObject* camera)
{
    if (lbl_803DD5D0 != 0)
    {
        lbl_803A4420.x = camera->anim.localPosX;
        lbl_803A4420.y = camera->anim.localPosY;
        lbl_803A4420.z = camera->anim.localPosZ;
        lbl_803A4420.yaw = camera->anim.rotX;
        lbl_803A4420.pitch = camera->anim.rotY;
        lbl_803A4420.roll = camera->anim.rotZ;
        lbl_803DD5D0 = 0;
    }
    if (lbl_803DD5D2 != lbl_803DD5D1)
    {
        u8* save = getSaveFileStruct();
        f32 v;

        titleScreenCamProgress = titleScreenCamProgress + lbl_803E1BE8;
        if (titleScreenCamProgress >= lbl_803E1BE0)
        {
            if (lbl_803DD5D2 == 4)
            {
                Movie_SetVolumeFade(100, 1);
                audioSetVolumes(0, 10, 1, 0, 0);
                Music_Trigger(0xbe, 0);
                Music_Trigger(0xc1, 0);
            }
            else if (lbl_803DD5D1 == 4)
            {
                Movie_SetVolumeFade(0, 1);
                audioSetVolumes(*(u8*)(save + 10), 10, 1, 0, 0);
            }
            titleScreenCamProgress = lbl_803E1BE0;
            lbl_803DD5D1 = lbl_803DD5D2;
        }
        else
        {
            if (lbl_803DD5D2 == 4)
            {
                Movie_SetVolumeFade((s32)(lbl_803E1BEC * titleScreenCamProgress), 1);
                audioSetVolumes(
                    (s32)((f32)(u32) * (u8*)(save + 10) * (lbl_803E1BE0 - titleScreenCamProgress)), 10, 1, 0,
                    0);
            }
            else if (lbl_803DD5D1 == 4)
            {
                Movie_SetVolumeFade((s32)(lbl_803E1BEC * (lbl_803E1BE0 - titleScreenCamProgress)), 1);
                audioSetVolumes((s32)((f32)(u32) * (u8*)(save + 10) * titleScreenCamProgress), 10, 1, 0, 0);
            }
        }

        if (titleScreenCamProgress < lbl_803E1BF0)
        {
            v = lbl_803E1BF0 *
                ((lbl_803E1BF4 * titleScreenCamProgress) * (lbl_803E1BF4 * titleScreenCamProgress));
        }
        else
        {
            f32 w = -(lbl_803E1BF4 * (titleScreenCamProgress - lbl_803E1BF0) - lbl_803E1BE0);
            w = w * w;
            v = lbl_803E1BF0 * (lbl_803E1BE0 - w) + lbl_803E1BF0;
        }
        v = v * ((lbl_803E1BFC * v) * v) + (lbl_803E1BF0 * v + (lbl_803E1BF8 * v) * v);

        camera->anim.localPosX =
            v * (lbl_80319FB8[lbl_803DD5D2].x - lbl_803A4420.x) + lbl_803A4420.x;
        camera->anim.localPosY =
            v * (lbl_80319FB8[lbl_803DD5D2].y - lbl_803A4420.y) + lbl_803A4420.y;
        camera->anim.localPosZ =
            v * (lbl_80319FB8[lbl_803DD5D2].z - lbl_803A4420.z) + lbl_803A4420.z;

        {
            u16 sy = lbl_803A4420.yaw;
            u16 ty = lbl_80319FB8[lbl_803DD5D2].yaw;
            int d = ty - sy;
            if (__fabs((f32)d) > lbl_803E1C00)
            {
                int d2 = (s16)ty - (s16)sy;
                camera->anim.rotX = (s16)(s32)(v * (f32)d2 + (f32)(s16)sy);
            }
            else
            {
                *(u16*)&camera->anim.rotX = v * (f32)d + (f32)sy;
            }
        }
        {
            u16 sy = lbl_803A4420.pitch;
            u16 ty = lbl_80319FB8[lbl_803DD5D2].pitch;
            int d = ty - sy;
            if (__fabs((f32)d) > lbl_803E1C00)
            {
                int d2 = (s16)ty - (s16)sy;
                camera->anim.rotY = (s16)(s32)(v * (f32)d2 + (f32)(s16)sy);
            }
            else
            {
                *(u16*)&camera->anim.rotY = v * (f32)d + (f32)sy;
            }
        }
        {
            u16 sy = lbl_803A4420.roll;
            u16 ty = lbl_80319FB8[lbl_803DD5D2].roll;
            int d = ty - sy;
            if (__fabs((f32)d) > lbl_803E1C00)
            {
                int d2 = (s16)ty - (s16)sy;
                camera->anim.rotZ = (s16)(s32)(v * (f32)d2 + (f32)(s16)sy);
            }
            else
            {
                *(u16*)&camera->anim.rotZ = v * (f32)d + (f32)sy;
            }
        }
    }
}

extern int arwarwing_isDead(int state);
extern int arwarwing_isExplodingOrWarping(int state);
extern f32 lbl_803E1BA0;
extern f32 lbl_803E1BA8;
extern f32 lbl_803E1BAC;
extern f32 lbl_803E1BB0;

/* CameraModeArwing_update  addr=0x80110EC4  size=0x5FC  linkage=global */
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

extern int ObjList_FindObjectById(int id);
extern int getButtonsHeld(int pad);
extern int getButtonsJustPressed(int pad);
extern int padGetCX(int pad);
extern int padGetCY(int pad);
extern int isWidescreen(void);
extern void fn_8012DDB8(int mode);
extern f32 lbl_80319DF8[];
extern f32 lbl_803E1A2C;
extern f32 lbl_803E1A30;
extern f32 lbl_803E1A34;
extern f32 lbl_803E1A38;
extern f32 lbl_803E1A3C;
extern f32 lbl_803E1A44;
extern f32 lbl_803E1A48;
extern f32 lbl_803E1A4C;
extern f32 lbl_803E1A50;
extern f32 lbl_803E1A54;
extern f32 lbl_803E1A58;
extern f32 lbl_803E1A5C;
extern f32 lbl_803E1A60;
extern f32 lbl_803E1A64;
extern f32 lbl_803E1A68;
extern f32 lbl_803E1A6C;

/* CameraModeWorldMap_update  addr=0x8010E5B4  size=0xC8C  linkage=global */
void CameraModeWorldMap_update(u8* obj)
{
    extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int mtx); /* #57 */
    GameObject* camera = (GameObject*)obj;
    GameObject* focus;
    GameObject *objA, *objB;
    int buttons;
    f32 spd = lbl_803E1A28;
    f32 mdx, mdz;
    s16 e;

    focus = (GameObject*)camera->anim.targetObj;
    objA = (GameObject*)ObjList_FindObjectById(0x42fff);
    objB = (GameObject*)ObjList_FindObjectById(0x4325b);
    buttons = (u16)getButtonsHeld(0);
    getButtonsJustPressed(0);

    switch (lbl_803DD588->mode)
    {
    case 0:
        if (lbl_803DD588->previousMode != lbl_803DD588->mode)
        {
            lbl_803DD588->focusBlendTimer = 1;
            (*gScreenTransitionInterface)->start(0xc, 1);
            lbl_803DD588->settleFrames = 2;
            lbl_803DD588->flags.transitionActive = 1;
        }
        else
        {
            s16 dYaw, dPitch;
            if (lbl_803DD588->flags.transitionActive != 0 &&
                (*gScreenTransitionInterface)->isFinished() != 0)
            {
                fn_8012DDB8(0);
                (*gScreenTransitionInterface)->step(0xc, 1);
                lbl_803DD588->flags.transitionActive = 0;
                *(u8*)(*(int*)(ObjList_FindObjectById(0x43077) + 0xb8) + 0x27d) = 0;
            }
            if (lbl_803DD588->flags.transitionActive == 0)
            {
                lbl_803DD588->settleFrames -= 1;
                if (lbl_803DD588->settleFrames < 1)
                {
                    lbl_803DD588->settleFrames = 1;
                }
                if (buttons & 8)
                {
                    spd = lbl_803E1A2C * lbl_803DD588->distance;
                }
                if (buttons & 4)
                {
                    spd = lbl_803E1A30 * lbl_803DD588->distance;
                }
                {
                    f32 a, b, rate, vel;
                    if (spd < lbl_803E1A28)
                    {
                        a = -spd;
                    }
                    else
                    {
                        a = spd;
                    }
                    vel = lbl_803DD588->distanceVelocity;
                    if (vel < lbl_803E1A28)
                    {
                        b = -vel;
                    }
                    else
                    {
                        b = vel;
                    }
                    if (b > a)
                    {
                        rate = lbl_803E1A34;
                    }
                    else
                    {
                        rate = lbl_803E1A38;
                    }
                    lbl_803DD588->distanceVelocity =
                        rate * (spd - vel) + lbl_803DD588->distanceVelocity;
                }
                lbl_803DD588->distance = lbl_803DD588->distance + lbl_803DD588->distanceVelocity;
                if (lbl_803DD588->distance < lbl_803E1A3C)
                {
                    lbl_803DD588->distance = lbl_803E1A3C;
                }
                if (lbl_803DD588->distance > lbl_803E1A40)
                {
                    lbl_803DD588->distance = lbl_803E1A40;
                }
                dYaw = (s16)((s8)padGetCX(0) * 3);
                dPitch = (s16)((s8)padGetCY(0) * 3);
                if (lbl_803DD588->focusBlendTimer != 0)
                {
                    GameObject* f = (GameObject*)ObjList_FindObjectById(lbl_803DD588->focusObjectId);
                    f32 dx = f->anim.worldPosX - objA->anim.worldPosX;
                    f32 dz = f->anim.worldPosZ - objA->anim.worldPosZ;
                    s16 d;
                    f32 cur;
                    lbl_803DD588->targetAngle = (s16)(0x8000 - getAngle(dx, dz));
                    d = (s16)(lbl_803DD588->targetAngle - (u16)camera->anim.rotX);
                    if (d > 0x8000)
                    {
                        d = (s16)(d - 0xffff);
                    }
                    if (d < -0x8000)
                    {
                        d += 0xffff;
                    }
                    camera->anim.rotX = camera->anim.rotX + d / lbl_803DD588->focusBlendTimer;
                    lbl_803DD588->targetAngle =
                        (s16)(0x47d0 - getAngle(sqrtf(dx * dx + dz * dz),
                                                f->anim.worldPosY - objA->anim.worldPosY));
                    d = (s16)(lbl_803DD588->targetAngle - (u16)camera->anim.rotY);
                    if (d > 0x8000)
                    {
                        d = (s16)(d - 0xffff);
                    }
                    if (d < -0x8000)
                    {
                        d += 0xffff;
                    }
                    camera->anim.rotY = camera->anim.rotY + d / lbl_803DD588->focusBlendTimer;
                    cur = lbl_803DD588->distance;
                    lbl_803DD588->distance =
                        cur + (f32)((s16)(s32)(lbl_803E1A44 - cur) /
                            (s32)lbl_803DD588->focusBlendTimer);
                    lbl_803DD588->focusBlendTimer -= 1;
                }
                camera->anim.rotX += dYaw;
                camera->anim.rotY += dPitch;
                if (camera->anim.rotY > 12000)
                {
                    camera->anim.rotY = 12000;
                }
                if (camera->anim.rotY < -12000)
                {
                    camera->anim.rotY = -12000;
                }
                {
                    f32 snYaw, csYaw, snPit, csPit;
                    f32 r, vy, h, px, pz;
                    f32 dxx, dyy, dzz;
                    snYaw = -mathCosf(lbl_803E1A48 * (f32)camera->anim.rotX / lbl_803E1A4C);
                    csYaw = mathSinf(lbl_803E1A48 * (f32)camera->anim.rotX / lbl_803E1A4C);
                    snPit = mathCosf(lbl_803E1A48 * (f32)(camera->anim.rotY + 0x320) / lbl_803E1A4C);
                    csPit = mathSinf(lbl_803E1A48 * (f32)(camera->anim.rotY + 0x320) /
                        lbl_803E1A4C);
                    r = lbl_803DD588->distance;
                    vy = r * csPit;
                    h = r * snPit;
                    px = h * csYaw;
                    pz = h * snYaw;
                    dxx = camera->anim.worldPosX - (focus->anim.worldPosX + px);
                    dyy = camera->anim.worldPosY - ((lbl_803E1A50 + focus->anim.worldPosY) + vy);
                    dzz = camera->anim.worldPosZ - (focus->anim.worldPosZ + pz);
                    camera->anim.worldPosX =
                        camera->anim.worldPosX - dxx / (f32)lbl_803DD588->settleFrames;
                    camera->anim.worldPosY =
                        camera->anim.worldPosY - dyy / (f32)lbl_803DD588->settleFrames;
                    camera->anim.worldPosZ =
                        camera->anim.worldPosZ - dzz / (f32)lbl_803DD588->settleFrames;
                }
            }
        }
        break;
    case 1:
        {
            GameObject* g = (GameObject*)ObjList_FindObjectById(0x43077);
            if (lbl_803DD588->previousMode != lbl_803DD588->mode)
            {
                (*gScreenTransitionInterface)->start(0xc, 1);
                lbl_803DD588->settleFrames = 2;
                lbl_803DD588->flags.transitionActive = 1;
            }
            else
            {
                if (lbl_803DD588->flags.transitionActive != 0 &&
                    (*gScreenTransitionInterface)->isFinished() != 0)
                {
                    fn_8012DDB8(1);
                    (*gScreenTransitionInterface)->step(0xc, 1);
                    lbl_803DD588->flags.transitionActive = 0;
                    *(u8*)(*(int*)(ObjList_FindObjectById(0x43077) + 0xb8) + 0x27d) = 1;
                }
                if (lbl_803DD588->flags.transitionActive == 0)
                {
                    int ang;
                    s16 d;
                    u16 my;
                    lbl_803DD588->settleFrames -= 1;
                    if (lbl_803DD588->settleFrames < 1)
                    {
                        lbl_803DD588->settleFrames = 1;
                    }
                    ang = (u16) - getAngle(objA->anim.worldPosX - focus->anim.worldPosX,
                                           objA->anim.worldPosZ - focus->anim.worldPosZ);
                    d = (s16)((ang - 0x308f) - (u16)camera->anim.rotX);
                    if (d > 0x8000)
                    {
                        d = (s16)(d - 0xffff);
                    }
                    if (d < -0x8000)
                    {
                        d += 0xffff;
                    }
                    camera->anim.rotX = camera->anim.rotX + d / lbl_803DD588->settleFrames;
                    d = (s16)(0x7d0 - (u16)camera->anim.rotY);
                    if (d > 0x8000)
                    {
                        d = (s16)(d - 0xffff);
                    }
                    if (d < -0x8000)
                    {
                        d += 0xffff;
                    }
                    camera->anim.rotY = camera->anim.rotY + d / lbl_803DD588->settleFrames;
                    {
                        f32 a, sn, cs, sn54, cs54;
                        f32 t6, t5, px, pz;
                        f32 dxx, dyy, dzz;
                        a = lbl_803E1A48 * (f32)(u16)(ang - 0x39dc) / lbl_803E1A4C;
                        sn = -mathCosf(a);
                        cs = mathSinf(a);
                        sn54 = mathCosf(lbl_803E1A54);
                        cs54 = mathSinf(lbl_803E1A54);
                        t6 = lbl_803E1A58 * cs54;
                        t5 = lbl_803E1A58 * sn54;
                        px = t5 * cs;
                        pz = t5 * sn;
                        dxx = camera->anim.worldPosX - (focus->anim.worldPosX + px);
                        dyy = camera->anim.worldPosY -
                            (lbl_803E1A5C + (focus->anim.worldPosY + t6));
                        dzz = camera->anim.worldPosZ - (focus->anim.worldPosZ + pz);
                        camera->anim.worldPosX =
                            camera->anim.worldPosX - dxx / (f32)lbl_803DD588->settleFrames;
                        camera->anim.worldPosY =
                            camera->anim.worldPosY - dyy / (f32)lbl_803DD588->settleFrames;
                        camera->anim.worldPosZ =
                            camera->anim.worldPosZ - dzz / (f32)lbl_803DD588->settleFrames;
                    }
                    my = (u16)(camera->anim.rotX + 0x1388);
                    if (isWidescreen() != 0)
                    {
                        my = (u16)(my + 0x514);
                    }
                    {
                        f32 b = lbl_803E1A48 * (f32)my / lbl_803E1A4C;
                        f32 sb = mathCosf(b);
                        f32 cb = -mathSinf(b);
                        g->anim.localPosX = lbl_803E1A60 * cb + camera->anim.worldPosX;
                        g->anim.localPosY =
                            camera->anim.worldPosY + lbl_80319DF8[(s8) * (u8*)&g->anim.bankIndex];
                        g->anim.localPosZ = lbl_803E1A60 * sb + camera->anim.worldPosZ;
                        g->anim.rotX = (s16)(-0xbb8 - my);
                    }
                }
            }
            break;
        }
    }

    lbl_803DD588->previousMode = lbl_803DD588->mode;
    {
        GameObject* marker = (GameObject*)ObjList_FindObjectById(0x431dc);
        mdx = marker->anim.worldPosX - camera->anim.worldPosX;
        mdz = marker->anim.worldPosZ - camera->anim.worldPosZ;
        marker->anim.rotX = (s16)(getAngle(mdx, mdz) + 0x8000);
        marker->anim.rotY = (s16)(0x8000 - getAngle(sqrtf(mdx * mdx + mdz * mdz),
                                                    marker->anim.worldPosY - camera->anim.worldPosY));
        marker->anim.rootMotionScale = lbl_803E1A64 + lbl_803E1A68 / lbl_803DD588->distance;
        objB->anim.rotX = marker->anim.rotX;
        objB->anim.rotY = marker->anim.rotY;
        objB->anim.rootMotionScale = marker->anim.rootMotionScale;
    }

    e = (s16)(objB->anim.rotX - 0x2198);
    if (e > -0x2000 && e < 0x2000)
    {
        f32 lim = lbl_803E1A28;
        if (lbl_803E1A28 <=
            lbl_803E1A6C *
            (mathCosf(lbl_803E1A48 * (f32)((objB->anim.rotX - 0x2198) * 2) / lbl_803E1A4C) *
                mathCosf(lbl_803E1A48 * (f32)((objB->anim.rotY - 0x4000) * 2) / lbl_803E1A4C)))
        {
            lim = lbl_803E1A6C *
            (mathCosf(lbl_803E1A48 * (f32)((objB->anim.rotX - 0x2198) * 2) / lbl_803E1A4C) *
                mathCosf(lbl_803E1A48 * (f32)((objB->anim.rotY - 0x4000) * 2) / lbl_803E1A4C));
        }
        objB->anim.alpha = (s32)lim;
    }
    else
    {
        objB->anim.alpha = 0;
    }

    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}

extern void turnOnBlurFilter(f32 x, f32 y, f32 z, int a, int b);
extern f32 lbl_803DB9C4;

/* CameraModeNpcSpeak_update  addr=0x8010DD58  size=0x298  linkage=global */
void CameraModeNpcSpeak_update(u8* obj)
{
    extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz, int mtx); /* #57 */
    CameraObject* camera = (CameraObject*)obj;
    CameraModeNpcSpeakState* speakState;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    f32 ex, ey, ez;
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
        if (speakState->orbitAngleVelocity > 0 && speakState->orbitAngleOffset > 0xd6d8)
        {
            speakState->orbitAngleOffset = 0xd6d8;
        }
        else if (speakState->orbitAngleVelocity < 0 && speakState->orbitAngleOffset < -0xd6d8)
        {
            speakState->orbitAngleOffset = -0xd6d8;
        }
        fn_8010DB7C(target, &speakState->cameraX, &speakState->cameraY, &speakState->cameraZ);
    }
    camera->anim.worldPosX = speakState->cameraX;
    camera->anim.worldPosY = speakState->cameraY;
    camera->anim.worldPosZ = speakState->cameraZ;
    dx = target->anim.worldPosX - speakState->anchorX;
    dy = (target->anim.worldPosY + speakState->lookAtHeightOffset) - speakState->anchorY;
    dz = target->anim.worldPosZ - speakState->anchorZ;
    dx *= speakState->lookAtXZScale;
    dy *= speakState->lookAtYScale;
    dz *= speakState->lookAtXZScale;
    if (speakState->mode == 3)
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
    if (speakState->mode != 3)
    {
        camera->anim.rotY = (s16)(s32)
        getAngle(ey, sqrtf(ex * ex + ez * ez));
    }
    turnOnBlurFilter(speakState->anchorX, speakState->anchorY, speakState->anchorZ, 1, 0);
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

/* === moved from main/dll/moveLib.c [80113504-80113F8C) (TU re-split, docs/boundary_audit.md) === */
#include "main/objanim.h"
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/moveLib.h"

#include "main/dll/dll19_state.h"


extern undefined4 GameBit_Set(int eventId, int value);


/*
 * --INFO--
 *
 * Function: dll_19_func0F
 * EN v1.0 Address: 0x80113504
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x80113590
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dll_19_func0F(int obj, char* state, char* st, int p4, int p5, s16 p6)
{
    extern int* gPlayerInterface;
    extern f32 lbl_803DD5D8;
    extern s8 lbl_803DD5DC;
    extern f32 lbl_803E1C2C;
    extern f32 lbl_803E1C70;
    extern f32 lbl_803E1C74;
    extern f32 lbl_803E1C6C;
    extern f32 lbl_803E1C5C;
    extern f32 timeDelta;
    extern f32 sqrtf(f32 x);
    extern u8 framesThisStep;
    f32 dist;
    f32 nx;
    f32 nz;
    char* t;

    *(int*)&((BaddieState*)st)->unk318 = 0;
    *(int*)&((BaddieState*)st)->unk31C = 0;
    ((BaddieState*)st)->cameraYaw = 0;
    {
        f32 rest = lbl_803E1C2C;
        ((BaddieState*)st)->moveInputX = rest;
        ((BaddieState*)st)->moveInputZ = rest;
    }
    if ((s8) * (u8*)(state + 0x56) != 1)
    {
        *(f32*)(state + 0x40) = ((GameObject*)obj)->anim.localPosX;
        *(f32*)(state + 0x44) = ((GameObject*)obj)->anim.localPosY;
        *(f32*)(state + 0x48) = ((GameObject*)obj)->anim.localPosZ;
        lbl_803DD5D8 = lbl_803E1C70;
        lbl_803DD5DC = 0;
    }
    *(s16*)(state + 0x6e) = 0;
    *(u8*)(state + 0x56) = 1;
    {
        f32 ex = *(f32*)(state + 0x40) - ((GameObject*)obj)->anim.localPosX;
        f32 ez = *(f32*)(state + 0x48) - ((GameObject*)obj)->anim.localPosZ;
        dist = sqrtf(ex * ex + ez * ez);
    }
    t = *(char**)&((BaddieState*)st)->targetObj;
    if (t == NULL)
    {
        return 0;
    }
    nx = *(f32*)(t + 0xc) - *(f32*)(state + 0x40);
    nz = *(f32*)(t + 0x14) - *(f32*)(state + 0x48);
    {
        f32 total = sqrtf(nx * nx + nz * nz);
        f32 step = timeDelta * (total - dist) * lbl_803E1C74;
        f32 td;
        if (step > lbl_803E1C6C)
        {
            step = lbl_803E1C6C;
        }
        else if (step < lbl_803E1C5C)
        {
            step = lbl_803E1C5C;
        }
        if (dist <= lbl_803DD5D8)
        {
            lbl_803DD5DC = lbl_803DD5DC + 1;
        }
        if (dist >= total || (s8)lbl_803DD5DC > 9)
        {
            char* t2 = *(char**)&((BaddieState*)st)->targetObj;
            int delta = ((GameObject*)obj)->anim.rotX - (u16) * (s16*)t2;
            if (delta > 0x8000)
            {
                delta -= 0xffff;
            }
            if (delta < -0x8000)
            {
                delta += 0xffff;
            }
            if (delta > 0x2000)
            {
                delta = 0x2000;
            }
            if (delta < -0x2000)
            {
                delta = -0x2000;
            }
            ((GameObject*)obj)->anim.rotX -= (s16)((delta * framesThisStep) >> 3);
            if ((s8)lbl_803DD5DC > 10)
            {
                delta = 0;
            }
            if (delta < 0x100 && delta > -0x100)
            {
                *(u8*)(state + 0x56) = 0;
                *(s16*)(state + 0x5a) = (s16)(*(s16*)(state + 0x58) - 1);
            }
            else
            {
                td = timeDelta;
                (*(void (**)(int, char*, f32, f32, int, int))(*gPlayerInterface + 0x8))(
                    obj, st, td, td, p4, p5);
            }
        }
        else
        {
            nx = nx / total;
            nz = nz / total;
            ((BaddieState*)st)->moveInputX = -nx * step;
            ((BaddieState*)st)->moveInputZ = nz * step;
            ((GameObject*)obj)->anim.localPosX = dist * nx + *(f32*)(state + 0x40);
            ((GameObject*)obj)->anim.localPosZ = dist * nz + *(f32*)(state + 0x48);
            td = timeDelta;
            (*(void (**)(int, char*, f32, f32, int, int))(*gPlayerInterface + 0x8))(
                obj, st, td, td, p4, p5);
        }
    }
    lbl_803DD5D8 = dist;
    if ((s8) * (u8*)(state + 0x56) == 0)
    {
        *(u8*)(st + 0x405) = 0;
        ((BaddieState*)st)->controlMode = p6;
        *(int*)&((BaddieState*)st)->targetObj = 0;
        *(s16*)(state + 0x6e) = -1;
        *(s16*)(state + 0x6e) = *(s16*)(state + 0x6e) & ~0x60;
        ((BaddieState*)st)->physicsActive = 0;
        GameBit_Set(*(s16*)(st + 0x3f4), 0);
    }
    return 1;
}


/*
 * --INFO--
 *
 * Function: FUN_801135c0
 * EN v1.0 Address: 0x801135C0
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x80113634
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801141dc
 * EN v1.0 Address: 0x801141DC
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80114230
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801141e8
 * EN v1.0 Address: 0x801141E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80114238
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801141ec
 * EN v1.0 Address: 0x801141EC
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801142B4
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


extern f32 sqrtf(f32 x);

#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801143e8
 * EN v1.0 Address: 0x801143E8
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x801144C0
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801145a8
 * EN v1.0 Address: 0x801145A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801146A4
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801145b0
 * EN v1.0 Address: 0x801145B0
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x80114A58
 * EN v1.1 Size: 864b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801149b8
 * EN v1.0 Address: 0x801149B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80114E4C
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: FUN_801149bc
 * EN v1.0 Address: 0x801149BC
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x80115088
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on

/*
 * --INFO--
 *
 * Function: FUN_80114b10
 * EN v1.0 Address: 0x80114B10
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80115200
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void dll_19_func04_nop(void)
{
}

void dll_19_func03_nop(void)
{
}

/* 8b "li r3, N; blr" returners. */
int dll_19_func09_ret_0(void) { return 0x0; }

/* 12b chained getters. */
f32 dll_19_func0B(int* obj) { return *(f32*)((char*)((int**)obj)[0xb8 / 4] + 0x3e4); }

/* misc 8b leaves */


u16 dll_19_func0A(int obj)
{
    void* p = ((GameObject*)obj)->anim.placementData;
    if (p != NULL) return *(u16*)((char*)p + 0x34);
    return 0xd2;
}







/* EN v1.0 0x80114184  size: 160b  Copies a curve point's position and packed
 * angle into the caller's record. */


/* EN v1.0 0x80114084  size: 256b  Copies a curve point's position into the
 * caller's record and aims its angle at the nearest group-8 object (falling
 * back to the point's packed angle). */

extern f32 timeDelta;
extern f32 lbl_803E1C78;
extern f32 lbl_803E1C2C;
extern f32 lbl_803E1C7C;

/* EN v1.0 0x80113864  size: 248b  Steps the movement blend factors toward the
 * current target and turns the yaw by the buffered turn rate. */
void dll_19_func06(s16* yaw, char* st, f32 cap, f32 speed)
{
    if (*(f32*)(st + 0x298) < lbl_803E1C78)
    {
        f32 rest;
        *(s16*)(st + 0x334) = 0;
        ((BaddieState*)st)->turnRate = 0;
        rest = lbl_803E1C2C;
        *(f32*)(st + 0x298) = rest;
        ((BaddieState*)st)->animSpeedA = rest;
    }
    ((BaddieState*)st)->animSpeedB = lbl_803E1C2C;
    *yaw = lbl_803E1C7C * ((f32)((BaddieState*)st)->turnRate * timeDelta / speed) + (f32) * yaw;
    ((BaddieState*)st)->animSpeedC +=
        timeDelta * ((*(f32*)(st + 0x298) - ((BaddieState*)st)->animSpeedC) / *(f32*)(st + 0x2b8));
    ((BaddieState*)st)->animSpeedA +=
        timeDelta * ((*(f32*)(st + 0x298) - ((BaddieState*)st)->animSpeedA) / *(f32*)(st + 0x2b8));
    if (((BaddieState*)st)->animSpeedC > cap)
    {
        ((BaddieState*)st)->animSpeedC = cap;
    }
    if (((BaddieState*)st)->animSpeedA > cap)
    {
        ((BaddieState*)st)->animSpeedA = cap;
    }
}


/* EN v1.0 0x80114F64  size: 280b  Initializes the movement-state block and
 * primes the animation channel tables. */


/* EN v1.0 0x80114DEC  size: 376b  Latches the path-relative start offset on
 * first use and refreshes the current path point position. */

extern s16 getAngle(f32 x, f32 z);

/* EN v1.0 0x80113BD0  size: 396b  Computes the yaw step, signed yaw delta and
 * distance from an object to its target, updating the wide-turn flag. */
void dll_19_func07(int obj, int target, int div, u16* outYaw, u16* outDelta, u16* outDist)
{
    char* st = ((GameObject*)obj)->extra;
    f32 d[3];
    f32* dp = d;
    s16* ovr;
    u16 ang;
    int cur;
    int delta;

    if ((void*)obj == NULL || (void*)target == NULL)
    {
        *outYaw = 0;
        *outDelta = 0;
        *outDist = 0;
    }
    else
    {
        dp[0] = *(f32*)(target + 0x18) - ((GameObject*)obj)->anim.worldPosX;
        dp[1] = *(f32*)(target + 0x1c) - ((GameObject*)obj)->anim.worldPosY;
        dp[2] = *(f32*)(target + 0x20) - ((GameObject*)obj)->anim.worldPosZ;
        ang = getAngle(-dp[0], -dp[2]);
        ovr = *(s16**)&((GameObject*)obj)->anim.parent;
        if (ovr != NULL)
        {
            cur = (s16)(((GameObject*)obj)->anim.rotX + *ovr);
        }
        else
        {
            cur = ((GameObject*)obj)->anim.rotX;
        }
        delta = ang - (u16)(s16)
        cur;
        if (delta > 0x8000)
        {
            delta -= 0xffff;
        }
        if (delta < -0x8000)
        {
            delta += 0xffff;
        }
        *outDelta = (u16)delta;
        if ((u16)delta < 0x31c4 || (u16)delta > 0xce3b)
        {
            ((Dll19State*)st)->unk400 &= ~0x10;
        }
        else
        {
            ((Dll19State*)st)->unk400 |= 0x10;
        }
        *outYaw = (u16)delta / (0x10000 / (u8)div);
        *outDist = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
    }
}

extern void voxmaps_worldToGrid(f32* world, int* grid);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern const f32 lbl_803E1C80;
extern const f32 lbl_803E1C84;
extern f32 lbl_803E1C48;

/* EN v1.0 0x80113D64  size: 544b  Probes the four compass directions around
 * the object for walkable space, returning a bitmask of clear directions. */
u8 dll_19_func08(int obj, char* st, f32 dist)
{
    extern const f32 lbl_803E1C68; /* #57 */
    extern int objBboxFn_800640cc(void* pos, f32* world, f32 rad, int a, void* out, int obj, int b, int c, int d, int e); /* #57 */
    extern u8 voxmaps_traceLine(int* from, int* to, int a, u8* outFlag, int b); /* #57 */
    u16 i;
    u8 mask;
    u8 hitFlag;
    int grid1[2];
    int grid0[2];
    f32 world[3];
    u8 bboxOut[0x54];
    int cur;
    s16* ovr;
    u8 ok;
    f32 a;

    mask = 0;
    world[0] = ((GameObject*)obj)->anim.localPosX;
    world[1] = lbl_803E1C68 + ((GameObject*)obj)->anim.localPosY;
    world[2] = ((GameObject*)obj)->anim.localPosZ;
    voxmaps_worldToGrid(world, grid0);
    ovr = *(s16**)&((GameObject*)obj)->anim.parent;
    if (ovr != NULL)
    {
        cur = (s16)(((GameObject*)obj)->anim.rotX + *ovr);
    }
    else
    {
        cur = ((GameObject*)obj)->anim.rotX;
    }
    for (i = 0; i < 4; i++)
    {
        a = lbl_803E1C80 * (f32)((s16)cur + (i << 14)) / lbl_803E1C84;
        world[0] = ((GameObject*)obj)->anim.localPosX - dist * mathSinf(a);
        world[1] = lbl_803E1C68 + ((GameObject*)obj)->anim.localPosY;
        world[2] = ((GameObject*)obj)->anim.localPosZ - dist * mathCosf(a);
        voxmaps_worldToGrid(world, grid1);
        if (((GameObject*)obj)->anim.parent != NULL)
        {
            ok = 1;
        }
        else
        {
            ok = (u8)voxmaps_traceLine(grid1, grid0, 0, &hitFlag, 0);
            if (hitFlag == 1)
            {
                ok = 1;
            }
        }
        if (ok != 0)
        {
            if (objBboxFn_800640cc((char*)(obj + 0xc), world, lbl_803E1C48, 0, bboxOut, obj,
                                   *(u8*)(st + 0x261), -1, 0, 0) != 0)
            {
                ok = 0;
            }
        }
        mask |= ok << i;
    }
    return mask;
}


/* EN v1.0 0x801145BC  size: 512b  Advances the object along its movement
 * curve, snapping to ground and easing the yaw toward the path direction. */

extern u8 framesThisStep;

/* EN v1.0 0x80114BB0  size: 572b  Object-sequence scripted-move step: phase 4
 * arms the move, phase 5 walks the setup/playback sub-phases. */

extern f32 lbl_803E1C40;

/* EN v1.0 0x8011395C  size: 628b  Constrains a follow point against the
 * object's facing plane and returns the lateral offset of the result. */
f32 dll_19_func05(int obj, f32 px, f32 pz, f32 range, char* st)
{
    extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, u32 obj); /* #57 */
    f32 dist;
    f32 fz;
    f32 fx;
    f32 c;
    f32 s;
    f32 dx;
    f32 dz;

    dx = *(f32*)(st + 0x18) - px;
    dz = *(f32*)(st + 0x20) - pz;
    dist = sqrtf(dx * dx + dz * dz);
    if (dist < range)
    {
        f32 base;
        f32 d1;
        f32 d2;
        c = mathSinf(lbl_803E1C80 * (f32)((GameObject*)obj)->anim.rotX / lbl_803E1C84);
        s = mathCosf(lbl_803E1C80 * (f32)((GameObject*)obj)->anim.rotX / lbl_803E1C84);
        base = -(c * (px - c) + s * (pz - s));
        d1 = base + (c * *(f32*)(st + 0x18) + s * *(f32*)(st + 0x20));
        d2 = base + (c * *(f32*)(st + 0x8c) + s * *(f32*)(st + 0x94));
        if (d1 > lbl_803E1C2C && d2 <= lbl_803E1C48)
        {
            *(f32*)(st + 0x18) = *(f32*)(st + 0x18) - c * d1;
            *(f32*)(st + 0x20) = *(f32*)(st + 0x20) - s * d1;
            Obj_TransformWorldPointToLocal(*(f32*)(st + 0x18), *(f32*)(st + 0x1c),
                                           *(f32*)(st + 0x20), (f32*)(st + 0xc),
                                           (f32*)(st + 0x10), (f32*)(st + 0x14),
                                           *(u32*)(st + 0x30));
        }
        else if (d2 > lbl_803E1C48)
        {
            dist = lbl_803E1C40 * range;
        }
    }
    if (dist < range)
    {
        fx = *(f32*)(st + 0x18);
        fz = *(f32*)(st + 0x20);
    }
    else
    {
        fx = px;
        fz = pz;
    }
    c = mathSinf(lbl_803E1C80 * (f32)(((GameObject*)obj)->anim.rotX + 0x4000) / lbl_803E1C84);
    s = mathCosf(lbl_803E1C80 * (f32)(((GameObject*)obj)->anim.rotX + 0x4000) / lbl_803E1C84);
    return -(-(((GameObject*)obj)->anim.localPosX * c + ((GameObject*)obj)->anim.localPosZ * s) + (c * fx + s * fz));
}


/* EN v1.0 0x801147BC  size: 864b  Homes the object toward its target at the
 * given speed, snapping when close, easing yaw and pacing the walk anim. */


/* === helper-last relocation (re-split inline suppression; defs moved below their callers to suppress cross-TU-merge auto-inlining) === */
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
        f32 scale = state->anchorLerpScale;
        dx *= scale;
        dz *= scale;
    }
    dx += state->anchorX;
    dz += state->anchorZ;

    cosVal = mathSinf(lbl_803E19D0 * (f32)(s32)(angle + state->orbitAngleOffset) / lbl_803E19D4);
    sinVal = mathCosf(lbl_803E19D0 * (f32)(s32)(angle + state->orbitAngleOffset) / lbl_803E19D4);

    if (dist < state->minDistance)
    {
        dist = state->minDistance;
    }
    dist += state->distanceOffset;

    *outX = cosVal * dist + dx;
    *outY = (target->anim.worldPosY + state->targetHeightOffset) - lbl_803E19D8 * ((lbl_803E19DC + target->anim.
        worldPosY) - state->anchorY);
    *outZ = sinVal * dist + dz;
}
