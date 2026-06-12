/* === moved from main/dll/CAM/camDebug.c [8010DB7C-8010DD58) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/CAM/camnpcspeak_state.h"
#include "main/game_object.h"
#include "main/mm.h"

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

void CameraModeWorldMap_release(void);

void CameraModeWorldMap_initialise(void);

void dll_4F_func06_nop(void);

void dll_4F_release_nop(void);

void dll_4F_initialise_nop(void);

void CameraModeCrawl_release(void);

void CameraModeCrawl_initialise(void);

void CameraModeCannon_copyToCurrent_nop(void);

void CameraModeCannon_release(void);

void CameraModeCannon_initialise(void);

void CameraModeForceBehind_func06_nop(void)
{
}

void CameraModeForceBehind_func05_nop(void)
{
}

void CameraModeForceBehind_release(void);

void CameraModeForceBehind_initialise(void);

void fn_801101E4(void)
{
}

void CameraModeCloudRunner_release(void);

void CameraModeCloudRunner_initialise(void);

void dll_54_func06_nop(void);

void dll_54_release_nop(void);

void dll_54_initialise_nop(void);

void fn_80110C80(void)
{
}

void CameraModePerv_release(void);

void CameraModePerv_initialise(void);

void fn_80110EC0(void)
{
}

void CameraModeArwing_release(void);

void CameraModeArwing_initialise(void);

void CameraModeTitle_release(void);

void CameraModeTitle_initialise(void);

void CameraModeForceBehind_copyToCurrent(void);

void CameraModeForceBehind_free(void);

void CameraModeCloudRunner_copyToCurrent(void);

void CameraModePerv_copyToCurrent(void);

void CameraModeArwing_free(void);

extern void* memset(void* dst, int val, u32 n);
extern void audioSetVolumes(int volume, int p1, int p2, int p3, int p4);
extern f32 lbl_803E1A88;
extern CameraMode4FState* lbl_803DD590;
extern CameraModeCrawlState* lbl_803DD598;

void CameraModeTitle_loadVolumes(void);

void dll_4F_init(void);

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

void dll_4F_update(int* obj);

void CameraModeCrawl_init(void);

extern CameraModeCannonState* lbl_803DD5A0;
extern CameraModePervState* lbl_803DD5C8;
extern f32 lbl_803E1B98;
extern f32 lbl_803E1B9C;
extern CameraModeWorldMapState* lbl_803DD588;

void CameraModePerv_init(int* obj);

void CameraModeCannon_init(int* p1, int unused, int* p3);

extern f32 lbl_803E1A40;
extern f32 lbl_803E1A28;
extern f32 lbl_803E1A80;

void CameraModeWorldMap_init(int* obj);

void CameraModeWorldMap_copyToCurrent(int* p1, int kind);

extern f32 lbl_803A43C0[];

void CameraModeArwing_copyToCurrent(void* p1, u32 kind);

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
void CameraModeArwing_init(int* obj, int mode, int unused);
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

void CameraModeTitle_init(CameraObject* camera);

extern CameraMode54State* lbl_803DD5C0;
extern f32 lbl_803E1B5C;

void dll_54_init(int* p1, int unused, int* p3);

int dll_19_func1B(int p);

extern void Sfx_StopObjectChannel(int* p1, int channel);
extern void voxmaps_freeRouteWork(void* p);

void dll_19_func12(int* p1, int* p2, u8 flag);

extern CameraModeCloudRunnerState* lbl_803DD5B8;

void CameraModeCloudRunner_init(int* p1, int p2, f32* p3);

extern f32 lbl_803E1BE4;
extern void Movie_SetVolumeFade(int p1, int p2);
extern void Music_Trigger(int id, int mode);

void CameraModeTitle_moveCam(u8 newCam);

/* misc 8b leaves */
f32 titleScreenGetCamProgress(void);

/* fn_X(lbl); lbl = 0; */
void CameraModeWorldMap_free(void);

void dll_4F_func05(void);

void CameraModeCrawl_free(void);

void CameraModeCannon_free(void);

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void CameraModeCloudRunner_free(void);

void dll_54_func05(void);

void CameraModePerv_free(void);

void dll_19_func11(void);

/* baddie spawn/visibility predicate */
extern int objPosToMapBlockIdx(double x, double y, double z);

int dll_19_func0E(int p1, int p2, u8 b);

/* compute progress ratio (signed numerator / unsigned denominator) */
extern f32 lbl_803E1C2C;

f32 dll_19_func1A(int obj);

/* baddie state reset */
extern void ObjHits_SetHitVolumeSlot(void* obj, int animObjId, int frame, int flags);

void dll_19_func0D(int p1, int p2, f32 fval, s8 b);

extern void Obj_FreeObject(void* obj);
extern u8 Obj_IsLoadingLocked(void);
extern ObjPlacement* Obj_AllocObjectSetup(int size, int id);
extern GameObject* Obj_SetupObject(ObjPlacement* setup, int mode, int mapLayer, int objIndex, int parent);
extern u8 lbl_802C2190[];

/* dll_19_func19  addr=0x80111EB4  size=0x100  linkage=global */
void dll_19_func19(u8* cam, u8* ctx);


extern int* gPlayerInterface;

/* dll_19_func0C  addr=0x80112D80  size=0x114  linkage=global */
#pragma dont_inline on
void dll_19_func0C(int p1, u8* p2, u8* p3, s16 p4, u8* p5, s16 p6, s16 p7, int p8, s8 p9);
#pragma dont_inline reset

extern f32 lbl_803E1B78;
extern f32 lbl_803E1B7C;
extern f32 lbl_803E1B80;
extern f32 lbl_803E1B84;
extern f32 lbl_803E1B88;

/* CameraModePerv_update  addr=0x80110CB0  size=0x10C  linkage=global */
void CameraModePerv_update(u8* obj);

extern f32 lbl_803E1B00;
extern f32 lbl_803E1B04;
extern f32 lbl_803E1B08;
extern f32 lbl_803E1B1C;
extern f32 lbl_803DB9C8;
extern f32 lbl_803DD5AC;
extern f32 lbl_803DD5B0;

extern f32 lbl_803DD5A8;
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern void fn_8029697C(int state, s16* a, s16* b);
extern f32 lbl_803E1B18;


/* CameraModeForceBehind_init  addr=0x801100B8  size=0x124  linkage=global */
void CameraModeForceBehind_init(u8* obj, int p2, f32* p3);

extern int Obj_GetPlayerObject(void);
extern int fn_80295A04(int obj, int a);
extern int fn_80296AE8(int obj);
extern f32 lbl_803E1C48;

/* dll_19_func13  addr=0x8011313C  size=0x13C  linkage=global */
int dll_19_func13(int p1, u8* p2, f32 f, int p4);

extern f32 lbl_803E1C6C;

/* dll_19_func10  addr=0x80113398  size=0x16C  linkage=global */
int dll_19_func10(int p1, u8* p2, int p3, int p4, s16 p5, f32* p6, f32* p7, int* p8);

extern f32 lbl_803E1AC0;
extern f32 lbl_803E1AC4;

/* CameraModeCrawl_copyToCurrent  addr=0x8010F540  size=0x1E0  linkage=global */
void CameraModeCrawl_copyToCurrent(void* param1, int param2);

/* dll_19_func17  addr=0x80112544  size=0x19C  linkage=global */
int dll_19_func17(int p1, u8* p2, u8* p3, s16 p4, u8* p5, s16 p6, s16 p7, s16 p8);

extern s16* objModelGetVecFn_800395d8(int obj, int idx);
extern f32 lbl_803E1AE0;
extern f32 lbl_803E1AE4;
extern f32 lbl_803E1AE8;
extern f32 lbl_803E1AEC;
extern f32 lbl_803E1AF0;

/* CameraModeCannon_update  addr=0x8010FA84  size=0x168  linkage=global */
void CameraModeCannon_update(u8* obj);

extern f32 fn_8029610C(int obj);
extern void voxmaps_worldToGrid(f32* pos, int* grid);
extern f32 lbl_803E1C64;

/* dll_19_func14  addr=0x80112E94  size=0x2A8  linkage=global */
int dll_19_func14(u8* p1, u8* p2, f32 frange, int p4);

extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E1C30;
extern f32 lbl_803E1C40;
extern f32 lbl_803E1C44;
extern f32 lbl_803E1C4C;
extern f32 lbl_803E1C50;

/* dll_19_func16  addr=0x801126E0  size=0x348  linkage=global */
int dll_19_func16(u8* p1, u8* p2, int p3, int p4, int* p5, u8* p6, s16 p7, u8* p8);

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
int dll_19_func15(u8* p1, int p2, int p3, int p4);

extern int GameBit_Get(int bit);
extern void voxmaps_allocRouteWork(u8 * work);
extern u32 lbl_803E1C28;
extern f32 lbl_803E1C38;
extern u8 lbl_8031A054[];
extern u8 lbl_8031A048[];
extern u32 lbl_803DB9E0;
extern u32 lbl_803DD5E0;

/* dll_19_func18  addr=0x80112098  size=0x47C  linkage=global */
void dll_19_func18(int p1, u8* p2, u8* p3, int p4, int p5, int p6, f32 fparam, int p7);

extern f32 lbl_803E1AD0;
extern f32 lbl_803E1AD4;
extern f32 lbl_803E1AD8;
extern f32 lbl_803E1ADC;

/* CameraModeCrawl_update  addr=0x8010F74C  size=0x2B8  linkage=global */
void CameraModeCrawl_update(u8* obj);

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
void CameraModeCloudRunner_update(u8* obj);


/* CameraModeForceBehind_update  addr=0x8010FC7C  size=0x43C  linkage=global */
void CameraModeForceBehind_update(u8* obj);

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
void dll_54_update(u8* obj);

extern int getFocusedNpc(void);
extern int randomGetRange(int lo, int hi);
extern void fn_8010DB7C(GameObject * target, f32 * a, f32 * b, f32 * c);
extern f32 lbl_803E19E8;
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
void CameraModeTitle_update(CameraObject* camera);

extern int arwarwing_isDead(int state);
extern int arwarwing_isExplodingOrWarping(int state);
extern f32 lbl_803E1BA0;
extern f32 lbl_803E1BA8;
extern f32 lbl_803E1BAC;
extern f32 lbl_803E1BB0;

/* CameraModeArwing_update  addr=0x80110EC4  size=0x5FC  linkage=global */
void CameraModeArwing_update(u8* obj);

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
void CameraModeWorldMap_update(u8* obj);

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

#include "main/dll/dll19_state.h"




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
int dll_19_func0F(int obj, char* state, char* st, int p4, int p5, s16 p6);


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
void dll_19_func04_nop(void);

void dll_19_func03_nop(void);

/* 8b "li r3, N; blr" returners. */
int dll_19_func09_ret_0(void);

/* 12b chained getters. */
f32 dll_19_func0B(int* obj);

/* misc 8b leaves */


u16 dll_19_func0A(int obj);







/* EN v1.0 0x80114184  size: 160b  Copies a curve point's position and packed
 * angle into the caller's record. */


/* EN v1.0 0x80114084  size: 256b  Copies a curve point's position into the
 * caller's record and aims its angle at the nearest group-8 object (falling
 * back to the point's packed angle). */

extern f32 lbl_803E1C78;
extern f32 lbl_803E1C7C;

/* EN v1.0 0x80113864  size: 248b  Steps the movement blend factors toward the
 * current target and turns the yaw by the buffered turn rate. */
void dll_19_func06(s16* yaw, char* st, f32 cap, f32 speed);


/* EN v1.0 0x80114F64  size: 280b  Initializes the movement-state block and
 * primes the animation channel tables. */


/* EN v1.0 0x80114DEC  size: 376b  Latches the path-relative start offset on
 * first use and refreshes the current path point position. */

extern s16 getAngle(f32 x, f32 z);

/* EN v1.0 0x80113BD0  size: 396b  Computes the yaw step, signed yaw delta and
 * distance from an object to its target, updating the wide-turn flag. */
void dll_19_func07(int obj, int target, int div, u16* outYaw, u16* outDelta, u16* outDist);

extern void voxmaps_worldToGrid(f32* world, int* grid);
extern f32 mathCosf(f32 x);
extern const f32 lbl_803E1C80;
extern const f32 lbl_803E1C84;

/* EN v1.0 0x80113D64  size: 544b  Probes the four compass directions around
 * the object for walkable space, returning a bitmask of clear directions. */
u8 dll_19_func08(int obj, char* st, f32 dist);


/* EN v1.0 0x801145BC  size: 512b  Advances the object along its movement
 * curve, snapping to ground and easing the yaw toward the path direction. */

extern u8 framesThisStep;

/* EN v1.0 0x80114BB0  size: 572b  Object-sequence scripted-move step: phase 4
 * arms the move, phase 5 walks the setup/playback sub-phases. */


/* EN v1.0 0x8011395C  size: 628b  Constrains a follow point against the
 * object's facing plane and returns the lateral offset of the result. */
f32 dll_19_func05(int obj, f32 px, f32 pz, f32 range, char* st);


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
