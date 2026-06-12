/* DLL 0x004E — camera mode: world map [8010DB7C-8010DD58) */
#include "main/dll/CAM/camnpcspeak_state.h"
#include "main/game_object.h"
#include "main/mm.h"

extern s16 getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);
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
extern ScreenTransitionInterface** gScreenTransitionInterface;
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
void CameraModeNpcSpeak_release(void);


void CameraModeWorldMap_release(void)
{
}

void CameraModeWorldMap_initialise(void)
{
}

void dll_4F_func06_nop(void);








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












extern f32 mathCosf(f32);
extern f32 mathSinf(f32);



extern CameraModeWorldMapState* lbl_803DD588;



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


#pragma opt_common_subs off
#pragma opt_common_subs reset









extern CameraModeCloudRunnerState* lbl_803DD5B8;




/* misc 8b leaves */

/* fn_X(lbl); lbl = 0; */
void CameraModeWorldMap_free(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD588);
    lbl_803DD588 = NULL;
}

void dll_4F_func05(void);



void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void CameraModeCloudRunner_free(void);




/* baddie spawn/visibility predicate */


/* compute progress ratio (signed numerator / unsigned denominator) */


/* baddie state reset */



/* dll_19_func19  addr=0x80111EB4  size=0x100  linkage=global */



/* dll_19_func0C  addr=0x80112D80  size=0x114  linkage=global */
#pragma dont_inline on
#pragma dont_inline reset


/* CameraModePerv_update  addr=0x80110CB0  size=0x10C  linkage=global */




/* CameraModeForceBehind_init  addr=0x801100B8  size=0x124  linkage=global */


/* dll_19_func13  addr=0x8011313C  size=0x13C  linkage=global */


/* dll_19_func10  addr=0x80113398  size=0x16C  linkage=global */


/* CameraModeCrawl_copyToCurrent  addr=0x8010F540  size=0x1E0  linkage=global */

/* dll_19_func17  addr=0x80112544  size=0x19C  linkage=global */


/* CameraModeCannon_update  addr=0x8010FA84  size=0x168  linkage=global */


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

/* CameraModeNpcSpeak_update  addr=0x8010DD58  size=0x298  linkage=global */

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


/* 8b "li r3, N; blr" returners. */

/* 12b chained getters. */

/* misc 8b leaves */









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

extern s16 getAngle(f32 x, f32 z);

/* EN v1.0 0x80113BD0  size: 396b  Computes the yaw step, signed yaw delta and
 * distance from an object to its target, updating the wide-turn flag. */

extern f32 mathCosf(f32 x);

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


/* === helper-last relocation (re-split inline suppression; defs moved below their callers to suppress cross-TU-merge auto-inlining) === */
