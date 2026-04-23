#include "ghidra_import.h"
#include "main/dll/CAM/camcontrol.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000e054();
extern undefined4 FUN_8000e0c0();
extern uint FUN_80014e9c();
extern undefined4 FUN_8001f7e0();
extern undefined4 FUN_800238c4();
extern int FUN_80023d8c();
extern undefined4 FUN_8002fb40();
extern undefined4 FUN_800303fc();
extern int FUN_80037ad4();
extern undefined8 FUN_8007d858();
extern undefined4 FUN_80098230();
extern undefined4 FUN_800e875c();
extern undefined4 FUN_80101350();
extern undefined4 FUN_80101844();
extern undefined4 FUN_80101c1c();
extern undefined8 camcontrol_applyQueuedAction();
extern int FUN_80111fb0();
extern int FUN_8012ee7c();
extern int FUN_80134f70();
extern double FUN_8014ca48();
extern double FUN_8018375c();
extern int FUN_80286838();
extern undefined4 FUN_80286884();
extern double FUN_80293900();

extern undefined4 DAT_803a4e88;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de130;
extern short* DAT_803de134;
extern undefined4 DAT_803de140;
extern undefined4 DAT_803de142;
extern undefined4 gCamcontrolSavedActionMode;
extern undefined4 gCamcontrolSavedActionFlags;
extern undefined4 gCamcontrolSavedActionId;
extern undefined gCamcontrolQueuedActionMode;
extern undefined4 gCamcontrolQueuedActionBlendFrames;
extern undefined gCamcontrolQueuedActionPending;
extern void *gCamcontrolQueuedActionData;
extern int gCamcontrolQueuedActionSource;
extern undefined4 gCamcontrolCurrentActionId;
extern undefined4 DAT_803de194;
extern undefined4 DAT_803de198;
extern short* DAT_803de19c;
extern f64 DOUBLE_803e22d0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de14c;
extern f32 FLOAT_803de150;
extern f32 FLOAT_803de154;
extern f32 FLOAT_803de158;
extern f32 FLOAT_803de15c;
extern f32 FLOAT_803de160;
extern f32 FLOAT_803e22ac;
extern f32 FLOAT_803e22b0;
extern f32 FLOAT_803e22b4;
extern f32 FLOAT_803e22b8;
extern f32 FLOAT_803e22bc;
extern f32 FLOAT_803e22f0;
extern f32 FLOAT_803e22f4;
extern f32 FLOAT_803e22f8;
extern f32 FLOAT_803e22fc;
extern f32 FLOAT_803e2300;

typedef struct CamcontrolTriggeredAction {
  u8 actionKind;
  u8 pad01[0xC];
  s8 triggerMode;
  u8 pad0E[2];
} CamcontrolTriggeredAction;

/*
 * --INFO--
 *
 * Function: FUN_801024e8
 * EN v1.0 Address: 0x801024E8
 * EN v1.0 Size: 1736b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801024e8(void)
{
  bool bVar1;
  char cVar2;
  short sVar3;
  float fVar4;
  float fVar5;
  short *psVar6;
  byte bVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  double dVar12;
  
  psVar6 = DAT_803de134;
  iVar11 = *(int *)(DAT_803de19c + 0x124);
  if (DAT_803de134 == (short *)0x0) {
    return;
  }
  iVar8 = FUN_80134f70();
  if (iVar8 != 0) {
    return;
  }
  if ((DAT_803de130 != '\0') && (DAT_803de130 = '\0', iVar11 != 0)) {
    cVar2 = *(char *)(DAT_803de19c + 0x138);
    if (cVar2 == '\x01') {
      FUN_8000bb38(0,0x3ff);
      FUN_80098230((double)FLOAT_803e22ac,psVar6,2);
    }
    else if ((cVar2 == '\x04') || (cVar2 == '\t')) {
      FUN_8000bb38(0,0x402);
      FUN_80098230((double)FLOAT_803e22ac,psVar6,3);
    }
    else if (cVar2 != '\b') {
      FUN_8000bb38(0,0x288);
      FUN_80098230((double)FLOAT_803e22ac,psVar6,1);
    }
  }
  if (iVar11 != 0) {
    *(byte *)(iVar11 + 0xaf) = *(byte *)(iVar11 + 0xaf) | 4;
    uVar9 = FUN_80014e9c(0);
    uVar10 = 0x100;
    bVar7 = *(byte *)(*(int *)(iVar11 + 0x78) + (uint)*(byte *)(iVar11 + 0xe4) * 5 + 4) & 0xf;
    if ((bVar7 == 4) || (bVar7 == 9)) {
      uVar10 = 0x900;
    }
    bVar1 = (uVar9 & uVar10) != 0;
    if ((*(byte *)(iVar11 + 0xaf) & 0x10) == 0) {
      if (bVar1) {
        *(byte *)(iVar11 + 0xaf) = *(byte *)(iVar11 + 0xaf) | 1;
      }
    }
    else if ((bVar1) && (iVar8 = FUN_8012ee7c(), iVar8 == 0)) {
      FUN_8000bb38(0,0x287);
    }
  }
  if (DAT_803de142 == '\0') {
    if (FLOAT_803e22b0 < *(float *)(psVar6 + 0x4c)) {
      FUN_8002fb40((double)FLOAT_803e22f0,(double)FLOAT_803dc074);
    }
    else if (iVar11 == 0) {
      *(undefined4 *)(DAT_803de19c + 0x128) = 0;
    }
    else {
      *(int *)(DAT_803de19c + 0x128) = iVar11;
      *(byte *)(DAT_803de19c + 0x138) =
           *(byte *)(*(int *)(iVar11 + 0x78) + (uint)*(byte *)(iVar11 + 0xe4) * 5 + 4) & 0xf;
      DAT_803de142 = '\x03';
      DAT_803de130 = '\x01';
    }
  }
  else if ((*(int *)(DAT_803de19c + 0x128) == iVar11) ||
          (*(float *)(psVar6 + 0x4c) < FLOAT_803e22ac)) {
    FUN_8002fb40((double)FLOAT_803e22f4,(double)FLOAT_803dc074);
  }
  else {
    DAT_803de142 = '\0';
    if (iVar11 == 0) {
      cVar2 = *(char *)(DAT_803de19c + 0x138);
      if (cVar2 == '\x01') {
        FUN_8000bb38(0,0x400);
      }
      else if ((cVar2 == '\x04') || (cVar2 == '\t')) {
        FUN_8000bb38(0,0x401);
      }
      else if (cVar2 != '\b') {
        FUN_8000bb38(0,0x289);
      }
    }
    else {
      FUN_800303fc((double)FLOAT_803e22b0,(int)psVar6);
    }
  }
  iVar11 = FUN_80037ad4(*(int *)(DAT_803de19c + 0x128));
  if (iVar11 == 0) {
    *(undefined4 *)(DAT_803de19c + 0x128) = 0;
  }
  if ((DAT_803de142 != '\x03') || (*(int *)(DAT_803de19c + 0x128) == 0)) goto LAB_80102ab4;
  if ((*(byte *)(*(int *)(DAT_803de19c + 0x128) + 0xaf) & 0x10) == 0) {
    *(byte *)(DAT_803de19c + 0x141) = *(byte *)(DAT_803de19c + 0x141) & 0xdf;
  }
  else {
    *(byte *)(DAT_803de19c + 0x141) = *(byte *)(DAT_803de19c + 0x141) | 0x20;
  }
  iVar11 = *(int *)(DAT_803de19c + 0x128);
  sVar3 = *(short *)(iVar11 + 0x46);
  if (sVar3 == 0x49f) {
LAB_80102994:
    dVar12 = FUN_8018375c(iVar11);
  }
  else {
    if (sVar3 < 0x49f) {
      if (sVar3 != 0x281) {
        if (sVar3 < 0x281) {
          if (sVar3 != 0x13a) {
            if (sVar3 < 0x13a) {
              if (sVar3 == 0x31) {
                dVar12 = (double)FLOAT_803e22ac;
                goto LAB_801029e0;
              }
              if (sVar3 < 0x31) {
                if (sVar3 != 0x11) goto LAB_801029ac;
              }
              else if (sVar3 != 0xd8) goto LAB_801029ac;
            }
            else if ((sVar3 != 0x25d) && ((0x25c < sVar3 || (sVar3 != 0x251)))) goto LAB_801029ac;
          }
        }
        else if (sVar3 != 0x3fe) {
          if (sVar3 < 0x3fe) {
            if (sVar3 == 0x3de) goto LAB_80102994;
            if ((0x3dd < sVar3) || (sVar3 != 0x369)) goto LAB_801029ac;
          }
          else if (sVar3 < 0x457) {
            if (sVar3 != 0x427) goto LAB_801029ac;
          }
          else if (0x458 < sVar3) goto LAB_801029ac;
        }
      }
    }
    else if (sVar3 != 0x613) {
      if (sVar3 < 0x613) {
        if (sVar3 != 0x58b) {
          if (sVar3 < 0x58b) {
            if ((sVar3 != 0x4d7) && ((0x4d6 < sVar3 || (sVar3 != 0x4ac)))) {
LAB_801029ac:
              iVar8 = FUN_80111fb0(iVar11);
              if (iVar8 == 0) {
                dVar12 = (double)FLOAT_803e22ac;
              }
              else {
                dVar12 = (double)(**(code **)(*DAT_803dd738 + 0x60))(iVar11);
              }
              goto LAB_801029e0;
            }
          }
          else if ((sVar3 != 0x5e1) && (((0x5e0 < sVar3 || (0x5b9 < sVar3)) || (sVar3 < 0x5b7))))
          goto LAB_801029ac;
        }
      }
      else if (sVar3 != 0x842) {
        if (sVar3 < 0x842) {
          if (sVar3 < 0x6a2) {
            if (sVar3 != 0x642) goto LAB_801029ac;
          }
          else if (0x6a5 < sVar3) goto LAB_801029ac;
        }
        else if ((sVar3 != 0x851) && ((0x850 < sVar3 || (sVar3 != 0x84b)))) goto LAB_801029ac;
      }
    }
    dVar12 = FUN_8014ca48(iVar11);
  }
LAB_801029e0:
  if (((double)FLOAT_803e22b0 < dVar12) ||
     ((double)*(float *)(DAT_803de19c + 0x134) <= (double)FLOAT_803e22b0)) {
    if (((double)FLOAT_803e22b4 < dVar12) ||
       ((double)*(float *)(DAT_803de19c + 0x134) <= (double)FLOAT_803e22b4)) {
      if (((double)FLOAT_803e22b8 < dVar12) ||
         ((double)*(float *)(DAT_803de19c + 0x134) <= (double)FLOAT_803e22b8)) {
        if ((dVar12 <= (double)FLOAT_803e22bc) &&
           ((double)FLOAT_803e22bc < (double)*(float *)(DAT_803de19c + 0x134))) {
          FUN_80098230((double)FLOAT_803e22ac,psVar6,4);
        }
      }
      else {
        FUN_80098230((double)FLOAT_803e22ac,psVar6,4);
      }
    }
    else {
      FUN_80098230((double)FLOAT_803e22ac,psVar6,4);
    }
  }
  else {
    FUN_80098230((double)FLOAT_803e22ac,psVar6,4);
  }
  *(float *)(DAT_803de19c + 0x134) = (float)dVar12;
LAB_80102ab4:
  fVar4 = FLOAT_803e22f8 * *(float *)(psVar6 + 0x4c);
  fVar5 = FLOAT_803e22b0;
  if ((FLOAT_803e22b0 <= fVar4) && (fVar5 = fVar4, FLOAT_803e22f8 < fVar4)) {
    fVar5 = FLOAT_803e22f8;
  }
  *(char *)(psVar6 + 0x1b) = (char)(int)fVar5;
  DAT_803de140 = 0x400;
  *psVar6 = (short)(int)(FLOAT_803e22fc * FLOAT_803dc074 +
                        (float)((double)CONCAT44(0x43300000,(int)*psVar6 ^ 0x80000000) -
                               DOUBLE_803e22d0));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80102bb0
 * EN v1.0 Address: 0x80102BB0
 * EN v1.0 Size: 396b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80102bb0(double param_1,int param_2,float *param_3,float *param_4,float *param_5,
                 float *param_6,int param_7)
{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(DAT_803de19c + 0xa4);
  if (param_7 == 0) {
    *param_3 = *(float *)(param_2 + 0x18) - *(float *)(iVar1 + 0x18);
    *param_4 = *(float *)(param_2 + 0x1c) - (float)((double)*(float *)(iVar1 + 0x1c) + param_1);
    *param_5 = *(float *)(param_2 + 0x20) - *(float *)(iVar1 + 0x20);
  }
  else {
    *param_3 = *(float *)(param_2 + 0xc) - *(float *)(iVar1 + 0xc);
    *param_4 = *(float *)(param_2 + 0x10) - (float)((double)*(float *)(iVar1 + 0x10) + param_1);
    *param_5 = *(float *)(param_2 + 0x14) - *(float *)(iVar1 + 0x14);
  }
  if (param_6 != (float *)0x0) {
    *param_6 = *param_3 * *param_3 + *param_5 * *param_5;
    if ((double)FLOAT_803e22b0 < (double)*param_6) {
      dVar2 = FUN_80293900((double)*param_6);
      *param_6 = (float)dVar2;
    }
    if (*param_6 < FLOAT_803e2300) {
      *param_6 = FLOAT_803e2300;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_loadTriggeredCamAction
 * EN v1.0 Address: 0x80102D3C
 * EN v1.0 Size: 1012b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_loadTriggeredCamAction(undefined8 param_1,double param_2,double param_3,
                                      undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                      undefined8 param_7,undefined8 param_8,int param_9,
                                      uint param_10,char param_11,undefined4 param_12,
                                      undefined4 param_13,undefined4 param_14,undefined4 param_15,
                                      undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  CamcontrolTriggeredAction *camAction;
  undefined8 uVar6;
  uint local_28;
  undefined local_24;
  uint local_20;
  byte local_1c;
  
  if (param_9 == 2) {
    local_28 = param_10 & 0x7f;
    local_24 = (undefined)(param_10 & 0x80);
    if ((param_10 & 0x80) == 0) {
      uVar4 = 0x78;
    }
    else {
      uVar4 = 0;
    }
    camcontrol_queueCamAction(0x47,1,0,8,(uint)&local_28,uVar4,0xff);
    return;
  }
  if (param_9 < 2) {
    if ((param_9 != 0) && (-1 < param_9)) {
      local_20 = param_10 & 0x7f;
      local_1c = (byte)param_10 & 0x80;
      *(undefined *)(DAT_803de19c + 0x139) = 1;
      if ((param_10 & 0x80) == 0) {
        uVar4 = 0x78;
      }
      else {
        uVar4 = 0;
      }
      camcontrol_queueCamAction(0x48,1,0,8,(uint)&local_20,uVar4,0xff);
      return;
    }
  }
  else {
    if (param_9 == 4) {
      camcontrol_queueCamAction(param_10 + 0x42,1,0,0,0,0x78,0xff);
      return;
    }
    if (param_9 < 4) {
      camcontrol_queueCamAction(0x42,0,1,0,0,0x78,0xff);
      return;
    }
  }
  if (param_10 == 0) {
    uVar6 = FUN_8007d858();
    camAction = (CamcontrolTriggeredAction *)FUN_80023d8c(0x10,0xf);
    if (camAction != (CamcontrolTriggeredAction *)0x0) {
      FUN_8001f7e0(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,camAction,0xb,0,
                   0x10,param_13,param_14,param_15,param_16);
      camAction->triggerMode = param_11;
      FUN_800e875c(1);
      if ((((gCamcontrolCurrentActionId == 0x42) || (gCamcontrolCurrentActionId == 0x4b)) ||
          (gCamcontrolCurrentActionId == 0x48)) || (gCamcontrolCurrentActionId == 0x47)) {
        if (camAction->actionKind == 1) {
          camcontrol_queueCamAction(0x4b,1,2,0x10,(uint)camAction,0,0xff);
        }
        else {
          camcontrol_queueCamAction(0x42,0,2,0x10,(uint)camAction,0,0xff);
        }
      }
      else {
        iVar2 = 0;
        puVar3 = &DAT_803a4e88;
        for (uVar1 = (uint)DAT_803de198; uVar1 != 0; uVar1 = uVar1 - 1) {
          if (*(short *)*puVar3 == 0x42) {
            iVar2 = (&DAT_803a4e88)[iVar2];
            goto LAB_80103090;
          }
          puVar3 = puVar3 + 1;
          iVar2 = iVar2 + 1;
        }
        iVar2 = 0;
LAB_80103090:
        (**(code **)(**(int **)(iVar2 + 4) + 0x10))(camAction,0x10);
      }
      FUN_800238c4((uint)camAction);
    }
  }
  else {
    if (param_10 == 0) {
      camAction = (CamcontrolTriggeredAction *)0x0;
    }
    else {
      camAction = (CamcontrolTriggeredAction *)FUN_80023d8c(0x10,0xf);
      if (camAction != (CamcontrolTriggeredAction *)0x0) {
        FUN_8001f7e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,camAction,0xb,
                     (param_10 - 1) * 0x10,0x10,param_13,param_14,param_15,param_16);
      }
    }
    if (camAction != (CamcontrolTriggeredAction *)0x0) {
      camAction->triggerMode = param_11;
      FUN_800e875c((short)param_10);
      if (((gCamcontrolCurrentActionId == 0x42) || (gCamcontrolCurrentActionId == 0x4b)) ||
         ((gCamcontrolCurrentActionId == 0x48 || (gCamcontrolCurrentActionId == 0x47)))) {
        if (camAction->actionKind == 1) {
          camcontrol_queueCamAction(0x4b,1,2,0x10,(uint)camAction,0,0xff);
        }
        else {
          camcontrol_queueCamAction(0x42,0,2,0x10,(uint)camAction,0,0xff);
        }
      }
      else {
        iVar2 = 0;
        puVar3 = &DAT_803a4e88;
        for (uVar1 = (uint)DAT_803de198; uVar1 != 0; uVar1 = uVar1 - 1) {
          if (*(short *)*puVar3 == 0x42) {
            iVar2 = (&DAT_803a4e88)[iVar2];
            goto LAB_80102f3c;
          }
          puVar3 = puVar3 + 1;
          iVar2 = iVar2 + 1;
        }
        iVar2 = 0;
LAB_80102f3c:
        (**(code **)(**(int **)(iVar2 + 4) + 0x10))(camAction,0x10);
      }
      FUN_800238c4((uint)camAction);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_loadCamAction
 * EN v1.0 Address: 0x80103130
 * EN v1.0 Size: 116b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int camcontrol_loadCamAction(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                             undefined8 param_5,undefined8 param_6,undefined8 param_7,
                             undefined8 param_8,int param_9)
{
  int iVar1;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  if (param_9 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_80023d8c(0x10,0xf);
    if (iVar1 != 0) {
      FUN_8001f7e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0xb,
                   (param_9 + -1) * 0x10,0x10,in_r7,in_r8,in_r9,in_r10);
    }
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_801031a4
 * EN v1.0 Address: 0x801031A4
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801031a4(void)
{
  if (DAT_803de194 != 0) {
    (**(code **)(**(int **)(DAT_803de194 + 4) + 0x10))();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_queueSavedAction
 * EN v1.0 Address: 0x801031E0
 * EN v1.0 Size: 68b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_queueSavedAction(undefined4 param_1,undefined param_2)
{
  if (gCamcontrolSavedActionId != -1) {
    camcontrol_queueCamAction(gCamcontrolSavedActionId,gCamcontrolSavedActionFlags,
                              (char)gCamcontrolSavedActionMode,0,0,param_1,param_2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_queueCamAction
 * EN v1.0 Address: 0x80103224
 * EN v1.0 Size: 312b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_queueCamAction(undefined4 param_1,undefined4 param_2,undefined param_3,int param_4,
                               uint param_5,undefined4 param_6,undefined param_7)
{
  int iVar1;
  undefined extraout_r4;
  
  iVar1 = FUN_80286838();
  if (gCamcontrolQueuedActionData != (void *)0x0) {
    FUN_800238c4((uint)gCamcontrolQueuedActionData);
    gCamcontrolQueuedActionData = (void *)0x0;
    gCamcontrolQueuedActionPending = 0;
  }
  gCamcontrolQueuedActionBlendFrames = param_6;
  gCamcontrolQueuedActionSource = iVar1;
  if (param_5 == 0) {
    gCamcontrolQueuedActionData = (void *)0x0;
  }
  else {
    gCamcontrolQueuedActionData = (void *)FUN_80023d8c(param_4,0xf);
    FUN_80003494((uint)gCamcontrolQueuedActionData,param_5,param_4);
  }
  if (iVar1 == 0x42) {
    extraout_r4 = 0;
  }
  gCamcontrolQueuedActionPending = 1;
  gCamcontrolQueuedActionMode = param_7;
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010335c
 * EN v1.0 Address: 0x8010335C
 * EN v1.0 Size: 748b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010335c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  undefined4 uVar2;
  short *psVar3;
  undefined8 uVar4;
  
  iVar1 = FUN_80134f70();
  psVar3 = *(short **)(DAT_803de19c + 0x52);
  if (psVar3 == (short *)0x0) {
    psVar3 = DAT_803de19c;
    psVar3[0x92] = 0;
    psVar3[0x93] = 0;
    psVar3 = DAT_803de19c;
    psVar3[0x8e] = 0;
    psVar3[0x8f] = 0;
  }
  else {
    FLOAT_803de160 = *(float *)(psVar3 + 6);
    FLOAT_803de15c = *(float *)(psVar3 + 8);
    FLOAT_803de158 = *(float *)(psVar3 + 10);
    FLOAT_803de154 = *(float *)(psVar3 + 0xc);
    FLOAT_803de150 = *(float *)(psVar3 + 0xe);
    FLOAT_803de14c = *(float *)(psVar3 + 0x10);
    FUN_80101844((int)DAT_803de19c,(int)psVar3);
    if (*(char *)((int)DAT_803de19c + 0x13d) != '\0') {
      *(undefined4 *)(psVar3 + 0xc) = *(undefined4 *)(DAT_803de19c + 0x6e);
      *(undefined4 *)(psVar3 + 0xe) = *(undefined4 *)(DAT_803de19c + 0x70);
      *(undefined4 *)(psVar3 + 0x10) = *(undefined4 *)(DAT_803de19c + 0x72);
      param_2 = (double)*(float *)(psVar3 + 0xe);
      param_3 = (double)*(float *)(psVar3 + 0x10);
      FUN_8000e054((double)*(float *)(psVar3 + 0xc),param_2,param_3,(float *)(psVar3 + 6),
                   (float *)(psVar3 + 8),(float *)(psVar3 + 10),*(int *)(psVar3 + 0x18));
      *(undefined *)((int)DAT_803de19c + 0x13d) = 0;
    }
    if (*(int *)(DAT_803de19c + 0x18) != *(int *)(psVar3 + 0x18)) {
      FUN_8000e0c0((double)*(float *)(DAT_803de19c + 6),(double)*(float *)(DAT_803de19c + 8),
                   (double)*(float *)(DAT_803de19c + 10),(float *)(DAT_803de19c + 0xc),
                   (float *)(DAT_803de19c + 0xe),(float *)(DAT_803de19c + 0x10),
                   *(int *)(DAT_803de19c + 0x18));
      FUN_8000e0c0((double)*(float *)(DAT_803de19c + 0x54),(double)*(float *)(DAT_803de19c + 0x56),
                   (double)*(float *)(DAT_803de19c + 0x58),(float *)(DAT_803de19c + 0x5c),
                   (float *)(DAT_803de19c + 0x5e),(float *)(DAT_803de19c + 0x60),
                   *(int *)(DAT_803de19c + 0x18));
      FUN_8000e054((double)*(float *)(DAT_803de19c + 0xc),(double)*(float *)(DAT_803de19c + 0xe),
                   (double)*(float *)(DAT_803de19c + 0x10),(float *)(DAT_803de19c + 6),
                   (float *)(DAT_803de19c + 8),(float *)(DAT_803de19c + 10),*(int *)(psVar3 + 0x18))
      ;
      param_2 = (double)*(float *)(DAT_803de19c + 0x5e);
      param_3 = (double)*(float *)(DAT_803de19c + 0x60);
      FUN_8000e054((double)*(float *)(DAT_803de19c + 0x5c),param_2,param_3,
                   (float *)(DAT_803de19c + 0x54),(float *)(DAT_803de19c + 0x56),
                   (float *)(DAT_803de19c + 0x58),*(int *)(psVar3 + 0x18));
      *(undefined4 *)(DAT_803de19c + 0x18) = *(undefined4 *)(psVar3 + 0x18);
    }
    if (*(short **)(psVar3 + 0x18) != (short *)0x0) {
      *psVar3 = *psVar3 + **(short **)(psVar3 + 0x18);
    }
    camcontrol_applyQueuedAction();
    if (DAT_803de194 != 0) {
      (**(code **)(**(int **)(DAT_803de194 + 4) + 8))(DAT_803de19c);
      param_2 = (double)*(float *)(DAT_803de19c + 8);
      param_3 = (double)*(float *)(DAT_803de19c + 10);
      FUN_8000e0c0((double)*(float *)(DAT_803de19c + 6),param_2,param_3,
                   (float *)(DAT_803de19c + 0xc),(float *)(DAT_803de19c + 0xe),
                   (float *)(DAT_803de19c + 0x10),*(int *)(DAT_803de19c + 0x18));
      FUN_80101c1c(DAT_803de19c);
    }
    uVar4 = camcontrol_applyQueuedAction();
    if (iVar1 == 0) {
      if (*(int *)(DAT_803de19c + 0x8e) == 0) {
        uVar2 = FUN_80101350(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        *(undefined4 *)(DAT_803de19c + 0x92) = uVar2;
      }
      else {
        *(int *)(DAT_803de19c + 0x92) = *(int *)(DAT_803de19c + 0x8e);
      }
    }
    *(undefined4 *)(DAT_803de19c + 0x54) = *(undefined4 *)(DAT_803de19c + 6);
    *(undefined4 *)(DAT_803de19c + 0x56) = *(undefined4 *)(DAT_803de19c + 8);
    *(undefined4 *)(DAT_803de19c + 0x58) = *(undefined4 *)(DAT_803de19c + 10);
    *(undefined4 *)(DAT_803de19c + 0x5c) = *(undefined4 *)(DAT_803de19c + 0xc);
    *(undefined4 *)(DAT_803de19c + 0x5e) = *(undefined4 *)(DAT_803de19c + 0xe);
    *(undefined4 *)(DAT_803de19c + 0x60) = *(undefined4 *)(DAT_803de19c + 0x10);
    *(undefined *)(DAT_803de19c + 0xa0) = 0;
    *(float *)(psVar3 + 6) = FLOAT_803de160;
    *(float *)(psVar3 + 8) = FLOAT_803de15c;
    *(float *)(psVar3 + 10) = FLOAT_803de158;
    *(float *)(psVar3 + 0xc) = FLOAT_803de154;
    *(float *)(psVar3 + 0xe) = FLOAT_803de150;
    *(float *)(psVar3 + 0x10) = FLOAT_803de14c;
    if (*(short **)(psVar3 + 0x18) != (short *)0x0) {
      *psVar3 = *psVar3 - **(short **)(psVar3 + 0x18);
    }
  }
  return;
}
