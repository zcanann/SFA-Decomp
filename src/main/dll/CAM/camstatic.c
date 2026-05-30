#include "ghidra_import.h"
#include "main/dll/CAM/camstatic.h"

extern undefined4 FUN_800068f4();
extern undefined4 FUN_800068f8();
extern double FUN_800176f4();
extern int FUN_80017730();
extern void camcontrol_traceMove(f32 radius, f32 *from, void *to, f32 *out, void *work, int a,
                                 int b, int c);
extern undefined4 camcontrol_updateTargetAction();
extern undefined4 camMoveFn_80104040();
extern void camcontrol_updateModeSettings(int camera);
extern void camcontrol_updateVerticalBounds(int camera,int flags,s8 param_3,float *upperBound,
                                            float *lowerBound);
extern undefined4 camslide_update();
extern undefined4 firstperson_updatePosition();
extern int EmissionController_IsLingering(int obj);
extern void fn_8029656C(int obj, float *out);
extern void cameraGetPrevPos2(int obj, float *x, float *y, float *z);

extern undefined4* DAT_803dd6d0;
extern u8 *cameraMtxVar57;
extern f64 DOUBLE_803e2318;
extern f64 DOUBLE_803e2378;
extern f32 lbl_803DC074;
extern f32 lbl_803DD52C;
extern f32 lbl_803E16AC;
extern f32 lbl_803E1718;
extern f32 lbl_803E171C;
extern f32 lbl_803E1720;
extern f32 lbl_803E2308;
extern f32 lbl_803E2324;
extern f32 lbl_803E232C;
extern f32 lbl_803E235C;
extern f32 lbl_803E2388;
extern f32 lbl_803E2398;
extern f32 lbl_803E239C;
extern f32 lbl_803E23A0;
extern f32 lbl_803E23A4;
extern f32 lbl_803E23A8;
extern f32 lbl_803E23AC;
extern f32 lbl_803E23B0;
extern f32 timeDelta;

#define gCamcontrolModeSettings cameraMtxVar57

/*
 * --INFO--
 *
 * Function: camstatic_update
 * EN v1.0 Address: 0x80105810
 * EN v1.0 Size: 1572b
 * EN v1.1 Address: 0x80105AAC
 * EN v1.1 Size: 1644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void camstatic_update(short *param_1)
{
  float fVar1;
  int iVar2;
  uint uVar3;
  short *psVar4;
  double dVar5;
  float local_148;
  undefined local_144 [4];
  undefined local_140 [4];
  undefined auStack_13c [4];
  undefined local_138 [4];
  float local_134;
  float local_130;
  undefined4 local_12c;
  float local_128;
  float local_124;
  undefined4 local_120;
  undefined auStack_11c [112];
  undefined auStack_ac [116];
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  psVar4 = *(short **)(param_1 + 0x52);
  if (psVar4 == (short *)0x0) {
    return;
  }
  if (psVar4[0x22] == 1) {
    fn_8029656C((int)psVar4,&local_148);
    lbl_803DD52C = timeDelta * local_148;
    iVar2 = EmissionController_IsLingering((int)psVar4);
    if (iVar2 == 3) {
      *(float *)(gCamcontrolModeSettings + 0x14) = lbl_803E1720;
      *(undefined *)(gCamcontrolModeSettings + 0xc2) = 8;
    }
    else {
      if (iVar2 < 3) {
        if (iVar2 == 1) {
          *(float *)(gCamcontrolModeSettings + 0x14) = lbl_803E16AC;
          *(undefined *)(gCamcontrolModeSettings + 0xc2) = 0xff;
          goto LAB_80105bbc;
        }
        if (0 < iVar2) {
          *(float *)(gCamcontrolModeSettings + 0x14) = lbl_803E1718;
          *(undefined *)(gCamcontrolModeSettings + 0xc2) = 0xc;
          goto LAB_80105bbc;
        }
      }
      else if (iVar2 < 5) {
        *(float *)(gCamcontrolModeSettings + 0x14) = lbl_803E171C;
        *(undefined *)(gCamcontrolModeSettings + 0xc2) = 2;
        goto LAB_80105bbc;
      }
      *(undefined4 *)(gCamcontrolModeSettings + 0x14) =
           *(undefined4 *)(gCamcontrolModeSettings + 0x58);
      *(undefined *)(gCamcontrolModeSettings + 0xc2) = 8;
    }
  }
  else {
    lbl_803DD52C = timeDelta;
  }
LAB_80105bbc:
  *(undefined *)(param_1 + 0x9f) = 0;
  camcontrol_updateModeSettings((int)param_1);
  camMoveFn_80104040();
  firstperson_updatePosition((int)param_1,psVar4);
  FUN_800068f8((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
               (double)*(float *)(param_1 + 10),(float *)(param_1 + 0xc),(float *)(param_1 + 0xe),
               (float *)(param_1 + 0x10),*(int *)(param_1 + 0x18));
  camslide_update((int)param_1,(int)psVar4);
  camcontrol_updateVerticalBounds((int)param_1,1,8,(float *)(gCamcontrolModeSettings + 0xa0),
                                  (float *)(gCamcontrolModeSettings + 0xa4));
  fVar1 = lbl_803E232C;
  if (*(char *)(gCamcontrolModeSettings + 0xc6) < '\0') {
    *(float *)(param_1 + 0x98) = lbl_803E232C;
    *(float *)(param_1 + 0x96) = fVar1;
    if ((*(char *)(param_1 + 0x51) == '\x01') && (*(float *)(param_1 + 0x1c) < fVar1)) {
      *(byte *)(gCamcontrolModeSettings + 0xc6) = *(byte *)(gCamcontrolModeSettings + 0xc6) & 0x7f;
    }
    if ((lbl_803E23AC + *(float *)(psVar4 + 0xe) < *(float *)(param_1 + 0xe)) ||
       (*(float *)(param_1 + 0xe) < lbl_803E2388 + *(float *)(psVar4 + 0xe))) {
      *(byte *)(gCamcontrolModeSettings + 0xc6) = *(byte *)(gCamcontrolModeSettings + 0xc6) & 0x7f;
    }
  }
  else {
    *(undefined *)(gCamcontrolModeSettings + 0xc5) = *(undefined *)(param_1 + 0x51);
    if (((*(char *)(param_1 + 0xa1) != '\0') ||
        ((*(char *)(gCamcontrolModeSettings + 0xc5) == '\x01' &&
         (lbl_803E232C <= *(float *)(param_1 + 0x1c))))) &&
       (-1 < *(char *)(gCamcontrolModeSettings + 200))) {
      if (((lbl_803E235C + *(float *)(psVar4 + 0xe) < *(float *)(param_1 + 0xe)) &&
          (*(float *)(param_1 + 0xe) < lbl_803E23A4 + *(float *)(psVar4 + 0xe))) &&
         (*(int *)(param_1 + 0x18) == 0)) {
        *(byte *)(gCamcontrolModeSettings + 0xc6) =
             *(byte *)(gCamcontrolModeSettings + 0xc6) & 0x7f | 0x80;
      }
    }
    if ((((*(byte *)(gCamcontrolModeSettings + 0xc5) & 0x10) != 0) &&
        (*(float *)(param_1 + 0x1c) < lbl_803E23A8)) &&
       (*(float *)(psVar4 + 0x14) <= lbl_803E232C)) {
      *(byte *)(gCamcontrolModeSettings + 200) =
           *(byte *)(gCamcontrolModeSettings + 200) & 0xbf | 0x40;
      *(undefined4 *)(gCamcontrolModeSettings + 0xbc) = *(undefined4 *)(param_1 + 0xe);
    }
  }
  if (*(char *)(gCamcontrolModeSettings + 200) < '\0') {
    if ((*(char *)(gCamcontrolModeSettings + 0xc5) == '\x01') || (*(char *)(param_1 + 0xa1) != '\0'))
    {
      *(char *)(gCamcontrolModeSettings + 199) = *(char *)(gCamcontrolModeSettings + 199) + '\x01';
    }
    else {
      *(undefined *)(gCamcontrolModeSettings + 199) = 0;
    }
    if (10 < *(byte *)(gCamcontrolModeSettings + 199)) {
      if (psVar4[0x22] == 1) {
        cameraGetPrevPos2((int)psVar4,&local_128,&local_124,(float *)&local_120);
      }
      else {
        local_128 = *(float *)(psVar4 + 0xc);
        local_124 = *(float *)(psVar4 + 0xe) + *(float *)(gCamcontrolModeSettings + 0x8c);
        local_120 = *(undefined4 *)(psVar4 + 0x10);
      }
      camcontrol_traceMove(lbl_803E2308,&local_128,(float *)(param_1 + 0xc),
                           (float *)(param_1 + 0xc),auStack_ac,3,1,1);
      *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
      *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
      *(undefined *)(gCamcontrolModeSettings + 199) = 0;
    }
  }
  if (-1 < *(char *)(gCamcontrolModeSettings + 0xc6)) {
    if ((*(byte *)(gCamcontrolModeSettings + 0xc5) & 0x10) == 0) {
      *(undefined *)(gCamcontrolModeSettings + 0xc3) = 0;
    }
    else {
      *(char *)(gCamcontrolModeSettings + 0xc3) =
           *(char *)(gCamcontrolModeSettings + 0xc3) + '\x01';
    }
    if (5 < *(byte *)(gCamcontrolModeSettings + 0xc3)) {
      if (psVar4[0x22] == 1) {
        cameraGetPrevPos2((int)psVar4,&local_134,&local_130,(float *)&local_12c);
      }
      else {
        local_134 = *(float *)(psVar4 + 0xc);
        local_130 = *(float *)(psVar4 + 0xe) + *(float *)(gCamcontrolModeSettings + 0x8c);
        local_12c = *(undefined4 *)(psVar4 + 0x10);
      }
      camcontrol_traceMove(lbl_803E2308,&local_134,(float *)(param_1 + 0xc),
                           (float *)(param_1 + 0xc),auStack_11c,3,1,1);
      *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
      *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
      *(undefined *)(gCamcontrolModeSettings + 0xc3) = 0;
    }
  }
  (**(code **)(*DAT_803dd6d0 + 0x38))
            ((double)*(float *)(gCamcontrolModeSettings + 0x8c),param_1,local_138,auStack_13c,
             local_140,
             local_144,0);
  iVar2 = FUN_80017730();
  *(undefined2 *)(gCamcontrolModeSettings + 0x80) = 0;
  *param_1 = (-0x8000 - (short)iVar2) - *(short *)(gCamcontrolModeSettings + 0x80);
  uVar3 = FUN_80017730();
  uStack_34 = (uVar3 & 0xffff) - (uint)(ushort)param_1[1];
  if (0x8000 < (int)uStack_34) {
    uStack_34 = uStack_34 - 0xffff;
  }
  if ((int)uStack_34 < -0x8000) {
    uStack_34 = uStack_34 + 0xffff;
  }
  uStack_34 = uStack_34 ^ 0x80000000;
  local_38 = 0x43300000;
  uStack_2c = (uint)*(byte *)(gCamcontrolModeSettings + 0xc2);
  local_30 = 0x43300000;
  dVar5 = FUN_800176f4((double)(f32)(s32)uStack_34,
                       (double)(lbl_803E2324 /
                               (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e2378)),
                       (double)lbl_803DC074);
  local_28 = (longlong)(int)dVar5;
  param_1[1] = param_1[1] + (short)(int)dVar5;
  camcontrol_updateTargetAction((int)param_1,(int)psVar4);
  uStack_1c = (int)param_1[2] ^ 0x80000000;
  local_20 = 0x43300000;
  dVar5 = FUN_800176f4((double)(f32)(s32)uStack_1c,
                       (double)lbl_803E23B0,(double)lbl_803DC074);
  local_18 = (longlong)(int)dVar5;
  param_1[2] = param_1[2] - (short)(int)dVar5;
  FUN_800068f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
}
#pragma peephole reset
#pragma scheduling reset
