#include "ghidra_import.h"
#include "main/dll/CAM/firstperson.h"

extern undefined4 FUN_800068f4();
extern double FUN_800176f4();
extern undefined4 camcontrol_getTargetPosition();
extern double FUN_80247f54();
extern double FUN_80293900();

extern undefined4* DAT_803dd6d0;
extern undefined4* gCamcontrolModeSettings;
extern f64 DOUBLE_803e1698;
extern f64 DOUBLE_803e16f8;
extern f32 lbl_803E1710;
extern f32 lbl_803E1714;
extern f64 DOUBLE_803e2318;
extern f64 DOUBLE_803e2378;
extern f32 lbl_803DC074;
extern f32 lbl_803E2314;
extern f32 lbl_803E2324;
extern f32 lbl_803E232C;
extern f32 lbl_803E2380;
extern f32 lbl_803E2384;
extern f32 lbl_803E2388;
extern f32 lbl_803E238C;
extern f32 lbl_803E2390;
extern f32 lbl_803E2394;

/*
 * --INFO--
 *
 * Function: firstperson_updatePosition
 * EN v1.0 Address: 0x80105178
 * EN v1.0 Size: 1352b
 * EN v1.1 Address: 0x80105338
 * EN v1.1 Size: 1140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void firstperson_updatePosition(int param_1,short *param_2)
{
  float fVar1;
  float fVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  
  (**(code **)(*DAT_803dd6d0 + 0x38))
            ((double)gCamcontrolModeSettings[0x23],param_1,&local_2c,&local_30,&local_34,&local_38,
             1);
  local_38 = local_34 * local_34 + local_2c * local_2c + local_30 * local_30;
  if ((double)lbl_803E232C < (double)local_38) {
    dVar3 = FUN_80293900((double)local_38);
    local_38 = (float)dVar3;
  }
  if (local_38 < lbl_803E2314) {
    local_38 = lbl_803E2314;
  }
  if (lbl_803E2380 * gCamcontrolModeSettings[1] < local_38) {
    camcontrol_getTargetPosition(param_1,param_2,(float *)(param_1 + 0x18),(short *)(param_1 + 2));
    FUN_800068f4((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                 (double)*(float *)(param_1 + 0x20),(float *)(param_1 + 0xc),
                 (float *)(param_1 + 0x10),(float *)(param_1 + 0x14),*(int *)(param_1 + 0x30));
    *(undefined4 *)(param_1 + 0xb8) = *(undefined4 *)(param_1 + 0x18);
    *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(param_1 + 0x1c);
    *(undefined4 *)(param_1 + 0xc0) = *(undefined4 *)(param_1 + 0x20);
    (**(code **)(*DAT_803dd6d0 + 0x38))
              ((double)gCamcontrolModeSettings[0x23],param_1,&local_2c,&local_30,&local_34,
               &local_38,1);
    local_38 = local_34 * local_34 + local_2c * local_2c + local_30 * local_30;
    if ((double)lbl_803E232C < (double)local_38) {
      dVar3 = FUN_80293900((double)local_38);
      local_38 = (float)dVar3;
    }
    if (local_38 < lbl_803E2314) {
      local_38 = lbl_803E2314;
    }
  }
  fVar1 = gCamcontrolModeSettings[1];
  if (local_38 <= fVar1) {
    fVar1 = *gCamcontrolModeSettings;
    if (fVar1 <= local_38) {
      *(byte *)(gCamcontrolModeSettings + 0x32) = *(byte *)(gCamcontrolModeSettings + 0x32) & 0x7f;
      fVar1 = local_38;
    }
    else {
      *(byte *)(gCamcontrolModeSettings + 0x32) = *(byte *)(gCamcontrolModeSettings + 0x32) & 0x7f;
    }
  }
  else {
    *(byte *)((int)gCamcontrolModeSettings + 0xc6) =
         *(byte *)((int)gCamcontrolModeSettings + 0xc6) & 0x7f;
    *(byte *)(gCamcontrolModeSettings + 0x32) =
         *(byte *)(gCamcontrolModeSettings + 0x32) & 0x7f | 0x80;
  }
  dVar5 = (double)*(float *)(param_1 + 0xc);
  dVar3 = (double)*(float *)(param_1 + 0x14);
  if (((-1 < *(char *)((int)gCamcontrolModeSettings + 0xc6)) && (fVar1 != local_38)) &&
     (lbl_803E232C != gCamcontrolModeSettings[4])) {
    if (local_38 < lbl_803E2324) {
      local_38 = lbl_803E2324;
    }
    dVar4 = FUN_800176f4((double)(local_38 - fVar1),(double)gCamcontrolModeSettings[4],
                         (double)lbl_803DC074);
    fVar1 = (float)((double)(float)((double)local_38 + dVar4) / (double)local_38);
    if (lbl_803E232C < fVar1) {
      dVar5 = (double)(*(float *)(param_2 + 6) + local_2c / fVar1);
      dVar3 = (double)(*(float *)(param_2 + 10) + local_34 / fVar1);
    }
  }
  local_2c = (float)(dVar5 - (double)*(float *)(param_1 + 0xc));
  local_34 = (float)(dVar3 - (double)*(float *)(param_1 + 0x14));
  dVar3 = FUN_80293900((double)(local_2c * local_2c + local_34 * local_34));
  local_38 = (float)dVar3;
  fVar1 = (float)dVar3;
  if (lbl_803E232C < fVar1) {
    local_2c = local_2c / fVar1;
    local_34 = local_34 / fVar1;
  }
  dVar3 = FUN_80247f54((float *)(param_2 + 0x12));
  fVar1 = (float)(dVar3 * (double)(lbl_803E2384 * lbl_803DC074));
  if (fVar1 < lbl_803E2324) {
    fVar1 = lbl_803E2324;
  }
  fVar2 = lbl_803E232C;
  if ((lbl_803E232C <= local_38) && (fVar2 = local_38, fVar1 < local_38)) {
    fVar2 = fVar1;
  }
  local_38 = lbl_803E232C;
  if ((lbl_803E232C <= fVar2) && (local_38 = fVar2, lbl_803E2388 < fVar2)) {
    local_38 = lbl_803E2388;
  }
  *(float *)(param_1 + 0xc) = local_2c * local_38 + *(float *)(param_1 + 0xc);
  *(float *)(param_1 + 0x14) = local_34 * local_38 + *(float *)(param_1 + 0x14);
  if (gCamcontrolModeSettings[0x27] < gCamcontrolModeSettings[3]) {
    local_2c = *(float *)(param_1 + 0xc) - *(float *)(param_2 + 6);
    local_34 = *(float *)(param_1 + 0x14) - *(float *)(param_2 + 10);
    dVar3 = FUN_80293900((double)(local_2c * local_2c + local_34 * local_34));
    fVar1 = (float)dVar3;
    if (fVar1 < lbl_803E238C * *gCamcontrolModeSettings) {
      if (lbl_803E232C < fVar1) {
        local_2c = local_2c / fVar1;
        local_34 = local_34 / fVar1;
      }
      fVar1 = lbl_803E238C * *gCamcontrolModeSettings;
      *(float *)(param_1 + 0xc) = fVar1 * local_2c + *(float *)(param_2 + 6);
      *(float *)(param_1 + 0x14) = fVar1 * local_34 + *(float *)(param_2 + 10);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: firstperson_loadSettings
 * EN v1.0 Address: 0x801056C0
 * EN v1.0 Size: 812b
 * EN v1.1 Address: 0x801057AC
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void firstperson_loadSettings(int param_1)
{
  float fVar1;
  double dVar2;
  double dVar3;
  int iVar4;
  
  iVar4 = (**(code **)(*DAT_803dd6d0 + 0xc))();
  gCamcontrolModeSettings[0x24] = gCamcontrolModeSettings[0x23];
  gCamcontrolModeSettings[0xf] = gCamcontrolModeSettings[2];
  gCamcontrolModeSettings[0x11] = gCamcontrolModeSettings[3];
  gCamcontrolModeSettings[0xb] = *gCamcontrolModeSettings;
  gCamcontrolModeSettings[0xd] = gCamcontrolModeSettings[1];
  gCamcontrolModeSettings[0x1b] = *(float *)(iVar4 + 0xb4);
  gCamcontrolModeSettings[0x17] = gCamcontrolModeSettings[6];
  gCamcontrolModeSettings[0x19] = gCamcontrolModeSettings[7];
  gCamcontrolModeSettings[0x15] = gCamcontrolModeSettings[5];
  gCamcontrolModeSettings[0x13] = gCamcontrolModeSettings[4];
  dVar2 = DOUBLE_803e1698;
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_1 + 5) ^ 0x80000000) -
                 DOUBLE_803e1698);
  gCamcontrolModeSettings[0x23] = fVar1;
  gCamcontrolModeSettings[0x25] = fVar1;
  dVar3 = DOUBLE_803e16f8;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 6)) - DOUBLE_803e16f8);
  gCamcontrolModeSettings[2] = fVar1;
  gCamcontrolModeSettings[0x26] = fVar1;
  gCamcontrolModeSettings[0x10] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 8)) - dVar3);
  gCamcontrolModeSettings[3] = fVar1;
  gCamcontrolModeSettings[0x27] = fVar1;
  gCamcontrolModeSettings[0x12] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 3)) - dVar3);
  *gCamcontrolModeSettings = fVar1;
  gCamcontrolModeSettings[0xc] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 4)) - dVar3);
  gCamcontrolModeSettings[1] = fVar1;
  gCamcontrolModeSettings[0xe] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_1 + 2) ^ 0x80000000) - dVar2);
  *(float *)(iVar4 + 0xb4) = fVar1;
  gCamcontrolModeSettings[0x1c] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 9)) - dVar3);
  gCamcontrolModeSettings[6] = fVar1;
  gCamcontrolModeSettings[0x18] = fVar1;
  fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 10)) - dVar3);
  gCamcontrolModeSettings[7] = fVar1;
  gCamcontrolModeSettings[0x1a] = fVar1;
  if (*(byte *)(param_1 + 0xb) == 0) {
    gCamcontrolModeSettings[0x14] = lbl_803E1714;
  }
  else {
    fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xb)) - dVar3) /
            lbl_803E1710;
    gCamcontrolModeSettings[4] = fVar1;
    gCamcontrolModeSettings[0x14] = fVar1;
  }
  if (*(byte *)(param_1 + 0xc) == 0) {
    gCamcontrolModeSettings[0x16] = lbl_803E1714;
  }
  else {
    fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xc)) - DOUBLE_803e16f8) /
            lbl_803E1710;
    gCamcontrolModeSettings[5] = fVar1;
    gCamcontrolModeSettings[0x16] = fVar1;
  }
  *(undefined2 *)((int)gCamcontrolModeSettings + 0x82) = 0;
  *(undefined2 *)(gCamcontrolModeSettings + 0x21) = 0;
  return;
}
