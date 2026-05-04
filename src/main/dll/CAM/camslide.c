#include "ghidra_import.h"
#include "main/dll/CAM/camslide.h"

extern double FUN_800176f4();
extern int FUN_80017730();
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017778();
extern double fn_80021370(double param_1,double param_2,double param_3);
extern uint fn_800217C0(double param_1);
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern double FUN_80294d08();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d0;
extern undefined4* gCamcontrolModeSettings;
extern f32 lbl_803DC074;
extern f32 lbl_803E2314;
extern f32 lbl_803E2324;
extern f32 lbl_803E232C;
extern f32 lbl_803E2334;
extern f32 lbl_803E2338;
extern f32 lbl_803E2358;
extern f32 lbl_803E235C;
extern f32 lbl_803E2360;
extern f32 lbl_803E2364;
extern f32 lbl_803E2368;
extern f32 lbl_803E236C;
extern f32 lbl_803E2370;
extern f32 lbl_803E2374;
extern f64 DOUBLE_803e1698;
extern f32 lbl_803E16A4;
extern f64 DOUBLE_803e16f8;
extern f32 lbl_803DB414;

/*
 * --INFO--
 *
 * Function: camslide_update
 * EN v1.0 Address: 0x801049B0
 * EN v1.0 Size: 2072b
 * EN v1.1 Address: 0x80104C4C
 * EN v1.1 Size: 1552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camslide_update(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  float local_c8;
  float local_c4;
  float fStack_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  short local_ac [4];
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float afStack_94 [17];
  undefined4 local_50;
  float fStack_4c;
  
  (**(code **)(*DAT_803dd6d0 + 0x38))
            ((double)gCamcontrolModeSettings[0x23],param_1,&local_b0,&local_b4,&local_b8,
             &local_bc,0);
  local_bc = local_b8 * local_b8 + local_b0 * local_b0 + local_b4 * local_b4;
  if ((double)lbl_803E232C < (double)local_bc) {
    dVar5 = FUN_80293900((double)local_bc);
    local_bc = (float)dVar5;
  }
  if (local_bc < lbl_803E2314) {
    local_bc = lbl_803E2314;
  }
  fVar1 = *(float *)(param_2 + 0x1c) + gCamcontrolModeSettings[0x23];
  dVar9 = (double)(gCamcontrolModeSettings[3] + fVar1);
  dVar5 = (double)(gCamcontrolModeSettings[2] + fVar1);
  if (*(short *)(param_2 + 0x44) == 1) {
    iVar4 = *(int *)(param_2 + 0xb8);
    iVar2 = FUN_80017730();
    local_ac[0] = -0x8000 - (short)iVar2;
    local_ac[1] = 0;
    local_ac[2] = 0;
    local_a4 = lbl_803E2324;
    local_a0 = lbl_803E232C;
    local_9c = lbl_803E232C;
    local_98 = lbl_803E232C;
    FUN_8001774c(afStack_94,(int)local_ac);
    FUN_80017778((double)*(float *)(iVar4 + 0x1a4),(double)*(float *)(iVar4 + 0x1a8),
                 (double)*(float *)(iVar4 + 0x1ac),afStack_94,&fStack_c0,&local_c4,&local_c8);
    uVar3 = FUN_80017730();
    gCamcontrolModeSettings[0x2b] =
         (float)((int)gCamcontrolModeSettings[0x2b] +
                ((int)((uint)DAT_803dc070 *
                      ((0x4000 - (uVar3 & 0xffff)) - (int)gCamcontrolModeSettings[0x2b])) >> 5));
  }
  else {
    gCamcontrolModeSettings[0x2b] =
         (float)((int)gCamcontrolModeSettings[0x2b] -
                ((int)((int)gCamcontrolModeSettings[0x2b] * (uint)DAT_803dc070) >> 5));
  }
  fVar1 = gCamcontrolModeSettings[0x2b];
  if ((int)fVar1 < 0) {
    fStack_4c = -fVar1;
    local_50 = 0x43300000;
    dVar6 = (double)FUN_80293f90();
    dVar6 = (double)(float)((double)gCamcontrolModeSettings[7] * dVar6);
  }
  else if ((int)fVar1 < 1) {
    dVar6 = (double)lbl_803E232C;
  }
  else {
    fStack_4c = -fVar1;
    local_50 = 0x43300000;
    dVar6 = (double)FUN_80293f90();
    dVar6 = (double)(float)((double)gCamcontrolModeSettings[6] * dVar6);
  }
  dVar8 = (double)(float)(dVar5 + dVar6);
  dVar9 = (double)(float)(dVar9 + dVar6);
  dVar5 = (double)(*gCamcontrolModeSettings - lbl_803E2358);
  if ((double)(*gCamcontrolModeSettings - lbl_803E2358) < (double)lbl_803E235C) {
    dVar5 = (double)lbl_803E235C;
  }
  if (*(short *)(param_2 + 0x44) == 1) {
    dVar6 = FUN_80294d08(param_2);
    if ((double)lbl_803E235C < dVar6) {
      local_b4 = (gCamcontrolModeSettings[0x26] - gCamcontrolModeSettings[2]) * lbl_803E2364;
      if (lbl_803E2368 < local_b4) {
        local_b4 = lbl_803E2368;
      }
      if (local_b4 < lbl_803E236C) {
        local_b4 = lbl_803E236C;
      }
      gCamcontrolModeSettings[2] = gCamcontrolModeSettings[2] + local_b4;
      if (gCamcontrolModeSettings[2] < gCamcontrolModeSettings[0x26]) {
        gCamcontrolModeSettings[2] = gCamcontrolModeSettings[0x26];
      }
      local_b4 = (gCamcontrolModeSettings[0x27] - gCamcontrolModeSettings[3]) * lbl_803E2364;
      if (lbl_803E2368 < local_b4) {
        local_b4 = lbl_803E2368;
      }
      if (local_b4 < lbl_803E236C) {
        local_b4 = lbl_803E236C;
      }
      gCamcontrolModeSettings[3] = gCamcontrolModeSettings[3] + local_b4;
      if (gCamcontrolModeSettings[3] < gCamcontrolModeSettings[0x27]) {
        gCamcontrolModeSettings[3] = gCamcontrolModeSettings[0x27];
      }
      dVar7 = (double)local_bc;
      dVar6 = (double)lbl_803E235C;
      if (dVar7 <= dVar6) {
        dVar8 = (double)(lbl_803E2360 * (float)(dVar6 - dVar7) +
                        lbl_803E2370 + *(float *)(param_2 + 0x1c));
        dVar9 = dVar8;
      }
      else if (dVar7 <= dVar5) {
        if (lbl_803E232C < (float)(dVar5 - dVar6)) {
          local_bc = (float)(dVar7 - dVar6) / (float)(dVar5 - dVar6);
        }
        if (lbl_803E232C <= local_bc) {
          if (lbl_803E2324 < local_bc) {
            local_bc = lbl_803E2324;
          }
        }
        else {
          local_bc = lbl_803E232C;
        }
        fVar1 = lbl_803E2370 + *(float *)(param_2 + 0x1c);
        dVar8 = (double)(local_bc *
                        ((gCamcontrolModeSettings[0x23] + gCamcontrolModeSettings[2]) -
                        lbl_803E2370) +
                        fVar1);
        dVar9 = (double)(local_bc *
                        ((gCamcontrolModeSettings[0x23] + gCamcontrolModeSettings[3]) -
                        lbl_803E2370) +
                        fVar1);
      }
    }
    else {
      local_b4 = (lbl_803E2360 * gCamcontrolModeSettings[1] - gCamcontrolModeSettings[2]) *
                 lbl_803E2364;
      if (lbl_803E2334 < local_b4) {
        local_b4 = lbl_803E2334;
      }
      gCamcontrolModeSettings[2] = gCamcontrolModeSettings[2] + local_b4;
      if (gCamcontrolModeSettings[1] < gCamcontrolModeSettings[2]) {
        gCamcontrolModeSettings[2] = gCamcontrolModeSettings[1];
      }
      local_b4 = (lbl_803E2360 * gCamcontrolModeSettings[1] - gCamcontrolModeSettings[3]) *
                 lbl_803E2364;
      if (lbl_803E2334 < local_b4) {
        local_b4 = lbl_803E2334;
      }
      gCamcontrolModeSettings[3] = gCamcontrolModeSettings[3] + local_b4;
      if (gCamcontrolModeSettings[1] < gCamcontrolModeSettings[3]) {
        gCamcontrolModeSettings[3] = gCamcontrolModeSettings[1];
      }
    }
  }
  dVar5 = (double)*(float *)(param_1 + 0x1c);
  if (dVar8 <= dVar5) {
    if (dVar5 <= dVar9) {
      local_b4 = lbl_803E232C;
    }
    else {
      local_b4 = (float)(dVar9 - dVar5);
    }
  }
  else {
    local_b4 = (float)(dVar8 - dVar5);
  }
  dVar5 = FUN_800176f4((double)local_b4,(double)gCamcontrolModeSettings[5],
                       (double)lbl_803DC074);
  local_b4 = (float)dVar5;
  if ((lbl_803E2368 < (float)dVar5) && ((float)dVar5 < lbl_803E2374)) {
    local_b4 = lbl_803E232C;
  }
  *(float *)(param_1 + 0x1c) = *(float *)(param_1 + 0x1c) + local_b4;
  if ((float)((double)lbl_803E2338 + dVar9) < *(float *)(param_1 + 0x1c)) {
    *(float *)(param_1 + 0x1c) = (float)((double)lbl_803E2338 + dVar9);
  }
  if (gCamcontrolModeSettings[3] <= gCamcontrolModeSettings[0x27]) {
    *(byte *)(gCamcontrolModeSettings + 0x32) = *(byte *)(gCamcontrolModeSettings + 0x32) & 0xbf;
  }
  else {
    if (((*(byte *)(gCamcontrolModeSettings + 0x32) >> 6 & 1) != 0) &&
       (gCamcontrolModeSettings[0x2f] < *(float *)(param_1 + 0x1c))) {
      *(float *)(param_1 + 0x1c) = gCamcontrolModeSettings[0x2f];
    }
    if (lbl_803E232C < *(float *)(param_2 + 0x28)) {
      *(byte *)(gCamcontrolModeSettings + 0x32) = *(byte *)(gCamcontrolModeSettings + 0x32) & 0xbf;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: firstperson_updatePitch
 * EN v1.0 Address: 0x80104FC0
 * EN v1.0 Size: 220b
 * EN v1.1 Address: 0x8010525C
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void firstperson_updatePitch(double param_1,int param_2)
{
  uint uVar1;
  double dVar2;

  uVar1 = fn_800217C0((double)(*(float *)(param_2 + 0x1c) -
                              (float)(param_1 + (double)gCamcontrolModeSettings[0x23])));
  uVar1 = (uVar1 & 0xffff) - ((int)*(short *)(param_2 + 2) & 0xffffU);
  if (0x8000 < (int)uVar1) {
    uVar1 = uVar1 - 0xffff;
  }
  if ((int)uVar1 < -0x8000) {
    uVar1 = uVar1 + 0xffff;
  }
  dVar2 = fn_80021370((double)(float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                      DOUBLE_803e1698),
                      (double)(lbl_803E16A4 /
                              (float)((double)CONCAT44(0x43300000,
                                                       (uint)*(byte *)(gCamcontrolModeSettings +
                                                                      0x30)) - DOUBLE_803e16f8)),
                      (double)lbl_803DB414);
  *(short *)(param_2 + 2) = *(short *)(param_2 + 2) + (short)(int)dVar2;
  return;
}
