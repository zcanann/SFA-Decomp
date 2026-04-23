#include "ghidra_import.h"
#include "main/dll/CAM/cutCam.h"

extern int FUN_800033a8();
extern undefined4 FUN_8000e054();
extern undefined4 FUN_8000e0c0();
extern undefined4 FUN_800134f4();
extern undefined4 FUN_80013590();
extern ushort FUN_80014dc8();
extern uint FUN_80014e9c();
extern uint FUN_80021884();
extern char FUN_80064248();
extern undefined4 FUN_80067ad4();
extern undefined4 FUN_8006933c();
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern int FUN_80080490();
extern undefined4 FUN_80101c10();
extern undefined4 FUN_802473cc();
extern undefined4 FUN_8028681c();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286868();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();
extern uint FUN_8029636c();
extern int FUN_80296a14();
extern int FUN_80296e60();
extern undefined4 FUN_80297334();

extern undefined4 DAT_803a4ed8;
extern undefined4 DAT_803dc5f2;
extern undefined4* DAT_803dd6d0;
extern undefined4 gCamcontrolTargetState;
extern undefined4 DAT_803de143;
extern undefined4 DAT_803de144;
extern undefined4 DAT_803de188;
extern undefined4 DAT_803de18c;
extern undefined4 gCamcontrolCurrentActionId;
extern undefined4* gCamcontrolState;
extern undefined4 DAT_803de1a0;
extern undefined4* DAT_803de1a8;
extern f64 DOUBLE_803e2318;
extern f32 FLOAT_803de1a4;
extern f32 FLOAT_803e2304;
extern f32 FLOAT_803e2308;
extern f32 FLOAT_803e2314;
extern f32 FLOAT_803e2320;
extern f32 FLOAT_803e2324;
extern f32 FLOAT_803e2328;
extern f32 FLOAT_803e232c;
extern f32 FLOAT_803e2330;
extern f32 FLOAT_803e2334;
extern f32 FLOAT_803e2338;
extern f32 FLOAT_803e233c;
extern f32 FLOAT_803e2340;
extern f32 FLOAT_803e2344;
extern f32 FLOAT_803e2348;
extern f32 FLOAT_803e234c;

/*
 * --INFO--
 *
 * Function: FUN_80103648
 * EN v1.0 Address: 0x80103648
 * EN v1.0 Size: 240b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80103648(double param_1,double param_2,double param_3,undefined4 param_4)
{
  FUN_800033a8(gCamcontrolState,0,0x144);
  *(float *)(gCamcontrolState + 0xc) = (float)param_1;
  *(float *)(gCamcontrolState + 0x10) = (float)param_2;
  *(float *)(gCamcontrolState + 0x14) = (float)param_3;
  *(float *)(gCamcontrolState + 0x18) = (float)param_1;
  *(float *)(gCamcontrolState + 0x1c) = (float)param_2;
  *(float *)(gCamcontrolState + 0x20) = (float)param_3;
  *(float *)(gCamcontrolState + 0xa8) = (float)param_1;
  *(float *)(gCamcontrolState + 0xac) = (float)param_2;
  *(float *)(gCamcontrolState + 0xb0) = (float)param_3;
  *(float *)(gCamcontrolState + 0xb8) = (float)param_1;
  *(float *)(gCamcontrolState + 0xbc) = (float)param_2;
  *(float *)(gCamcontrolState + 0xc0) = (float)param_3;
  *(undefined4 *)(gCamcontrolState + 0xa4) = param_4;
  *(float *)(gCamcontrolState + 0xb4) = FLOAT_803e2304;
  gCamcontrolTargetState = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80103738
 * EN v1.0 Address: 0x80103738
 * EN v1.0 Size: 40b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80103738(void)
{
  FUN_800134f4();
  DAT_803de143 = 0xff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80103760
 * EN v1.0 Address: 0x80103760
 * EN v1.0 Size: 96b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80103760(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  gCamcontrolState = &DAT_803a4ed8;
  uVar2 = 0;
  uVar3 = 0x144;
  iVar1 = FUN_800033a8(-0x7fc5b128,0,0x144);
  FUN_80013590(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,uVar2,uVar3,
               in_r6,in_r7,in_r8,in_r9,in_r10);
  gCamcontrolCurrentActionId = 0xffffffff;
  DAT_803de18c = 0xffffffff;
  DAT_803de188 = 0xffffffff;
  DAT_803de144 = 0;
  DAT_803de143 = 0xff;
  DAT_803dc5f2 = 0xffff;
  return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_traceMove
 * EN v1.0 Address: 0x801037C0
 * EN v1.0 Size: 316b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
camcontrol_traceMove(double param_1,float *param_2,float *param_3,float *param_4,int param_5,
                     undefined param_6,char param_7,char param_8)
{
  char cVar2;
  undefined4 uVar1;
  float local_40 [3];
  uint auStack_34 [9];
  
  if (param_4 == (float *)0x0) {
    param_4 = local_40;
  }
  *param_4 = *param_3;
  param_4[1] = param_3[1];
  param_4[2] = param_3[2];
  *(float *)(param_5 + 0x40) = (float)param_1;
  *(undefined *)(param_5 + 0x50) = 0xff;
  *(undefined *)(param_5 + 0x54) = param_6;
  *(undefined2 *)(param_5 + 0x6c) = 0;
  cVar2 = '\0';
  if (param_8 != '\0') {
    cVar2 = FUN_80064248(param_2,param_4,(float *)0x1,(int *)0x0,(int *)0x0,0x10,0xffffffff,0xff,0);
  }
  DAT_803de1a0 = cVar2;
  if (param_7 != '\0') {
    trackDolphin_buildSweptBounds(auStack_34,param_2,param_4,(float *)(param_5 + 0x40),1);
    FUN_8006933c(0,auStack_34,0x240,'\x01');
  }
  FUN_80067ad4();
  uVar1 = 0;
  if ((DAT_803de1a0 == '\0') && (*(short *)(param_5 + 0x6c) == 0)) {
    uVar1 = 1;
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_801038fc
 * EN v1.0 Address: 0x801038FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801038fc(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_traceFromTarget
 * EN v1.0 Address: 0x80103900
 * EN v1.0 Size: 164b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined camcontrol_traceFromTarget(float *param_1,int param_2,float *param_3)
{
  float local_88;
  float local_84;
  undefined4 local_80;
  undefined auStack_7c [110];
  undefined local_e;
  
  if (*(short *)(param_2 + 0x44) == 1) {
    FUN_80297334(param_2,&local_88,&local_84,&local_80);
  }
  else {
    local_88 = *(float *)(param_2 + 0x18);
    local_84 = *(float *)(param_2 + 0x1c) + *(float *)(DAT_803de1a8 + 0x8c);
    local_80 = *(undefined4 *)(param_2 + 0x20);
  }
  camcontrol_traceMove((double)FLOAT_803e2308,&local_88,param_1,param_3,(int)auStack_7c,3,'\x01',
                       '\x01');
  return local_e;
}

/*
 * --INFO--
 *
 * Function: camcontrol_getTargetPosition
 * EN v1.0 Address: 0x801039A4
 * EN v1.0 Size: 584b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined camcontrol_getTargetPosition(int param_1,short *param_2,float *param_3,short *param_4)
{
  float fVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined auStack_d8 [4];
  float local_d4;
  undefined auStack_d0 [4];
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  undefined auStack_b0 [110];
  undefined local_42;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  uStack_3c = (int)*param_2 ^ 0x80000000;
  local_40 = 0x43300000;
  dVar6 = (double)FUN_802945e0();
  uStack_34 = (int)*param_2 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar7 = (double)FUN_80294964();
  local_cc = *(float *)(DAT_803de1a8 + 4) * *(float *)(DAT_803de1a8 + 4) -
             *(float *)(DAT_803de1a8 + 8) * *(float *)(DAT_803de1a8 + 8);
  if (local_cc < FLOAT_803e2314) {
    local_cc = FLOAT_803e2314;
  }
  dVar8 = FUN_80293900((double)local_cc);
  local_cc = (float)dVar8;
  local_c8 = (float)(dVar6 * (double)(float)dVar8 + (double)*(float *)(param_2 + 0xc));
  fVar1 = *(float *)(param_2 + 0xe) + *(float *)(DAT_803de1a8 + 0x8c);
  local_c4 = *(float *)(DAT_803de1a8 + 8) + fVar1;
  local_c0 = (float)(dVar7 * (double)(float)dVar8 + (double)*(float *)(param_2 + 0x10));
  fVar2 = *(float *)(param_2 + 0xc);
  fVar3 = *(float *)(param_2 + 0x10);
  if (param_2[0x22] == 1) {
    FUN_80297334((int)param_2,&local_bc,&local_b8,&local_b4);
    fVar2 = local_bc;
    fVar1 = local_b8;
    fVar3 = local_b4;
  }
  local_b4 = fVar3;
  local_b8 = fVar1;
  local_bc = fVar2;
  camcontrol_traceMove((double)FLOAT_803e2308,&local_bc,&local_c8,param_3,(int)auStack_b0,3,
                       '\x01','\x01');
  (**(code **)(*DAT_803dd6d0 + 0x38))
            ((double)*(float *)(DAT_803de1a8 + 0x8c),param_1,auStack_d0,&local_d4,auStack_d8,
             &local_cc,0);
  local_d4 = *(float *)(param_1 + 0x1c) -
             (*(float *)(param_2 + 0xe) + *(float *)(DAT_803de1a8 + 0x8c));
  uVar4 = FUN_80021884();
  iVar5 = (uVar4 & 0xffff) - (uint)*(ushort *)(param_1 + 2);
  if (0x8000 < iVar5) {
    iVar5 = iVar5 + -0xffff;
  }
  if (iVar5 < -0x8000) {
    iVar5 = iVar5 + 0xffff;
  }
  if (param_4 != (short *)0x0) {
    *param_4 = *(ushort *)(param_1 + 2) + (short)iVar5;
  }
  return local_42;
}

/*
 * --INFO--
 *
 * Function: camcontrol_updateTargetAction
 * EN v1.0 Address: 0x80103BEC
 * EN v1.0 Size: 496b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_updateTargetAction(int param_1,int param_2)
{
  short sVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  ushort uVar5;
  undefined2 local_28;
  undefined local_26;
  undefined local_25;
  undefined4 local_24;
  undefined4 local_20;
  undefined2 local_1c;
  longlong local_18;
  
  if (*(int *)(param_2 + 0xc0) == 0) {
    uVar2 = FUN_80014e9c(0);
    if ((((*(int *)(param_1 + 0x124) == 0) ||
         (((sVar1 = *(short *)(*(int *)(param_1 + 0x124) + 0x44), sVar1 != 0x1c && (sVar1 != 0x2a))
          || (*(short *)(param_2 + 0x44) != 1)))) ||
        ((iVar3 = FUN_80296e60(param_2), iVar3 == 0 || (uVar4 = FUN_8029636c(param_2), uVar4 == 0)))
        ) && ((*(byte *)(param_1 + 0x141) & 2) == 0)) {
      if ((((uVar2 & 0x10) == 0) || (*(short *)(param_2 + 0x44) != 1)) ||
         (iVar3 = FUN_80296a14(param_2), iVar3 == 0)) {
        iVar3 = FUN_80080490();
        if (((iVar3 == 0) && (uVar5 = FUN_80014dc8(0), (uVar5 & 0x40) != 0)) &&
           ((*(ushort *)(param_1 + 6) & 4) == 0)) {
          local_28 = 5;
          local_26 = 1;
          local_25 = 1;
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x43,1,0,4,&local_28,0,0xff);
        }
      }
      else {
        local_24 = *DAT_803de1a8;
        local_20 = DAT_803de1a8[2];
        local_18 = (longlong)(int)(float)DAT_803de1a8[0x23];
        local_1c = (undefined2)(int)(float)DAT_803de1a8[0x23];
        FUN_80101c10(0);
        (**(code **)(*DAT_803dd6d0 + 0x1c))(0x44,1,0,0xc,&local_24,0xf,0xfe);
      }
    }
    else {
      FUN_80101c10(1);
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x49,1,0,4,param_1 + 0x124,0x3c,0xff);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80103ddc
 * EN v1.0 Address: 0x80103DDC
 * EN v1.0 Size: 1280b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80103ddc(void)
{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  uint in_r6;
  int iVar5;
  int iVar6;
  int iVar7;
  short sVar8;
  float *pfVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  short sVar13;
  double dVar14;
  double dVar15;
  double in_f28;
  double in_f29;
  double dVar16;
  double in_f30;
  double dVar17;
  double in_f31;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_2f8;
  undefined auStack_2f4 [4];
  float local_2f0;
  undefined auStack_2ec [4];
  float local_2e8;
  float local_2e4;
  undefined4 local_2e0;
  float local_2dc [21];
  float local_288 [21];
  undefined auStack_234 [136];
  float local_1ac;
  float local_1a8;
  float local_1a4;
  int local_120;
  undefined4 local_80;
  uint uStack_7c;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  psVar3 = (short *)FUN_8028681c();
  FUN_802473cc();
  (**(code **)(*DAT_803dd6d0 + 0x38))
            ((double)*(float *)(DAT_803de1a8 + 0x8c),psVar3,&local_2f0,auStack_2f4,&local_2f8,
             auStack_2ec,0);
  local_120 = *(int *)(psVar3 + 0x52);
  local_2dc[1] = *(float *)(psVar3 + 0xe);
  local_2dc[0] = *(float *)(psVar3 + 0xc);
  local_2dc[2] = *(float *)(psVar3 + 0x10);
  local_288[0] = local_2dc[0];
  local_288[1] = local_2dc[1];
  local_288[2] = local_2dc[2];
  local_1a8 = local_2dc[1];
  if (*(short *)(local_120 + 0x44) == 1) {
    FUN_80297334(local_120,&local_2e8,&local_2e4,&local_2e0);
  }
  else {
    local_2e8 = *(float *)(local_120 + 0x18);
    local_2e4 = *(float *)(local_120 + 0x1c) + *(float *)(DAT_803de1a8 + 0x8c);
    local_2e0 = *(undefined4 *)(local_120 + 0x20);
  }
  iVar7 = 0;
  iVar6 = -1;
  iVar5 = -1;
  sVar13 = 0xaaa;
  pfVar10 = local_288;
  pfVar9 = local_2dc;
  pfVar11 = pfVar9;
  pfVar12 = pfVar10;
  for (sVar8 = 0xf; sVar8 < 0x5b; sVar8 = sVar8 + 0xf) {
    if (iVar6 == -1) {
      dVar16 = (double)local_2f8;
      dVar17 = (double)local_2f0;
      iVar4 = *(int *)(psVar3 + 0x52);
      uStack_7c = (int)sVar13 ^ 0x80000000;
      local_80 = 0x43300000;
      dVar14 = (double)FUN_802945e0();
      dVar15 = (double)FUN_80294964();
      dVar17 = (double)(float)(dVar17 * dVar15 - (double)(float)(dVar16 * dVar14));
      local_1ac = (float)(dVar17 + (double)*(float *)(iVar4 + 0x18));
      fVar1 = (float)(dVar17 * dVar14 + (double)(float)(dVar16 * dVar15)) + *(float *)(iVar4 + 0x20)
      ;
      local_1a4 = fVar1;
      pfVar12[3] = local_1ac;
      pfVar12[4] = local_1a8;
      pfVar12[5] = fVar1;
      iVar4 = camcontrol_traceMove((double)FLOAT_803e2320,&local_2e8,&local_1ac,(float *)0x0,
                                   (int)auStack_234,7,'\0','\0');
      if (iVar4 != 0) {
        iVar6 = iVar7;
      }
    }
    if (iVar5 == -1) {
      dVar16 = (double)local_2f8;
      dVar17 = (double)local_2f0;
      iVar4 = *(int *)(psVar3 + 0x52);
      uStack_7c = (int)(short)(sVar8 * -0xb6) ^ 0x80000000;
      local_80 = 0x43300000;
      dVar14 = (double)FUN_802945e0();
      dVar15 = (double)FUN_80294964();
      dVar17 = (double)(float)(dVar17 * dVar15 - (double)(float)(dVar16 * dVar14));
      local_1ac = (float)(dVar17 + (double)*(float *)(iVar4 + 0x18));
      fVar1 = (float)(dVar17 * dVar14 + (double)(float)(dVar16 * dVar15)) + *(float *)(iVar4 + 0x20)
      ;
      local_1a4 = fVar1;
      pfVar11[3] = local_1ac;
      pfVar11[4] = local_1a8;
      pfVar11[5] = fVar1;
      iVar4 = camcontrol_traceMove((double)FLOAT_803e2320,&local_2e8,&local_1ac,(float *)0x0,
                                   (int)auStack_234,7,'\0','\0');
      if (iVar4 != 0) {
        iVar5 = iVar7;
      }
    }
    pfVar12 = pfVar12 + 3;
    pfVar11 = pfVar11 + 3;
    iVar7 = iVar7 + 1;
    sVar13 = sVar13 + 0xaaa;
  }
  if (iVar6 == -1) {
    iVar6 = 6;
  }
  else {
    for (iVar7 = 0; iVar7 <= iVar6; iVar7 = iVar7 + 1) {
      iVar4 = camcontrol_traceMove((double)FLOAT_803e2320,pfVar10,local_288 + (iVar7 + 1) * 3,
                                   (float *)0x0,(int)auStack_234,7,'\0','\0');
      if (iVar4 == 0) {
        iVar6 = 6;
        break;
      }
      pfVar10 = pfVar10 + 3;
    }
  }
  if (iVar5 == -1) {
    iVar5 = 6;
  }
  else {
    for (iVar7 = 0; iVar7 <= iVar5; iVar7 = iVar7 + 1) {
      iVar4 = camcontrol_traceMove((double)FLOAT_803e2320,pfVar9,local_2dc + (iVar7 + 1) * 3,
                                   (float *)0x0,(int)auStack_234,7,'\0','\0');
      if (iVar4 == 0) {
        iVar5 = 6;
        break;
      }
      pfVar9 = pfVar9 + 3;
    }
  }
  iVar7 = 0;
  if (iVar6 < iVar5) {
    iVar7 = 1;
  }
  else if (iVar5 < iVar6) {
    iVar7 = -1;
  }
  else if (iVar6 < 6) {
    iVar7 = 1;
  }
  if (iVar7 != 0) {
    uStack_7c = (0x8000 - *psVar3) - (in_r6 & 0xffff);
    if (0x8000 < (int)uStack_7c) {
      uStack_7c = uStack_7c - 0xffff;
    }
    if ((int)uStack_7c < -0x8000) {
      uStack_7c = uStack_7c + 0xffff;
    }
    if ((int)uStack_7c < 0) {
      uStack_7c = -uStack_7c;
    }
    fVar1 = *(float *)(psVar3 + 0x62) * *(float *)(psVar3 + 0x62);
    if (fVar1 < FLOAT_803e2324) {
      fVar1 = FLOAT_803e2324;
    }
    uStack_7c = uStack_7c ^ 0x80000000;
    local_80 = 0x43300000;
    fVar1 = FLOAT_803e232c + fVar1 * FLOAT_803e2328 +
            (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e2318) / FLOAT_803e2330;
    if (fVar1 < FLOAT_803e2334) {
      fVar1 = FLOAT_803e2334;
    }
    if (FLOAT_803e2338 < fVar1) {
      fVar1 = FLOAT_803e2338;
    }
    if (iVar7 == -1) {
      fVar1 = -fVar1;
    }
    fVar1 = fVar1 * FLOAT_803de1a4 + *(float *)(DAT_803de1a8 + 0x28);
    fVar2 = FLOAT_803e233c;
    if ((fVar1 <= FLOAT_803e233c) && (fVar2 = fVar1, fVar1 < FLOAT_803e2340)) {
      fVar2 = FLOAT_803e2340;
    }
    *(float *)(DAT_803de1a8 + 0x28) = fVar2;
  }
  FUN_80286868();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801042dc
 * EN v1.0 Address: 0x801042DC
 * EN v1.0 Size: 1280b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801042dc(void)
{
}
