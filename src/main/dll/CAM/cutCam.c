#include "ghidra_import.h"
#include "main/dll/CAM/cutCam.h"


#pragma peephole off
#pragma scheduling off
extern int FUN_800033a8();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_800068f8();
extern undefined4 FUN_80006a88();
extern undefined4 FUN_80006a8c();
extern ushort FUN_80006be8();
extern uint FUN_80006c00();
extern f32 curveFn_80010dc0(f32 param_1,float *param_2,float *param_3);
extern ushort getPadFn_80014d9c(int controller);
extern ushort getButtonsJustPressed(int controller);
extern uint FUN_80017730();
extern int objBboxFn_800640cc(float *p1, float *p2, float *p3, int *p4, int *p5, int p6, int p7, int p8, int p9);
extern void hitDetectFn_80067958(int a, float *b, float *c, int d, int e, int f);
extern void hitDetectFn_800691c0(int a, void *b, int c, int d);
extern void fn_8006961C(uint *boundsOut,float *startPoints,float *endPoints,
                        float *radii,int pointCount);
extern int FUN_8007f7c0();
extern int getCurSeqNo();
extern void cameraSetInterpMode(u8);
extern undefined4 camcontrol_applyState();
extern undefined4 FUN_802473cc();
extern undefined4 FUN_8028681c();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286868();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint FUN_80294bf4();
extern int FUN_80294c88();
extern int FUN_80294d10();
extern undefined4 FUN_80294d78();
extern void cameraGetPrevPos2();
extern int fn_80295C0C(int);
extern int objFn_802962b4(int);
extern int objFn_80296700(int);
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern f32 sqrtf(f32 x);
extern int getAngle(f32 dx, f32 dy);

extern undefined4 DAT_803a4ed8;
extern undefined4 gCamcontrolTargetTypeMask;
extern undefined4* DAT_803dd6d0;
extern int *gCameraInterface;
extern undefined4 gCamcontrolTargetState;
extern undefined4 DAT_803de143;
extern undefined4 DAT_803de144;
extern undefined4 DAT_803de188;
extern undefined4 DAT_803de18c;
extern undefined4 gCamcontrolCurrentActionId;
extern undefined4* gCamcontrolState;
extern u8 lbl_803DD528;
extern undefined4* gCamcontrolModeSettings;
extern f32 *cameraMtxVar57;
extern u8 framesThisStep;
extern f64 DOUBLE_803e2318;
extern f64 lbl_803E1698;
extern f32 lbl_803E1688;
extern f32 lbl_803E168C;
extern f32 lbl_803E1690;
extern f32 lbl_803E1694;
extern f32 lbl_803E16A4;
extern f32 lbl_803E16AC;
extern f32 lbl_803DE1A4;
extern f32 lbl_803E2304;
extern f32 lbl_803E2308;
extern f32 lbl_803E2314;
extern f32 lbl_803E2320;
extern f32 lbl_803E2324;
extern f32 lbl_803E2328;
extern f32 lbl_803E232C;
extern f32 lbl_803E2330;
extern f32 lbl_803E2334;
extern f32 lbl_803E2338;
extern f32 lbl_803E233C;
extern f32 lbl_803E2340;
extern f32 lbl_803E2344;
extern f32 lbl_803E2348;
extern f32 lbl_803E234C;

/*
 * --INFO--
 *
 * Function: camcontrol_traceMove
 * EN v1.0 Address: 0x80103768
 * EN v1.0 Size: 284b
 * EN v1.1 Address: 0x801037C0
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
undefined4
camcontrol_traceMove(float param_1,float *param_2,float *param_3,float *param_4,int param_5,
                     char param_6,u8 param_7,u8 param_8)
{
  u8 cVar2;
  undefined4 uVar1;
  float local_40 [3];
  uint auStack_34 [9];

  if (param_4 == (float *)0x0) {
    param_4 = local_40;
  }
  *param_4 = *param_3;
  param_4[1] = param_3[1];
  param_4[2] = param_3[2];
  *(float *)(param_5 + 0x40) = param_1;
  *(s8 *)(param_5 + 0x50) = -1;
  *(s8 *)(param_5 + 0x54) = param_6;
  cVar2 = '\0';
  *(undefined2 *)(param_5 + 0x6c) = 0;
  if (param_8 != '\0') {
    cVar2 = objBboxFn_800640cc(param_2,param_4,(float *)0x1,(int *)0x0,(int *)0x0,0x10,0xffffffff,0xff,0);
  }
  lbl_803DD528 = cVar2;
  if (param_7 != '\0') {
    fn_8006961C(auStack_34,param_2,param_4,(float *)(param_5 + 0x40),1);
    hitDetectFn_800691c0(0,auStack_34,0x240,'\x01');
  }
  hitDetectFn_80067958(0, param_2, param_4, 1, param_5, 0);
  uVar1 = 0;
  if ((lbl_803DD528 == '\0') && (*(short *)(param_5 + 0x6c) == 0)) {
    uVar1 = 1;
  }
  return uVar1;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: camcontrol_traceFromTarget
 * EN v1.0 Address: 0x80103888
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80103900
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined camcontrol_traceFromTarget(float *param_1,int param_2,float *param_3)
{
  float local_88;
  float local_84;
  float local_80;
  undefined auStack_7c [111];

  if (*(short *)(param_2 + 0x44) == 1) {
    cameraGetPrevPos2(param_2,&local_88,&local_84,&local_80);
  }
  else {
    local_88 = *(float *)(param_2 + 0x18);
    local_84 = *(float *)(param_2 + 0x1c) + cameraMtxVar57[0x23];
    local_80 = *(float *)(param_2 + 0x20);
  }
  camcontrol_traceMove((double)lbl_803E1688,&local_88,param_1,param_3,(int)auStack_7c,3,'\x01',
                       '\x01');
  return auStack_7c[110];
}

/*
 * --INFO--
 *
 * Function: camcontrol_getTargetPosition
 * EN v1.0 Address: 0x801039C4
 * EN v1.0 Size: 596b
 * EN v1.1 Address: 0x801039A4
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
undefined camcontrol_getTargetPosition(int param_1,short *param_2,float *param_3,short *param_4)
{
  uint uVar4;
  int iVar5;
  f32 cosv;
  f32 sinv;
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

  cosv = fn_80293E80(lbl_803E168C * (f32)*param_2 / lbl_803E1690);
  sinv = sin(lbl_803E168C * (f32)*param_2 / lbl_803E1690);
  local_cc = cameraMtxVar57[1] * cameraMtxVar57[1] - cameraMtxVar57[2] * cameraMtxVar57[2];
  if (local_cc < lbl_803E1694) {
    local_cc = lbl_803E1694;
  }
  local_cc = sqrtf(local_cc);
  local_c8 = cosv * local_cc + *(float *)(param_2 + 0xc);
  local_c4 = cameraMtxVar57[2] + (*(float *)(param_2 + 0xe) + cameraMtxVar57[0x23]);
  local_c0 = sinv * local_cc + *(float *)(param_2 + 0x10);
  if (param_2[0x22] == 1) {
    cameraGetPrevPos2((int)param_2,&local_bc,&local_b8,&local_b4);
  }
  else {
    local_bc = *(float *)(param_2 + 0xc);
    local_b8 = *(float *)(param_2 + 0xe) + cameraMtxVar57[0x23];
    local_b4 = *(float *)(param_2 + 0x10);
  }
  camcontrol_traceMove((double)lbl_803E1688,&local_bc,&local_c8,param_3,(int)auStack_b0,3,
                       '\x01','\x01');
  (**(code **)(*gCameraInterface + 0x38))
            ((double)cameraMtxVar57[0x23],param_1,auStack_d0,&local_d4,auStack_d8,
             &local_cc,0);
  local_d4 = *(float *)(param_1 + 0x1c) -
             (*(float *)(param_2 + 0xe) + cameraMtxVar57[0x23]);
  uVar4 = getAngle(local_d4,local_cc);
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
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: camcontrol_updateTargetAction
 * EN v1.0 Address: 0x80103C18
 * EN v1.0 Size: 488b
 * EN v1.1 Address: 0x80103BEC
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void camcontrol_updateTargetAction(int param_1,int param_2)
{
  short sVar1;
  uint uVar2;
  int iVar3;
  CamcontrolAction43Payload local_28;
  CamcontrolAction44Payload local_24;
  longlong local_18;
  
  if (*(void **)(param_2 + 0xc0) == NULL) {
    uVar2 = getButtonsJustPressed(0);
    if (*(void **)(param_1 + 0x124) != NULL) {
      sVar1 = *(short *)(*(int *)(param_1 + 0x124) + 0x44);
      if (((sVar1 == 0x1c) || (sVar1 == 0x2a)) && (*(short *)(param_2 + 0x44) == 1)) {
        iVar3 = objFn_80296700(param_2);
        if ((iVar3 != 0) && (iVar3 = fn_80295C0C(param_2), iVar3 != 0)) {
          goto action_49;
        }
      }
    }
    if ((*(byte *)(param_1 + 0x141) & 2) != 0) {
      goto action_49;
    }
    goto check_action_44;
action_49:
    cameraSetInterpMode(1);
    (*(code *)(*gCameraInterface + 0x1c))(0x49,1,0,4,param_1 + 0x124,0x3c,0xff);
    goto done;
check_action_44:
    if ((((uVar2 & 0x10) != 0) && (*(short *)(param_2 + 0x44) == 1)) &&
       (iVar3 = objFn_802962b4(param_2), iVar3 != 0)) {
      local_24.distance = *cameraMtxVar57;
      local_24.yOffset = cameraMtxVar57[2];
      local_18 = (longlong)(int)cameraMtxVar57[0x23];
      local_24.height = (int)cameraMtxVar57[0x23];
      cameraSetInterpMode(0);
      (*(code *)(*gCameraInterface + 0x1c))(0x44,1,0,0xc,&local_24,0xf,0xfe);
    }
    else {
      iVar3 = getCurSeqNo();
      if (((iVar3 == 0) && (uVar2 = getPadFn_80014d9c(0), (uVar2 & 0x40) != 0)) &&
         ((*(short *)(param_1 + 6) & 4) == 0)) {
        local_28.action = 5;
        local_28.enabled = 1;
        local_28.immediate = 1;
        (*(code *)(*gCameraInterface + 0x1c))(0x43,1,0,4,&local_28,0,0xff);
      }
    }
    goto done;
done:
    ;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: cameraFn_80103b40
 * EN v1.0 Address: 0x80103B40
 * EN v1.0 Size: 1280b
 *
 * NOTE: body inherited from Ghidra-imported v1.1 FUN_80103e00 (v1.1 size 1280b
 * matches asm v1.0 size). Signature/byte-match is approximate.
 */
void cameraFn_80103b40(void)
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
            ((double)*(float *)(gCamcontrolModeSettings + 0x8c),psVar3,&local_2f0,auStack_2f4,
             &local_2f8,
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
    FUN_80294d78(local_120,&local_2e8,&local_2e4,&local_2e0);
  }
  else {
    local_2e8 = *(float *)(local_120 + 0x18);
    local_2e4 = *(float *)(local_120 + 0x1c) + *(float *)(gCamcontrolModeSettings + 0x8c);
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
      dVar14 = (double)FUN_80293f90();
      dVar15 = (double)FUN_80294964();
      dVar17 = (double)(float)(dVar17 * dVar15 - (double)(float)(dVar16 * dVar14));
      local_1ac = (float)(dVar17 + (double)*(float *)(iVar4 + 0x18));
      fVar1 = (float)(dVar17 * dVar14 + (double)(float)(dVar16 * dVar15)) + *(float *)(iVar4 + 0x20)
      ;
      local_1a4 = fVar1;
      pfVar12[3] = local_1ac;
      pfVar12[4] = local_1a8;
      pfVar12[5] = fVar1;
      iVar4 = camcontrol_traceMove((double)lbl_803E2320,&local_2e8,&local_1ac,(float *)0x0,
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
      dVar14 = (double)FUN_80293f90();
      dVar15 = (double)FUN_80294964();
      dVar17 = (double)(float)(dVar17 * dVar15 - (double)(float)(dVar16 * dVar14));
      local_1ac = (float)(dVar17 + (double)*(float *)(iVar4 + 0x18));
      fVar1 = (float)(dVar17 * dVar14 + (double)(float)(dVar16 * dVar15)) + *(float *)(iVar4 + 0x20)
      ;
      local_1a4 = fVar1;
      pfVar11[3] = local_1ac;
      pfVar11[4] = local_1a8;
      pfVar11[5] = fVar1;
      iVar4 = camcontrol_traceMove((double)lbl_803E2320,&local_2e8,&local_1ac,(float *)0x0,
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
      iVar4 = camcontrol_traceMove((double)lbl_803E2320,pfVar10,local_288 + (iVar7 + 1) * 3,
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
      iVar4 = camcontrol_traceMove((double)lbl_803E2320,pfVar9,local_2dc + (iVar7 + 1) * 3,
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
    if (fVar1 < lbl_803E2324) {
      fVar1 = lbl_803E2324;
    }
    uStack_7c = uStack_7c ^ 0x80000000;
    local_80 = 0x43300000;
    fVar1 = lbl_803E232C + fVar1 * lbl_803E2328 +
            (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e2318) / lbl_803E2330;
    if (fVar1 < lbl_803E2334) {
      fVar1 = lbl_803E2334;
    }
    if (lbl_803E2338 < fVar1) {
      fVar1 = lbl_803E2338;
    }
    if (iVar7 == -1) {
      fVar1 = -fVar1;
    }
    fVar1 = fVar1 * lbl_803DE1A4 + *(float *)(gCamcontrolModeSettings + 0x28);
    fVar2 = lbl_803E233C;
    if ((fVar1 <= lbl_803E233C) && (fVar2 = fVar1, fVar1 < lbl_803E2340)) {
      fVar2 = lbl_803E2340;
    }
    *(float *)(gCamcontrolModeSettings + 0x28) = fVar2;
  }
  FUN_80286868();
  return;
}

/*
 * --INFO--
 *
 * Function: camMoveFn_80104040
 * EN v1.0 Address: 0x80104040
 * EN v1.0 Size: 1280b
 *
 * TODO: stub. Body is 1280b move/animation update; needs reverse-engineering.
 * Adding so the function set aligns with v1.0 asm.
 */
void camMoveFn_80104040(void)
{
}

/*
 * --INFO--
 *
 * Function: camcontrol_updateModeSettings
 * EN v1.0 Address: 0x80104540
 * EN v1.0 Size: 436b
 *
 * TODO: stub. Body adjusts gCamcontrolModeSettings fields with clamping.
 */
void camcontrol_updateModeSettings(int camera)
{
  f32 blend;
  float curve[4];
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  if (*(s16 *)((int)cameraMtxVar57 + 0x82) != 0) {
    *(u16 *)((int)cameraMtxVar57 + 0x82) =
         *(s16 *)((int)cameraMtxVar57 + 0x82) - (u16)framesThisStep;
    if (*(s16 *)((int)cameraMtxVar57 + 0x82) < 0) {
      *(undefined2 *)((int)cameraMtxVar57 + 0x82) = 0;
    }
    uStack_14 = (int)*(s16 *)(cameraMtxVar57 + 0x21) -
                (int)*(s16 *)((int)cameraMtxVar57 + 0x82) ^ 0x80000000;
    local_18 = 0x43300000;
    uStack_c = (int)*(s16 *)(cameraMtxVar57 + 0x21) ^ 0x80000000;
    local_10 = 0x43300000;
    curve[0] = lbl_803E16AC;
    curve[1] = lbl_803E16A4;
    curve[2] = lbl_803E16AC;
    curve[3] = lbl_803E16AC;
    blend = curveFn_80010dc0((float)(*(f64 *)&local_18 - lbl_803E1698) /
                             (float)(*(f64 *)&local_10 - lbl_803E1698),curve,(float *)0x0);
    cameraMtxVar57[0x23] =
         blend * (cameraMtxVar57[0x25] - cameraMtxVar57[0x24]) + cameraMtxVar57[0x24];
    cameraMtxVar57[0] =
         blend * (cameraMtxVar57[0xc] - cameraMtxVar57[0xb]) + cameraMtxVar57[0xb];
    cameraMtxVar57[1] =
         blend * (cameraMtxVar57[0xe] - cameraMtxVar57[0xd]) + cameraMtxVar57[0xd];
    cameraMtxVar57[2] =
         blend * (cameraMtxVar57[0x10] - cameraMtxVar57[0xf]) + cameraMtxVar57[0xf];
    cameraMtxVar57[3] =
         blend * (cameraMtxVar57[0x12] - cameraMtxVar57[0x11]) + cameraMtxVar57[0x11];
    cameraMtxVar57[4] =
         blend * (cameraMtxVar57[0x14] - cameraMtxVar57[0x13]) + cameraMtxVar57[0x13];
    cameraMtxVar57[5] =
         blend * (cameraMtxVar57[0x16] - cameraMtxVar57[0x15]) + cameraMtxVar57[0x15];
    cameraMtxVar57[6] =
         blend * (cameraMtxVar57[0x18] - cameraMtxVar57[0x17]) + cameraMtxVar57[0x17];
    cameraMtxVar57[7] =
         blend * (cameraMtxVar57[0x1a] - cameraMtxVar57[0x19]) + cameraMtxVar57[0x19];
    *(float *)(camera + 0xb4) =
         blend * (cameraMtxVar57[0x1c] - cameraMtxVar57[0x1b]) + cameraMtxVar57[0x1b];
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void doNothing_80103660(void) {}
