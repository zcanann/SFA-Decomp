#include "ghidra_import.h"
#include "main/dll/TrickyCurve.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017760();
extern int FUN_80017a98();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 TrickyCurve_updateCooldownTrigger();
extern uint FUN_80286838();
extern uint FUN_8028683c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80294c40();
extern int FUN_80294d6c();

extern int gSfxplayerEffectHandles[8];
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern u8 gTrickyCurveBurstCounter;
extern f64 DOUBLE_803e70d8;
extern f64 DOUBLE_803e7108;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e70d0;
extern f32 FLOAT_803e70e0;
extern f32 FLOAT_803e70f0;
extern f32 FLOAT_803e70f4;
extern f32 FLOAT_803e70f8;
extern f32 FLOAT_803e70fc;
extern f32 FLOAT_803e7100;

/*
 * --INFO--
 *
 * Function: TrickyCurve_updateBurstTrigger
 * EN v1.0 Address: 0x8020718C
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x80207250
 * EN v1.1 Size: 792b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void TrickyCurve_updateBurstTrigger(void)
{
  float fVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  char cVar7;
  char cVar8;
  char cVar9;
  short *psVar10;
  undefined8 uVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar4 = FUN_8028683c();
  psVar10 = *(short **)(uVar4 + 0xb8);
  iVar5 = FUN_80017a98();
  iVar6 = 0;
  cVar9 = '\0';
  cVar8 = '\0';
  cVar7 = '\0';
  fVar1 = *(float *)(iVar5 + 0xc) - *(float *)(uVar4 + 0xc);
  dVar12 = (double)fVar1;
  fVar2 = *(float *)(iVar5 + 0x10) - *(float *)(uVar4 + 0x10);
  dVar14 = (double)fVar2;
  fVar3 = *(float *)(iVar5 + 0x14) - *(float *)(uVar4 + 0x14);
  dVar13 = (double)fVar3;
  gTrickyCurveBurstCounter = gTrickyCurveBurstCounter + 1;
  if (dVar12 <= (double)FLOAT_803e70d0) {
    uStack_1c = (int)*psVar10 ^ 0x80000000;
    local_20 = 0x43300000;
    if (-(double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e70d8) < dVar12) {
      iVar6 = 1;
      cVar9 = '\x01';
    }
  }
  if ((double)FLOAT_803e70d0 < dVar12) {
    uStack_1c = (int)*psVar10 ^ 0x80000000;
    local_20 = 0x43300000;
    if (dVar12 < (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e70d8)) {
      iVar6 = iVar6 + 1;
      cVar9 = cVar9 + -1;
    }
  }
  if (dVar13 <= (double)FLOAT_803e70d0) {
    uStack_1c = (int)psVar10[1] ^ 0x80000000;
    local_20 = 0x43300000;
    if (-(double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e70d8) < dVar13) {
      iVar6 = iVar6 + 1;
      cVar7 = '\x01';
    }
  }
  if ((double)FLOAT_803e70d0 < dVar13) {
    uStack_1c = (int)psVar10[1] ^ 0x80000000;
    local_20 = 0x43300000;
    if (dVar13 < (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e70d8)) {
      iVar6 = iVar6 + 1;
      cVar7 = cVar7 + -1;
    }
  }
  if (dVar14 <= (double)FLOAT_803e70d0) {
    uStack_1c = (int)psVar10[2] ^ 0x80000000;
    local_20 = 0x43300000;
    if (-(double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e70d8) < dVar14) {
      iVar6 = iVar6 + 1;
      cVar8 = '\x01';
    }
  }
  if ((double)FLOAT_803e70d0 < dVar14) {
    uStack_1c = (int)psVar10[2] ^ 0x80000000;
    local_20 = 0x43300000;
    if (dVar14 < (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e70d8)) {
      iVar6 = iVar6 + 1;
      cVar8 = cVar8 + -1;
    }
  }
  if (iVar6 == 3) {
    local_30 = FLOAT_803e70e0;
    local_34 = 0;
    local_36 = 0;
    local_38 = 0;
    if (cVar9 != *(char *)(psVar10 + 8)) {
      local_38 = 0x3fff;
    }
    local_2c = fVar1;
    local_28 = fVar2;
    local_24 = fVar3;
    iVar6 = FUN_80294d6c(iVar5);
    if (iVar6 == 0x1d7) {
      if (0x14 < gTrickyCurveBurstCounter) {
        gTrickyCurveBurstCounter = 0;
        FUN_80017698(0x468,1);
        FUN_80006824(uVar4,0x1c9);
      }
      (**(code **)(*DAT_803dd708 + 8))(iVar5,0x397,0,2,0xffffffff,0);
    }
    else {
      uVar11 = FUN_80017698(0x468,1);
      ObjMsg_SendToObject(uVar11,dVar12,dVar13,dVar14,in_f5,in_f6,in_f7,in_f8,iVar5,0x60004,uVar4,2,in_r7,
                   in_r8,in_r9,in_r10);
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x399,&local_38,2,0xffffffff,0);
      FUN_80006824(uVar4,0x1c9);
    }
  }
  *(char *)(psVar10 + 8) = cVar9;
  *(char *)((int)psVar10 + 0x11) = cVar8;
  *(char *)(psVar10 + 9) = cVar7;
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: TrickyCurve_updateBoundsTrigger
 * EN v1.0 Address: 0x802074FC
 * EN v1.0 Size: 520b
 * EN v1.1 Address: 0x80207568
 * EN v1.1 Size: 604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void TrickyCurve_updateBoundsTrigger(int param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  
  psVar6 = *(short **)(param_1 + 0xb8);
  iVar4 = FUN_80017a98();
  iVar5 = 0;
  fVar1 = *(float *)(iVar4 + 0xc) - *(float *)(param_1 + 0xc);
  fVar2 = *(float *)(iVar4 + 0x10) - *(float *)(param_1 + 0x10);
  fVar3 = *(float *)(iVar4 + 0x14) - *(float *)(param_1 + 0x14);
  if ((fVar1 <= FLOAT_803e70d0) &&
     (-(float)((double)CONCAT44(0x43300000,(int)*psVar6 ^ 0x80000000) - DOUBLE_803e70d8) < fVar1)) {
    iVar5 = 1;
  }
  if ((FLOAT_803e70d0 < fVar1) &&
     (fVar1 < (float)((double)CONCAT44(0x43300000,(int)*psVar6 ^ 0x80000000) - DOUBLE_803e70d8))) {
    iVar5 = iVar5 + 1;
  }
  if ((fVar3 <= FLOAT_803e70d0) &&
     (-(float)((double)CONCAT44(0x43300000,(int)psVar6[1] ^ 0x80000000) - DOUBLE_803e70d8) < fVar3))
  {
    iVar5 = iVar5 + 1;
  }
  if ((FLOAT_803e70d0 < fVar3) &&
     (fVar3 < (float)((double)CONCAT44(0x43300000,(int)psVar6[1] ^ 0x80000000) - DOUBLE_803e70d8)))
  {
    iVar5 = iVar5 + 1;
  }
  if ((fVar2 <= FLOAT_803e70d0) &&
     (-(float)((double)CONCAT44(0x43300000,(int)psVar6[2] ^ 0x80000000) - DOUBLE_803e70d8) < fVar2))
  {
    iVar5 = iVar5 + 1;
  }
  if ((FLOAT_803e70d0 < fVar2) &&
     (fVar2 < (float)((double)CONCAT44(0x43300000,(int)psVar6[2] ^ 0x80000000) - DOUBLE_803e70d8)))
  {
    iVar5 = iVar5 + 1;
  }
  if (iVar5 == 3) {
    FUN_80017760(0xffffffe9,0x17);
    FUN_80017760(0xffffffe9,0x17);
    FUN_80294c40();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: TrickyCurve_updateEffectRingTrigger
 * EN v1.0 Address: 0x80207704
 * EN v1.0 Size: 1292b
 * EN v1.1 Address: 0x802077C4
 * EN v1.1 Size: 1008b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void TrickyCurve_updateEffectRingTrigger(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                                         undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                         undefined8 param_7,undefined8 param_8)
{
  bool bVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  char cVar5;
  char cVar6;
  char cVar7;
  int iVar8;
  short *psVar9;
  double dVar10;
  undefined8 uVar11;
  double in_f29;
  double dVar12;
  double in_f30;
  double dVar13;
  double in_f31;
  double dVar14;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined2 local_78;
  undefined2 local_76;
  undefined2 local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  undefined4 local_60;
  uint uStack_5c;
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
  uVar2 = FUN_80286838();
  psVar9 = *(short **)(uVar2 + 0xb8);
  iVar3 = FUN_80017a98();
  iVar8 = 0;
  cVar7 = '\0';
  cVar6 = '\0';
  cVar5 = '\0';
  dVar14 = (double)(*(float *)(iVar3 + 0xc) - *(float *)(uVar2 + 0xc));
  dVar12 = (double)(*(float *)(iVar3 + 0x10) - *(float *)(uVar2 + 0x10));
  dVar10 = (double)*(float *)(iVar3 + 0x14);
  dVar13 = (double)(float)(dVar10 - (double)*(float *)(uVar2 + 0x14));
  if (((int)psVar9[4] == 0xffffffff) || (uVar4 = FUN_80017690((int)psVar9[4]), uVar4 == 0)) {
    uVar4 = FUN_80017690((int)psVar9[5]);
    if (uVar4 != 0) {
      dVar10 = (double)FUN_80017698((int)psVar9[5],0);
    }
    if (dVar14 <= (double)FLOAT_803e70d0) {
      uStack_5c = (int)*psVar9 ^ 0x80000000;
      local_60 = 0x43300000;
      dVar10 = DOUBLE_803e70d8;
      if (-(double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e70d8) < dVar14) {
        iVar8 = 1;
        cVar7 = '\x01';
      }
    }
    if ((double)FLOAT_803e70d0 < dVar14) {
      uStack_5c = (int)*psVar9 ^ 0x80000000;
      local_60 = 0x43300000;
      dVar10 = DOUBLE_803e70d8;
      if (dVar14 < (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e70d8)) {
        iVar8 = iVar8 + 1;
        cVar7 = cVar7 + -1;
      }
    }
    if (dVar13 <= (double)FLOAT_803e70d0) {
      uStack_5c = (int)psVar9[1] ^ 0x80000000;
      local_60 = 0x43300000;
      dVar10 = DOUBLE_803e70d8;
      if (-(double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e70d8) < dVar13) {
        iVar8 = iVar8 + 1;
        cVar5 = '\x01';
      }
    }
    if ((double)FLOAT_803e70d0 < dVar13) {
      uStack_5c = (int)psVar9[1] ^ 0x80000000;
      local_60 = 0x43300000;
      dVar10 = DOUBLE_803e70d8;
      if (dVar13 < (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e70d8)) {
        iVar8 = iVar8 + 1;
        cVar5 = cVar5 + -1;
      }
    }
    if (dVar12 <= (double)FLOAT_803e70d0) {
      uStack_5c = (int)psVar9[2] ^ 0x80000000;
      local_60 = 0x43300000;
      dVar10 = DOUBLE_803e70d8;
      if (-(double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e70d8) < dVar12) {
        iVar8 = iVar8 + 1;
        cVar6 = '\x01';
      }
    }
    if ((double)FLOAT_803e70d0 < dVar12) {
      uStack_5c = (int)psVar9[2] ^ 0x80000000;
      local_60 = 0x43300000;
      dVar10 = DOUBLE_803e70d8;
      if (dVar12 < (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e70d8)) {
        iVar8 = iVar8 + 1;
        cVar6 = cVar6 + -1;
      }
    }
    if (iVar8 == 3) {
      local_6c = (float)dVar14;
      local_68 = (float)dVar12;
      local_64 = (float)dVar13;
      local_70 = FLOAT_803e70e0;
      local_74 = 0;
      local_76 = 0;
      local_78 = 0;
      if (cVar7 != *(char *)(psVar9 + 8)) {
        local_78 = 0x3fff;
      }
      uVar4 = FUN_80017690(0x1d9);
      if (uVar4 == 0) {
        ObjMsg_SendToObject(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x60004,
                     uVar2,1,in_r7,in_r8,in_r9,in_r10);
        (**(code **)(*DAT_803dd708 + 8))(uVar2,0x5ed,&local_78,2,0xffffffff,0);
        iVar3 = 9;
        do {
          (**(code **)(*DAT_803dd708 + 8))(uVar2,0x5fd,&local_78,2,0xffffffff,0);
          bVar1 = iVar3 != 0;
          iVar3 = iVar3 + -1;
        } while (bVar1);
      }
      else {
        uVar11 = FUN_80017698(0x468,1);
        ObjMsg_SendToObject(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x60004,
                     uVar2,0,in_r7,in_r8,in_r9,in_r10);
        (**(code **)(*DAT_803dd708 + 8))(uVar2,0x5ed,&local_78,2,0xffffffff,0);
        iVar3 = 9;
        do {
          (**(code **)(*DAT_803dd708 + 8))(uVar2,0x5fd,&local_78,2,0xffffffff,0);
          bVar1 = iVar3 != 0;
          iVar3 = iVar3 + -1;
        } while (bVar1);
      }
      FUN_80017698((int)psVar9[5],1);
      FUN_80006824(uVar2,0x1c9);
    }
    *(char *)(psVar9 + 8) = cVar7;
    *(char *)((int)psVar9 + 0x11) = cVar6;
    *(char *)(psVar9 + 9) = cVar5;
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80207c10
 * EN v1.0 Address: 0x80207C10
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80207BB4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80207c10(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: TrickyCurve_updateState
 * EN v1.0 Address: 0x80207C44
 * EN v1.0 Size: 640b
 * EN v1.1 Address: 0x80207BEC
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void TrickyCurve_updateState(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                             undefined8 param_4,undefined8 param_5,undefined8 param_6,
                             undefined8 param_7,undefined8 param_8,int param_9)
{
  char cVar1;
  
  cVar1 = *(char *)(*(int *)(param_9 + 0xb8) + 0xe);
  if (cVar1 == '\0') {
    TrickyCurve_updateEffectRingTrigger(param_1,param_2,param_3,param_4,param_5,param_6,param_7,
                                        param_8);
  }
  else if (cVar1 == '\x01') {
    TrickyCurve_updateBoundsTrigger(param_9);
  }
  else if (cVar1 == '\x02') {
    TrickyCurve_updateBurstTrigger();
  }
  else if (cVar1 == '\x03') {
    TrickyCurve_updateCooldownTrigger();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: sfxplayer_updateEffectHandlePositions
 * EN v1.0 Address: 0x80207EC4
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x80207CC4
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sfxplayer_updateEffectHandlePositions(short *param_1)
{
  int iVar1;
  char cVar2;
  short sVar3;
  int iVar4;
  short sVar5;
  int *piVar6;
  ushort local_38 [4];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  if ((((*(byte *)(iVar4 + 8) >> 4 & 1) != 0) && ((*(byte *)(iVar4 + 8) >> 5 & 1) == 0)) &&
     (0x32 < *(short *)(iVar4 + 4))) {
    FUN_800068c4((uint)param_1,0x459);
    cVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0x56));
    if (cVar2 == '\x02') {
      uStack_1c = (uint)*(byte *)(iVar4 + 7);
      local_20 = 0x43300000;
      iVar1 = (int)((FLOAT_803e70f0 +
                    (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7108)) *
                   FLOAT_803e70f4 * FLOAT_803dc074);
      local_18 = (longlong)iVar1;
      *param_1 = *param_1 + (short)iVar1;
    }
    else {
      local_18 = (longlong)(int)(FLOAT_803e70f4 * FLOAT_803dc074);
      *param_1 = *param_1 + (short)(int)(FLOAT_803e70f4 * FLOAT_803dc074);
    }
  }
  if ((*(short *)(iVar4 + 4) != 0) && ((*(byte *)(iVar4 + 8) >> 4 & 1) != 0)) {
    local_18 = (longlong)(int)FLOAT_803dc074;
    *(short *)(iVar4 + 4) = *(short *)(iVar4 + 4) - (short)(int)FLOAT_803dc074;
    if (*(short *)(iVar4 + 4) < 1) {
      *(undefined2 *)(iVar4 + 4) = 200;
    }
  }
  local_2c = FLOAT_803e70f8;
  local_28 = FLOAT_803e70f8;
  local_24 = FLOAT_803e70f8;
  local_30 = FLOAT_803e70f0;
  sVar5 = 0;
  local_38[2] = 0;
  local_38[1] = 0;
  piVar6 = gSfxplayerEffectHandles;
  for (sVar3 = 0; sVar3 < 4; sVar3 = sVar3 + 1) {
    if (*piVar6 != 0) {
      *(float *)(*piVar6 + 0xc) = FLOAT_803e70f8;
      *(float *)(*piVar6 + 0x10) = FLOAT_803e70fc;
      *(float *)(*piVar6 + 0x14) = FLOAT_803e7100;
      local_38[0] = *param_1 + sVar5;
      FUN_80017748(local_38,(float *)(*piVar6 + 0xc));
      *(float *)(*piVar6 + 0xc) = *(float *)(*piVar6 + 0xc) + *(float *)(param_1 + 6);
      *(float *)(*piVar6 + 0x10) = *(float *)(*piVar6 + 0x10) + *(float *)(param_1 + 8);
      *(float *)(*piVar6 + 0x14) = *(float *)(*piVar6 + 0x14) + *(float *)(param_1 + 10);
    }
    if (piVar6[1] != 0) {
      *(float *)(piVar6[1] + 0xc) = FLOAT_803e70f8;
      *(float *)(piVar6[1] + 0x10) = FLOAT_803e70fc;
      *(float *)(piVar6[1] + 0x14) = FLOAT_803e7100;
      local_38[0] = *param_1 + sVar5;
      FUN_80017748(local_38,(float *)(piVar6[1] + 0xc));
      *(float *)(piVar6[1] + 0xc) = *(float *)(piVar6[1] + 0xc) + *(float *)(param_1 + 6);
      *(float *)(piVar6[1] + 0x10) = *(float *)(piVar6[1] + 0x10) + *(float *)(param_1 + 8);
      *(float *)(piVar6[1] + 0x14) = *(float *)(piVar6[1] + 0x14) + *(float *)(param_1 + 10);
    }
    piVar6 = piVar6 + 2;
    sVar5 = sVar5 + 0x3fff;
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void TrickyCurve_render(void) {}
void TrickyCurve_hitDetect(void) {}
void TrickyCurve_release(void) {}
void TrickyCurve_initialise(void) {}
void sfxplayer_render(void) {}
void sfxplayer_hitDetect(void) {}
