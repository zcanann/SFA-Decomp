// Function: FUN_802a71e0
// Entry: 802a71e0
// Size: 708 bytes

/* WARNING: Removing unreachable block (ram,0x802a747c) */
/* WARNING: Removing unreachable block (ram,0x802a7484) */

void FUN_802a71e0(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,float *param_6,float *param_7,uint param_8,uint param_9)

{
  int iVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined8 extraout_f1;
  double dVar8;
  double dVar9;
  undefined8 in_f30;
  undefined8 uVar10;
  undefined8 in_f31;
  double dVar11;
  undefined8 uVar12;
  undefined auStack104 [8];
  float afStack96 [4];
  longlong local_50;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar12 = FUN_802860cc();
  iVar4 = (int)((ulonglong)uVar12 >> 0x20);
  uVar6 = *(undefined4 *)(*(int *)(iVar4 + 0x7c) + *(char *)(iVar4 + 0xad) * 4);
  uVar5 = 0;
  if ((param_9 & 2) != 0) {
    uVar5 = 2;
  }
  if ((param_9 & 0x40) != 0) {
    uVar5 = uVar5 | 4;
  }
  if ((param_9 & 0x10) != 0) {
    uVar5 = uVar5 | 8;
  }
  if ((param_9 & 0x20) != 0) {
    uVar5 = uVar5 | 1;
  }
  uVar3 = param_9 & 4;
  uVar10 = extraout_f1;
  if (uVar3 == 0) {
    FUN_8002f23c((double)FLOAT_803e7ea4,iVar4,(int)uVar12,uVar5);
    FUN_8002edc0(param_2,(double)FLOAT_803e7ea4,iVar4,0);
    FUN_80027e00(uVar10,(double)*(float *)(iVar4 + 8),uVar6,1,0,afStack96,auStack104);
  }
  else {
    FUN_80030334((double)FLOAT_803e7ea4,iVar4);
    FUN_8002fa48(param_2,(double)FLOAT_803e7ea4,iVar4,0);
    FUN_80027e00(uVar10,(double)*(float *)(iVar4 + 8),uVar6,0,0,afStack96,auStack104);
  }
  dVar11 = (double)afStack96[param_8 & 0xff];
  if (dVar11 < (double)FLOAT_803e7ea4) {
    dVar11 = -dVar11;
  }
  if (uVar3 == 0) {
    FUN_8002ed18(iVar4,param_5,0);
    FUN_80027e00(uVar10,(double)*(float *)(iVar4 + 8),uVar6,1,2,afStack96,auStack104);
  }
  else {
    FUN_8002ed6c(iVar4,param_5,0);
    FUN_80027e00(uVar10,(double)*(float *)(iVar4 + 8),uVar6,0,2,afStack96,auStack104);
  }
  dVar9 = (double)afStack96[param_8 & 0xff];
  if (dVar9 < (double)FLOAT_803e7ea4) {
    dVar9 = -dVar9;
  }
  dVar8 = (double)(param_7[3] + *param_6 * *param_7 + param_6[2] * param_7[2]);
  if (dVar8 < (double)FLOAT_803e7ea4) {
    dVar8 = -dVar8;
  }
  fVar2 = (float)(dVar8 - dVar11) / (float)(dVar9 - dVar11);
  if ((param_9 & 1) == 0) {
    if (fVar2 < FLOAT_803e7ea4) {
      fVar2 = -fVar2;
    }
  }
  else if (fVar2 < FLOAT_803e7ea4) {
    fVar2 = FLOAT_803e7ea4;
  }
  if (FLOAT_803e7ee0 < fVar2) {
    fVar2 = FLOAT_803e7ee0;
  }
  iVar1 = (int)(FLOAT_803e7fac * fVar2);
  local_50 = (longlong)iVar1;
  if (uVar3 == 0) {
    FUN_8002ed18(iVar4,param_5,(int)(short)iVar1);
  }
  else {
    FUN_8002ed6c(iVar4,param_5,(int)(short)iVar1);
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  FUN_80286118(iVar1);
  return;
}

