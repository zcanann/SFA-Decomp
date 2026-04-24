// Function: FUN_80065e50
// Entry: 80065e50
// Size: 632 bytes

/* WARNING: Removing unreachable block (ram,0x800660a0) */
/* WARNING: Removing unreachable block (ram,0x800660a8) */

void FUN_80065e50(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,undefined4 param_7)

{
  uint uVar1;
  float **ppfVar2;
  undefined *puVar3;
  int iVar4;
  float *pfVar5;
  int iVar6;
  bool bVar7;
  int *piVar8;
  undefined4 uVar9;
  double extraout_f1;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  undefined8 uVar11;
  float local_88;
  undefined auStack132 [4];
  float local_80;
  int local_7c;
  int local_78;
  int local_74;
  int local_70;
  int local_6c;
  int local_68;
  longlong local_60;
  longlong local_58;
  longlong local_50;
  longlong local_48;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar11 = FUN_802860dc();
  piVar8 = &DAT_8038dc64;
  dVar10 = extraout_f1;
  if (param_6 < 0) {
    if (param_6 == -1) {
      param_6 = 0;
    }
    else {
      param_6 = 1;
    }
  }
  else {
    local_7c = (int)extraout_f1;
    local_60 = (longlong)local_7c;
    local_78 = (int)(param_2 - (double)FLOAT_803dece8);
    local_58 = (longlong)local_78;
    local_6c = (int)((double)FLOAT_803dece8 + param_2);
    local_50 = (longlong)local_6c;
    local_74 = (int)param_3;
    local_48 = (longlong)local_74;
    local_70 = local_7c;
    local_68 = local_74;
    FUN_800691c0((int)((ulonglong)uVar11 >> 0x20),&local_7c,param_7,1);
  }
  DAT_803dcf68 = &DAT_8038d91c;
  DAT_803dcf64 = &DAT_8038d890;
  DAT_803dcf60 = '\0';
  uVar1 = (uint)DAT_803dcf6c;
  while ((piVar8 < &DAT_8038dc64 + uVar1 * 6 && (DAT_803dcf60 < '#'))) {
    if (*piVar8 == 0) {
      FUN_800659a8(dVar10,param_3,DAT_803dcf30 + *(short *)(piVar8 + 1) * 0x4c,
                   DAT_803dcf30 + *(short *)(piVar8 + 7) * 0x4c,piVar8,param_6);
    }
    else {
      FUN_800226cc(dVar10,(double)FLOAT_803decb4,param_3,piVar8[2],&local_80,auStack132,&local_88);
      FUN_800659a8((double)local_80,(double)local_88,DAT_803dcf30 + *(short *)(piVar8 + 1) * 0x4c,
                   DAT_803dcf30 + *(short *)(piVar8 + 7) * 0x4c,piVar8,param_6);
    }
    piVar8 = piVar8 + 6;
  }
  puVar3 = &DAT_8038d91c;
  iVar4 = 0;
  for (iVar6 = 0; iVar6 < DAT_803dcf60; iVar6 = iVar6 + 1) {
    *(undefined **)(DAT_803dcf64 + iVar4) = puVar3;
    puVar3 = puVar3 + 0x18;
    iVar4 = iVar4 + 4;
  }
  bVar7 = false;
  while (!bVar7) {
    bVar7 = true;
    iVar4 = 0;
    for (iVar6 = 0; iVar6 < DAT_803dcf60 + -1; iVar6 = iVar6 + 1) {
      ppfVar2 = (float **)(DAT_803dcf64 + iVar4);
      pfVar5 = *ppfVar2;
      if (*pfVar5 < *ppfVar2[1]) {
        bVar7 = false;
        *ppfVar2 = ppfVar2[1];
        *(float **)(DAT_803dcf64 + iVar4 + 4) = pfVar5;
      }
      iVar4 = iVar4 + 4;
    }
  }
  *(undefined4 *)uVar11 = &DAT_8038d890;
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  FUN_80286128((int)DAT_803dcf60);
  return;
}

