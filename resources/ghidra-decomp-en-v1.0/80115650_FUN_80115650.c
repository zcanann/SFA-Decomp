// Function: FUN_80115650
// Entry: 80115650
// Size: 908 bytes

/* WARNING: Removing unreachable block (ram,0x801159bc) */

void FUN_80115650(undefined4 param_1,undefined4 param_2,int *param_3,int param_4,float *param_5,
                 short *param_6)

{
  uint uVar1;
  short *psVar2;
  undefined4 uVar3;
  int iVar4;
  short sVar5;
  short sVar6;
  int iVar7;
  undefined4 uVar8;
  double extraout_f1;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined8 uVar11;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar11 = FUN_802860d0();
  psVar2 = (short *)((ulonglong)uVar11 >> 0x20);
  iVar7 = (int)uVar11;
  uVar3 = FUN_800394a0();
  iVar4 = *(int *)(iVar7 + 0x54);
  dVar9 = extraout_f1;
  if (iVar4 == 0) {
    dVar10 = (double)FLOAT_803e1cd0;
  }
  else if ((*(byte *)(iVar4 + 0x62) & 2) == 0) {
    if ((*(byte *)(iVar4 + 0x62) & 1) == 0) {
      dVar10 = (double)FLOAT_803e1cd0;
    }
    else {
      dVar10 = (double)(float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(iVar4 + 0x5a) ^ 0x80000000) -
                              DOUBLE_803e1c98);
      dVar9 = DOUBLE_803e1c98;
    }
  }
  else {
    dVar10 = (double)(FLOAT_803e1cdc *
                     (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar4 + 0x5e) ^ 0x80000000)
                            - DOUBLE_803e1c98));
    dVar9 = DOUBLE_803e1c98;
  }
  sVar5 = FUN_800385e8(dVar9,psVar2,iVar7,0);
  if ((*(byte *)(param_4 + 0x611) & 0x10) != 0) {
    FUN_80038f1c(0,1);
    sVar5 = sVar5 + -0x8000;
  }
  if ((*(byte *)(param_4 + 0x611) & 8) == 0) {
    iVar4 = param_4 + 0x1c;
  }
  else {
    iVar4 = 0;
  }
  sVar6 = FUN_8003a380(dVar10,psVar2,iVar7,param_4 + 0x10,iVar4,param_4 + 0x5bc,8,
                       (int)*(short *)(param_4 + 0x60c));
  if ((*(byte *)(param_4 + 0x611) & 8) == 0) {
    uVar3 = FUN_8003a8b4(psVar2,uVar3,*(undefined *)(param_4 + 0x610),param_4 + 0x1c);
    uVar1 = countLeadingZeros(uVar3);
    *(uint *)(param_4 + 0x5f8) = uVar1 >> 5;
  }
  *(undefined4 *)(param_4 + 0x5f8) = 0;
  if (((*(byte *)(param_4 + 0x611) & 2) == 0) || (sVar6 == 0)) {
    if (*(int *)(param_4 + 0x5f8) == 0) {
      if ((-(int)*(short *)(param_4 + 0x60e) < (int)sVar5) &&
         ((int)sVar5 < (int)*(short *)(param_4 + 0x60e))) {
        *param_5 = FLOAT_803e1cc4;
        *param_3 = 0;
        uVar1 = countLeadingZeros((int)sVar6);
        uVar1 = uVar1 >> 5;
        goto LAB_801159bc;
      }
    }
    if ((*param_3 == 0) && (sVar6 != 0)) {
      *param_3 = 1;
      *param_5 = FLOAT_803e1cc4;
    }
    else if (*param_3 != 0) {
      if ((0 < sVar5) && ((int)psVar2[0x50] != (int)param_6[1])) {
        FUN_80030334((double)FLOAT_803e1c90,psVar2,(int)param_6[1],0);
        FUN_8002f574(psVar2,0x1e);
      }
      if ((sVar5 < 0) && ((int)psVar2[0x50] != (int)*param_6)) {
        FUN_80030334((double)FLOAT_803e1c90,psVar2,(int)*param_6,0);
        FUN_8002f574(psVar2,0x1e);
      }
      if (sVar6 == 0) {
        iVar4 = (int)sVar5;
        if (iVar4 < 1) {
          iVar4 = iVar4 / 0x14 + (iVar4 >> 0x1f);
          sVar5 = (short)iVar4 - (short)(iVar4 >> 0x1f);
        }
        else {
          iVar4 = iVar4 / 0x14 + (iVar4 >> 0x1f);
          sVar5 = (short)iVar4 - (short)(iVar4 >> 0x1f);
        }
      }
      else {
        iVar4 = (int)sVar5;
        if (iVar4 < 1) {
          iVar4 = (iVar4 + 0x500) / 0x14 + (iVar4 + 0x500 >> 0x1f);
          sVar5 = (short)iVar4 - (short)(iVar4 >> 0x1f);
        }
        else {
          iVar4 = (iVar4 + -0x500) / 0x14 + (iVar4 + -0x500 >> 0x1f);
          sVar5 = (short)iVar4 - (short)(iVar4 >> 0x1f);
        }
      }
      *psVar2 = *psVar2 + sVar5;
      uVar1 = (uint)sVar5;
      if ((int)uVar1 < 0) {
        uVar1 = -uVar1;
      }
      *param_5 = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e1c98) /
                 FLOAT_803e1ce0;
    }
    uVar1 = 1;
  }
  else {
    *param_3 = 0;
    uVar1 = 0;
  }
LAB_801159bc:
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_8028611c(uVar1);
  return;
}

