// Function: FUN_801158ec
// Entry: 801158ec
// Size: 908 bytes

/* WARNING: Removing unreachable block (ram,0x80115c58) */
/* WARNING: Removing unreachable block (ram,0x801158fc) */

void FUN_801158ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int *param_11,int param_12,float *param_13,
                 short *param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  ushort *puVar2;
  undefined4 *puVar3;
  int iVar4;
  short sVar6;
  undefined4 uVar5;
  int iVar7;
  short *psVar8;
  undefined4 uVar9;
  int iVar10;
  short sVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_80286834();
  puVar2 = (ushort *)((ulonglong)uVar12 >> 0x20);
  iVar7 = (int)uVar12;
  puVar3 = FUN_80039598();
  if ((*(int *)(iVar7 + 0x54) != 0) && ((*(byte *)(*(int *)(iVar7 + 0x54) + 0x62) & 2) != 0)) {
    param_2 = (double)FLOAT_803e295c;
  }
  iVar4 = FUN_800386e0(puVar2,iVar7,(float *)0x0);
  sVar11 = (short)iVar4;
  if ((*(byte *)(param_12 + 0x611) & 0x10) != 0) {
    FUN_80039014('\0',1);
    sVar11 = sVar11 + -0x8000;
  }
  if ((*(byte *)(param_12 + 0x611) & 8) == 0) {
    iVar4 = param_12 + 0x1c;
  }
  else {
    iVar4 = 0;
  }
  psVar8 = (short *)(param_12 + 0x5bc);
  uVar9 = 8;
  iVar10 = (int)*(short *)(param_12 + 0x60c);
  sVar6 = FUN_8003a478(puVar2,iVar7,(float *)(param_12 + 0x10),iVar4,psVar8,8,
                       *(short *)(param_12 + 0x60c));
  if ((*(byte *)(param_12 + 0x611) & 8) == 0) {
    iVar4 = param_12 + 0x1c;
    uVar5 = FUN_8003a9ac(puVar2,puVar3,(uint)*(byte *)(param_12 + 0x610),iVar4);
    uVar1 = countLeadingZeros(uVar5);
    *(uint *)(param_12 + 0x5f8) = uVar1 >> 5;
  }
  *(undefined4 *)(param_12 + 0x5f8) = 0;
  if (((*(byte *)(param_12 + 0x611) & 2) == 0) || (sVar6 == 0)) {
    if (*(int *)(param_12 + 0x5f8) == 0) {
      if ((-(int)*(short *)(param_12 + 0x60e) < (int)sVar11) &&
         ((int)sVar11 < (int)*(short *)(param_12 + 0x60e))) {
        *param_13 = FLOAT_803e2944;
        *param_11 = 0;
        countLeadingZeros((int)sVar6);
        goto LAB_80115c58;
      }
    }
    if ((*param_11 == 0) && (sVar6 != 0)) {
      *param_11 = 1;
      *param_13 = FLOAT_803e2944;
    }
    else if (*param_11 != 0) {
      if ((0 < sVar11) && ((int)(short)puVar2[0x50] != (int)param_14[1])) {
        FUN_8003042c((double)FLOAT_803e2910,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     puVar2,(int)param_14[1],0,iVar4,psVar8,uVar9,iVar10,param_16);
        FUN_8002f66c((int)puVar2,0x1e);
      }
      if ((sVar11 < 0) && ((int)(short)puVar2[0x50] != (int)*param_14)) {
        FUN_8003042c((double)FLOAT_803e2910,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     puVar2,(int)*param_14,0,iVar4,psVar8,uVar9,iVar10,param_16);
        FUN_8002f66c((int)puVar2,0x1e);
      }
      if (sVar6 == 0) {
        iVar7 = (int)sVar11;
        if (iVar7 < 1) {
          iVar7 = iVar7 / 0x14 + (iVar7 >> 0x1f);
          sVar11 = (short)iVar7 - (short)(iVar7 >> 0x1f);
        }
        else {
          iVar7 = iVar7 / 0x14 + (iVar7 >> 0x1f);
          sVar11 = (short)iVar7 - (short)(iVar7 >> 0x1f);
        }
      }
      else {
        iVar7 = (int)sVar11;
        if (iVar7 < 1) {
          iVar7 = (iVar7 + 0x500) / 0x14 + (iVar7 + 0x500 >> 0x1f);
          sVar11 = (short)iVar7 - (short)(iVar7 >> 0x1f);
        }
        else {
          iVar7 = (iVar7 + -0x500) / 0x14 + (iVar7 + -0x500 >> 0x1f);
          sVar11 = (short)iVar7 - (short)(iVar7 >> 0x1f);
        }
      }
      *puVar2 = *puVar2 + sVar11;
      uVar1 = (uint)sVar11;
      if ((int)uVar1 < 0) {
        uVar1 = -uVar1;
      }
      *param_13 = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e2918) /
                  FLOAT_803e2960;
    }
  }
  else {
    *param_11 = 0;
  }
LAB_80115c58:
  FUN_80286880();
  return;
}

