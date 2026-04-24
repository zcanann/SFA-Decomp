// Function: FUN_80095b18
// Entry: 80095b18
// Size: 408 bytes

/* WARNING: Removing unreachable block (ram,0x80095c90) */

void FUN_80095b18(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  undefined extraout_r4;
  int iVar4;
  undefined4 *puVar5;
  int iVar6;
  undefined4 uVar7;
  double extraout_f1;
  undefined8 in_f31;
  double dVar8;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  puVar1 = (undefined4 *)FUN_802860dc();
  if (0x1e < param_3 + DAT_803dd224) {
    param_3 = 0x1e - DAT_803dd224;
  }
  if (param_3 != 0) {
    dVar8 = (double)(float)((double)FLOAT_803df324 * extraout_f1);
    for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
      iVar4 = 0;
      for (iVar2 = DAT_803dd220; (iVar4 < 0x1e && (*(char *)(iVar2 + 0x18) != -1));
          iVar2 = iVar2 + 0x1c) {
        iVar4 = iVar4 + 1;
      }
      if (iVar4 < 0x1e) {
        puVar5 = (undefined4 *)(DAT_803dd220 + iVar4 * 0x1c);
        uVar3 = FUN_800221a0(0xffffff06,0xfa);
        puVar5[3] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803df308);
        puVar5[3] = (float)((double)(float)puVar5[3] * dVar8);
        uVar3 = FUN_800221a0(0xffffff06,0xfa);
        puVar5[5] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803df308);
        puVar5[5] = (float)((double)(float)puVar5[5] * dVar8);
        uVar3 = FUN_800221a0(200,300);
        puVar5[4] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803df308);
        puVar5[4] = (float)((double)(float)puVar5[4] * dVar8);
        *(undefined *)(puVar5 + 6) = extraout_r4;
        *puVar5 = *puVar1;
        puVar5[1] = puVar1[1];
        puVar5[2] = puVar1[2];
        DAT_803dd224 = DAT_803dd224 + 1;
      }
    }
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286128(param_3);
  return;
}

