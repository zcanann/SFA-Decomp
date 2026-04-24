// Function: FUN_80083e00
// Entry: 80083e00
// Size: 912 bytes

/* WARNING: Removing unreachable block (ram,0x80084168) */
/* WARNING: Removing unreachable block (ram,0x80084160) */
/* WARNING: Removing unreachable block (ram,0x80084170) */

void FUN_80083e00(undefined4 param_1,undefined4 param_2,int param_3,char param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  float *pfVar5;
  float *pfVar6;
  undefined4 uVar7;
  double extraout_f1;
  double dVar8;
  undefined8 in_f29;
  double dVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  undefined8 uVar12;
  undefined4 local_138;
  undefined4 local_134;
  float local_130;
  float local_12c;
  undefined4 local_128;
  undefined4 local_124;
  float local_120;
  float local_11c;
  undefined4 local_118;
  undefined4 local_114;
  float local_110;
  float local_10c;
  float local_108 [9];
  float local_e4 [9];
  float local_c0 [10];
  undefined4 local_98;
  uint uStack148;
  undefined4 local_90;
  uint uStack140;
  undefined4 local_88;
  uint uStack132;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar12 = FUN_802860d4();
  iVar1 = (int)((ulonglong)uVar12 >> 0x20);
  iVar3 = (int)uVar12;
  uStack148 = (uint)*(byte *)(iVar3 + 0x2e);
  local_98 = 0x43300000;
  dVar11 = (double)(FLOAT_803df008 *
                   (float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803defe0));
  uStack140 = (uint)*(byte *)(param_3 + 0x2e);
  local_90 = 0x43300000;
  dVar10 = (double)(FLOAT_803df008 *
                   (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803defe0));
  local_118 = *(undefined4 *)(iVar3 + 8);
  uStack132 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
  local_88 = 0x43300000;
  dVar9 = extraout_f1;
  dVar8 = (double)FUN_80293e80((double)((FLOAT_803defe8 *
                                        (float)((double)CONCAT44(0x43300000,uStack132) -
                                               DOUBLE_803defb8)) / FLOAT_803defec));
  local_110 = (float)(dVar11 * dVar8);
  local_114 = *(undefined4 *)(param_3 + 8);
  uStack124 = (int)*(char *)(param_3 + 0x2c) << 8 ^ 0x80000000;
  local_80 = 0x43300000;
  dVar8 = (double)FUN_80293e80((double)((FLOAT_803defe8 *
                                        (float)((double)CONCAT44(0x43300000,uStack124) -
                                               DOUBLE_803defb8)) / FLOAT_803defec));
  local_10c = (float)(dVar10 * dVar8);
  local_128 = *(undefined4 *)(iVar3 + 0xc);
  uStack116 = (int)*(char *)(iVar3 + 0x2d) << 8 ^ 0x80000000;
  local_78 = 0x43300000;
  dVar8 = (double)FUN_80293e80((double)((FLOAT_803defe8 *
                                        (float)((double)CONCAT44(0x43300000,uStack116) -
                                               DOUBLE_803defb8)) / FLOAT_803defec));
  local_120 = (float)(dVar11 * dVar8);
  local_124 = *(undefined4 *)(param_3 + 0xc);
  uStack108 = (int)*(char *)(param_3 + 0x2d) << 8 ^ 0x80000000;
  local_70 = 0x43300000;
  dVar8 = (double)FUN_80293e80((double)((FLOAT_803defe8 *
                                        (float)((double)CONCAT44(0x43300000,uStack108) -
                                               DOUBLE_803defb8)) / FLOAT_803defec));
  local_11c = (float)(dVar10 * dVar8);
  local_138 = *(undefined4 *)(iVar3 + 0x10);
  uStack100 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
  local_68 = 0x43300000;
  dVar8 = (double)FUN_80294204((double)((FLOAT_803defe8 *
                                        (float)((double)CONCAT44(0x43300000,uStack100) -
                                               DOUBLE_803defb8)) / FLOAT_803defec));
  local_130 = (float)(dVar11 * dVar8);
  local_134 = *(undefined4 *)(param_3 + 0x10);
  uStack92 = (int)*(char *)(param_3 + 0x2c) << 8 ^ 0x80000000;
  local_60 = 0x43300000;
  dVar8 = (double)FUN_80294204((double)((FLOAT_803defe8 *
                                        (float)((double)CONCAT44(0x43300000,uStack92) -
                                               DOUBLE_803defb8)) / FLOAT_803defec));
  local_12c = (float)(dVar10 * dVar8);
  FUN_80010018(&local_118,&local_128,&local_138,local_c0,local_e4,local_108,8,&LAB_80010d54);
  *(float *)(iVar1 + 8) = FLOAT_803defb0;
  iVar2 = 0;
  pfVar5 = local_c0;
  pfVar6 = local_e4;
  pfVar4 = local_108;
  iVar3 = iVar1;
  do {
    dVar8 = (double)FUN_802931a0((double)((pfVar4[1] - *pfVar4) * (pfVar4[1] - *pfVar4) +
                                         (pfVar5[1] - *pfVar5) * (pfVar5[1] - *pfVar5) +
                                         (pfVar6[1] - *pfVar6) * (pfVar6[1] - *pfVar6)));
    *(float *)(iVar3 + 0xc) = (float)((double)*(float *)(iVar3 + 8) + dVar8);
    pfVar5 = pfVar5 + 1;
    pfVar6 = pfVar6 + 1;
    pfVar4 = pfVar4 + 1;
    iVar3 = iVar3 + 4;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 8);
  if (param_4 == '\x01') {
    dVar9 = (double)(float)(dVar9 - (double)*(float *)(iVar1 + 0x28));
  }
  *(float *)(iVar1 + 8) = (float)((double)*(float *)(iVar1 + 8) + dVar9);
  *(float *)(iVar1 + 0xc) = (float)((double)*(float *)(iVar1 + 0xc) + dVar9);
  *(float *)(iVar1 + 0x10) = (float)((double)*(float *)(iVar1 + 0x10) + dVar9);
  *(float *)(iVar1 + 0x14) = (float)((double)*(float *)(iVar1 + 0x14) + dVar9);
  *(float *)(iVar1 + 0x18) = (float)((double)*(float *)(iVar1 + 0x18) + dVar9);
  *(float *)(iVar1 + 0x1c) = (float)((double)*(float *)(iVar1 + 0x1c) + dVar9);
  *(float *)(iVar1 + 0x20) = (float)((double)*(float *)(iVar1 + 0x20) + dVar9);
  *(float *)(iVar1 + 0x24) = (float)((double)*(float *)(iVar1 + 0x24) + dVar9);
  *(float *)(iVar1 + 0x28) = (float)((double)*(float *)(iVar1 + 0x28) + dVar9);
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  FUN_80286120();
  return;
}

