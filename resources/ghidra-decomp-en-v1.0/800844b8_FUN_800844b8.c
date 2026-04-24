// Function: FUN_800844b8
// Entry: 800844b8
// Size: 1328 bytes

/* WARNING: Removing unreachable block (ram,0x800849c0) */
/* WARNING: Removing unreachable block (ram,0x800849b8) */
/* WARNING: Removing unreachable block (ram,0x800849c8) */

void FUN_800844b8(undefined4 param_1,undefined4 param_2,float *param_3,short *param_4,char param_5)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  short sVar6;
  undefined4 uVar5;
  float *pfVar7;
  int iVar8;
  undefined4 uVar9;
  undefined8 in_f29;
  double dVar10;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined8 uVar14;
  float local_d8;
  undefined auStack212 [4];
  float local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  float local_c4;
  float local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  float local_b4;
  float local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  float local_a4;
  float local_a0;
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
  undefined4 local_58;
  uint uStack84;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar14 = FUN_802860d4();
  puVar1 = (undefined4 *)((ulonglong)uVar14 >> 0x20);
  pfVar7 = (float *)uVar14;
  dVar10 = (double)pfVar7[2];
  FUN_80084190(dVar10);
  iVar2 = (**(code **)(*DAT_803dca9c + 0x1c))(*puVar1);
  if ((iVar2 == 0) || ((int)puVar1[1] < 0)) {
    if (iVar2 == 0) {
      iVar2 = (**(code **)(*DAT_803dca9c + 0x1c))(puVar1[1]);
    }
    if (iVar2 == 0) {
      uVar5 = 0;
      goto LAB_800849b8;
    }
    *param_3 = *(float *)(iVar2 + 8);
    if (param_5 == '\0') {
      param_3[1] = *(float *)(iVar2 + 0xc) + pfVar7[1];
    }
    param_3[2] = *(float *)(iVar2 + 0x10);
    uStack84 = (int)*(char *)(iVar2 + 0x2c) << 8 ^ 0x80000000;
    local_58 = 0x43300000;
    dVar10 = (double)FUN_80294204((double)((FLOAT_803defe8 *
                                           (float)((double)CONCAT44(0x43300000,uStack84) -
                                                  DOUBLE_803defb8)) / FLOAT_803defec));
    *param_3 = (float)((double)*pfVar7 * dVar10 + (double)*param_3);
    uStack92 = (int)*(char *)(iVar2 + 0x2c) << 8 ^ 0x80000000;
    local_60 = 0x43300000;
    dVar10 = (double)FUN_80293e80((double)((FLOAT_803defe8 *
                                           (float)((double)CONCAT44(0x43300000,uStack92) -
                                                  DOUBLE_803defb8)) / FLOAT_803defec));
    param_3[2] = (float)((double)*pfVar7 * dVar10 + (double)param_3[2]);
    *param_4 = (short)((int)*(char *)(iVar2 + 0x2c) << 8) + -0x8000;
  }
  else {
    iVar3 = (**(code **)(*DAT_803dca9c + 0x1c))();
    iVar8 = 0;
    for (puVar4 = puVar1; (iVar8 < 9 && ((double)(float)puVar4[2] <= dVar10)); puVar4 = puVar4 + 1)
    {
      iVar8 = iVar8 + 1;
    }
    uStack148 = iVar8 - 1U ^ 0x80000000;
    local_98 = 0x43300000;
    dVar13 = (double)(((float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803defb8) +
                      (float)(dVar10 - (double)(float)puVar1[iVar8 + 1]) /
                      (float)((double)(float)puVar1[iVar8 + 2] - (double)(float)puVar1[iVar8 + 1]))
                     * FLOAT_803df01c);
    uStack140 = (uint)*(byte *)(iVar2 + 0x2e);
    local_90 = 0x43300000;
    dVar12 = (double)(FLOAT_803df008 *
                     (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803defe0));
    uStack132 = (uint)*(byte *)(iVar3 + 0x2e);
    local_88 = 0x43300000;
    dVar11 = (double)(FLOAT_803df008 *
                     (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803defe0));
    local_ac = *(undefined4 *)(iVar2 + 8);
    uStack124 = (int)*(char *)(iVar2 + 0x2c) << 8 ^ 0x80000000;
    local_80 = 0x43300000;
    dVar10 = (double)FUN_80293e80((double)((FLOAT_803defe8 *
                                           (float)((double)CONCAT44(0x43300000,uStack124) -
                                                  DOUBLE_803defb8)) / FLOAT_803defec));
    local_a4 = (float)(dVar12 * dVar10);
    local_a8 = *(undefined4 *)(iVar3 + 8);
    uStack116 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
    local_78 = 0x43300000;
    dVar10 = (double)FUN_80293e80((double)((FLOAT_803defe8 *
                                           (float)((double)CONCAT44(0x43300000,uStack116) -
                                                  DOUBLE_803defb8)) / FLOAT_803defec));
    local_a0 = (float)(dVar11 * dVar10);
    local_bc = *(undefined4 *)(iVar2 + 0xc);
    uStack108 = (int)*(char *)(iVar2 + 0x2d) << 8 ^ 0x80000000;
    local_70 = 0x43300000;
    dVar10 = (double)FUN_80293e80((double)((FLOAT_803defe8 *
                                           (float)((double)CONCAT44(0x43300000,uStack108) -
                                                  DOUBLE_803defb8)) / FLOAT_803defec));
    local_b4 = (float)(dVar12 * dVar10);
    local_b8 = *(undefined4 *)(iVar3 + 0xc);
    uStack100 = (int)*(char *)(iVar3 + 0x2d) << 8 ^ 0x80000000;
    local_68 = 0x43300000;
    dVar10 = (double)FUN_80293e80((double)((FLOAT_803defe8 *
                                           (float)((double)CONCAT44(0x43300000,uStack100) -
                                                  DOUBLE_803defb8)) / FLOAT_803defec));
    local_b0 = (float)(dVar11 * dVar10);
    local_cc = *(undefined4 *)(iVar2 + 0x10);
    uStack92 = (int)*(char *)(iVar2 + 0x2c) << 8 ^ 0x80000000;
    local_60 = 0x43300000;
    dVar10 = (double)FUN_80294204((double)((FLOAT_803defe8 *
                                           (float)((double)CONCAT44(0x43300000,uStack92) -
                                                  DOUBLE_803defb8)) / FLOAT_803defec));
    local_c4 = (float)(dVar12 * dVar10);
    local_c8 = *(undefined4 *)(iVar3 + 0x10);
    uStack84 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
    local_58 = 0x43300000;
    dVar10 = (double)FUN_80294204((double)((FLOAT_803defe8 *
                                           (float)((double)CONCAT44(0x43300000,uStack84) -
                                                  DOUBLE_803defb8)) / FLOAT_803defec));
    local_c0 = (float)(dVar11 * dVar10);
    dVar10 = (double)FUN_80010dc0(dVar13,&local_ac,&local_d0);
    *param_3 = (float)dVar10;
    if (param_5 == '\0') {
      dVar10 = (double)FUN_80010dc0(dVar13,&local_bc,auStack212);
      param_3[1] = (float)dVar10;
    }
    dVar10 = (double)FUN_80010dc0(dVar13,&local_cc,&local_d8);
    param_3[2] = (float)dVar10;
    dVar10 = (double)FUN_802931a0((double)(local_d0 * local_d0 + local_d8 * local_d8));
    if ((double)FLOAT_803df020 < dVar10) {
      dVar10 = (double)(float)((double)*pfVar7 / dVar10);
      sVar6 = FUN_800217c0((double)local_d0,(double)local_d8);
      *param_4 = sVar6 + -0x8000;
      local_d0 = (float)((double)local_d0 * dVar10);
      local_d8 = (float)((double)local_d8 * dVar10);
      *param_3 = *param_3 + local_d8;
      param_3[2] = param_3[2] - local_d0;
      if (param_5 == '\0') {
        param_3[1] = param_3[1] + pfVar7[1];
      }
    }
  }
  uVar5 = 1;
LAB_800849b8:
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  FUN_80286120(uVar5);
  return;
}

