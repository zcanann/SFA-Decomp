// Function: FUN_80107b4c
// Entry: 80107b4c
// Size: 1076 bytes

/* WARNING: Removing unreachable block (ram,0x80107f58) */
/* WARNING: Removing unreachable block (ram,0x80107f50) */
/* WARNING: Removing unreachable block (ram,0x80107f60) */

void FUN_80107b4c(short *param_1)

{
  int iVar1;
  float fVar2;
  float fVar3;
  short sVar4;
  short *psVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  float local_108;
  float local_104;
  float local_100;
  short local_fc;
  undefined2 local_fa;
  undefined2 local_f8;
  float local_f4;
  undefined4 local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  undefined auStack228 [68];
  longlong local_a0;
  undefined4 local_98;
  uint uStack148;
  longlong local_90;
  longlong local_88;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  longlong local_60;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  longlong local_48;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  (**(code **)(*DAT_803dca50 + 0x18))();
  psVar5 = *(short **)(param_1 + 0x52);
  if (psVar5 != (short *)0x0) {
    *(float *)(param_1 + 0x5a) = FLOAT_803e1784;
    local_f0 = *(undefined4 *)(psVar5 + 0xc);
    local_ec = *(undefined4 *)(psVar5 + 0xe);
    local_e8 = *(undefined4 *)(psVar5 + 0x10);
    local_f4 = FLOAT_803e1788;
    local_fc = *psVar5;
    local_a0 = (longlong)(int)*(float *)(DAT_803dd540 + 0x30);
    local_fa = (undefined2)(int)*(float *)(DAT_803dd540 + 0x30);
    local_f8 = 0;
    FUN_80021ee8(auStack228,&local_fc);
    FUN_800226cc((double)FLOAT_803e1780,(double)FLOAT_803e178c,(double)FLOAT_803e1780,auStack228,
                 &local_100,&local_104,&local_108);
    *param_1 = -0x8000 - *psVar5;
    *(float *)(DAT_803dd540 + 0x20) =
         FLOAT_803e1790 *
         (FLOAT_803e1794 * *(float *)(DAT_803dd540 + 0x1c) - *(float *)(DAT_803dd540 + 0x20)) +
         *(float *)(DAT_803dd540 + 0x20);
    uStack148 = (int)*param_1 ^ 0x80000000;
    local_98 = 0x43300000;
    iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e17b8) +
                 *(float *)(DAT_803dd540 + 0x20));
    local_90 = (longlong)iVar1;
    *param_1 = (short)iVar1;
    iVar1 = (int)(FLOAT_803e1798 - *(float *)(DAT_803dd540 + 0x30));
    local_88 = (longlong)iVar1;
    sVar4 = (short)iVar1 - param_1[1];
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    param_1[1] = param_1[1] + (sVar4 >> 3);
    uStack124 = (int)*param_1 - 0x4000U ^ 0x80000000;
    local_80 = 0x43300000;
    dVar7 = (double)FUN_80293e80((double)((FLOAT_803e179c *
                                          (float)((double)CONCAT44(0x43300000,uStack124) -
                                                 DOUBLE_803e17b8)) / FLOAT_803e17a0));
    uStack116 = (int)*param_1 - 0x4000U ^ 0x80000000;
    local_78 = 0x43300000;
    dVar8 = (double)FUN_80294204((double)((FLOAT_803e179c *
                                          (float)((double)CONCAT44(0x43300000,uStack116) -
                                                 DOUBLE_803e17b8)) / FLOAT_803e17a0));
    uStack108 = (int)param_1[1] ^ 0x80000000;
    local_70 = 0x43300000;
    dVar9 = (double)FUN_80294204((double)((FLOAT_803e179c *
                                          (float)((double)CONCAT44(0x43300000,uStack108) -
                                                 DOUBLE_803e17b8)) / FLOAT_803e17a0));
    uStack100 = (int)param_1[1] ^ 0x80000000;
    local_68 = 0x43300000;
    dVar10 = (double)FUN_80293e80((double)((FLOAT_803e179c *
                                           (float)((double)CONCAT44(0x43300000,uStack100) -
                                                  DOUBLE_803e17b8)) / FLOAT_803e17a0));
    fVar2 = -*(float *)(DAT_803dd540 + 0x24) / FLOAT_803e17a4;
    fVar3 = FLOAT_803e1780;
    if ((FLOAT_803e1780 <= fVar2) && (fVar3 = fVar2, FLOAT_803e1788 < fVar2)) {
      fVar3 = FLOAT_803e1788;
    }
    *(float *)(DAT_803dd540 + 0x28) =
         FLOAT_803e17a8 *
         ((FLOAT_803e17b0 * fVar3 + FLOAT_803e17ac) - *(float *)(DAT_803dd540 + 0x28)) +
         *(float *)(DAT_803dd540 + 0x28);
    fVar2 = *(float *)(DAT_803dd540 + 0x28);
    dVar9 = (double)(float)((double)fVar2 * dVar9);
    *(float *)(param_1 + 0xc) = local_100 + (float)(dVar9 * dVar8);
    *(float *)(param_1 + 0xe) = local_104 + (float)((double)fVar2 * dVar10);
    *(float *)(param_1 + 0x10) = local_108 + (float)(dVar9 * dVar7);
    iVar1 = (int)(FLOAT_803e17a8 * *(float *)(DAT_803dd540 + 0x2c));
    local_60 = (longlong)iVar1;
    sVar4 = (short)iVar1 - param_1[2];
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    uStack84 = (int)sVar4 ^ 0x80000000;
    local_58 = 0x43300000;
    uStack76 = (int)param_1[2] ^ 0x80000000;
    local_50 = 0x43300000;
    iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e17b8) * FLOAT_803db414
                  * FLOAT_803e17b4 +
                 (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e17b8));
    local_48 = (longlong)iVar1;
    param_1[2] = (short)iVar1;
    FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
                 *(undefined4 *)(param_1 + 0x18));
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  return;
}

