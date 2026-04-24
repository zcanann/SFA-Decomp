// Function: FUN_8010fc7c
// Entry: 8010fc7c
// Size: 1084 bytes

/* WARNING: Removing unreachable block (ram,0x80110090) */
/* WARNING: Removing unreachable block (ram,0x80110080) */
/* WARNING: Removing unreachable block (ram,0x80110070) */
/* WARNING: Removing unreachable block (ram,0x80110078) */
/* WARNING: Removing unreachable block (ram,0x80110088) */
/* WARNING: Removing unreachable block (ram,0x80110098) */

void FUN_8010fc7c(short *param_1)

{
  int iVar1;
  short *psVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar10;
  double dVar11;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack216 [2];
  short local_d6;
  short local_d4 [2];
  float local_d0;
  float local_cc;
  float local_c8;
  undefined4 local_c0;
  uint uStack188;
  undefined4 local_b8;
  uint uStack180;
  undefined4 local_b0;
  uint uStack172;
  longlong local_a8;
  undefined4 local_a0;
  uint uStack156;
  undefined4 local_98;
  uint uStack148;
  longlong local_90;
  undefined4 local_88;
  uint uStack132;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  psVar2 = *(short **)(param_1 + 0x52);
  uStack188 = 0x8000U - (int)*param_1 ^ 0x80000000;
  local_c0 = 0x43300000;
  dVar10 = (double)((FLOAT_803e1b00 *
                    (float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803e1b10)) /
                   FLOAT_803e1b04);
  dVar4 = (double)FUN_80293e80(dVar10);
  dVar10 = (double)FUN_80294204(dVar10);
  dVar11 = (double)*(float *)(psVar2 + 0xc);
  local_d0 = (float)(dVar4 * (double)FLOAT_803db9c8 + dVar11);
  local_cc = FLOAT_803e1b08 + *(float *)(psVar2 + 0xe);
  dVar4 = (double)*(float *)(psVar2 + 0x10);
  local_c8 = (float)(dVar10 * (double)FLOAT_803db9c8 + dVar4);
  FUN_80103664(&local_d0,psVar2,&local_d0,auStack216);
  dVar4 = (double)FUN_802931a0((double)((float)((double)local_d0 - dVar11) *
                                        (float)((double)local_d0 - dVar11) +
                                       (float)((double)local_c8 - dVar4) *
                                       (float)((double)local_c8 - dVar4)));
  FLOAT_803dd5b0 = (float)dVar4;
  FLOAT_803dd5a8 = (float)dVar4;
  FUN_8029697c(psVar2,local_d4,&local_d6);
  local_d6 = local_d6 >> 1;
  dVar11 = (double)*(float *)(psVar2 + 0xc);
  dVar10 = (double)(*(float *)(psVar2 + 0xe) + FLOAT_803dd5ac);
  dVar4 = (double)*(float *)(psVar2 + 0x10);
  local_d4[0] = ((-0x8000 - *psVar2) + (local_d4[0] >> 1)) - *param_1;
  if (0x8000 < local_d4[0]) {
    local_d4[0] = local_d4[0] + 1;
  }
  if (local_d4[0] < -0x8000) {
    local_d4[0] = local_d4[0] + -1;
  }
  uStack180 = (int)local_d4[0] ^ 0x80000000;
  local_b8 = 0x43300000;
  dVar5 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,uStack180) -
                                              DOUBLE_803e1b10),(double)FLOAT_803e1b18,
                               (double)FLOAT_803db414);
  uStack172 = (int)*param_1 ^ 0x80000000;
  local_b0 = 0x43300000;
  iVar1 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack172) - DOUBLE_803e1b10) + dVar5);
  local_a8 = (longlong)iVar1;
  *param_1 = (short)iVar1;
  local_d6 = local_d6 - param_1[1];
  if (0x8000 < local_d6) {
    local_d6 = local_d6 + 1;
  }
  if (local_d6 < -0x8000) {
    local_d6 = local_d6 + -1;
  }
  uStack156 = (int)local_d6 ^ 0x80000000;
  local_a0 = 0x43300000;
  dVar6 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,uStack156) -
                                              DOUBLE_803e1b10),(double)FLOAT_803e1b18,
                               (double)FLOAT_803db414);
  dVar5 = DOUBLE_803e1b10;
  uStack148 = (int)param_1[1] ^ 0x80000000;
  local_98 = 0x43300000;
  iVar1 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e1b10) + dVar6);
  local_90 = (longlong)iVar1;
  param_1[1] = (short)iVar1;
  uStack132 = (int)*param_1 - 0x4000U ^ 0x80000000;
  local_88 = 0x43300000;
  dVar6 = (double)FUN_80293e80((double)((FLOAT_803e1b00 *
                                        (float)((double)CONCAT44(0x43300000,uStack132) - dVar5)) /
                                       FLOAT_803e1b04));
  uStack124 = (int)*param_1 - 0x4000U ^ 0x80000000;
  local_80 = 0x43300000;
  dVar7 = (double)FUN_80294204((double)((FLOAT_803e1b00 *
                                        (float)((double)CONCAT44(0x43300000,uStack124) -
                                               DOUBLE_803e1b10)) / FLOAT_803e1b04));
  uStack116 = (int)param_1[1] ^ 0x80000000;
  local_78 = 0x43300000;
  dVar8 = (double)FUN_80294204((double)((FLOAT_803e1b00 *
                                        (float)((double)CONCAT44(0x43300000,uStack116) -
                                               DOUBLE_803e1b10)) / FLOAT_803e1b04));
  uStack108 = (int)param_1[1] ^ 0x80000000;
  local_70 = 0x43300000;
  dVar9 = (double)FUN_80293e80((double)((FLOAT_803e1b00 *
                                        (float)((double)CONCAT44(0x43300000,uStack108) -
                                               DOUBLE_803e1b10)) / FLOAT_803e1b04));
  dVar5 = (double)FLOAT_803dd5a8;
  dVar8 = (double)(float)(dVar5 * dVar8);
  *(float *)(param_1 + 0xc) = (float)(dVar11 + (double)(float)(dVar8 * dVar7));
  *(float *)(param_1 + 0xe) = (float)(dVar10 + (double)(float)(dVar5 * dVar9));
  *(float *)(param_1 + 0x10) = (float)(dVar4 + (double)(float)(dVar8 * dVar6));
  FUN_80103664(param_1 + 0xc,psVar2,param_1 + 0xc,param_1 + 1);
  FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
               *(undefined4 *)(param_1 + 0x18));
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  __psq_l0(auStack40,uVar3);
  __psq_l1(auStack40,uVar3);
  __psq_l0(auStack56,uVar3);
  __psq_l1(auStack56,uVar3);
  __psq_l0(auStack72,uVar3);
  __psq_l1(auStack72,uVar3);
  __psq_l0(auStack88,uVar3);
  __psq_l1(auStack88,uVar3);
  return;
}

