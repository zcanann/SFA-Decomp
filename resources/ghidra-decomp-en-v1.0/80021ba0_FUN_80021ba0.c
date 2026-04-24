// Function: FUN_80021ba0
// Entry: 80021ba0
// Size: 800 bytes

/* WARNING: Removing unreachable block (ram,0x80021e98) */
/* WARNING: Removing unreachable block (ram,0x80021e88) */
/* WARNING: Removing unreachable block (ram,0x80021e80) */
/* WARNING: Removing unreachable block (ram,0x80021e90) */
/* WARNING: Removing unreachable block (ram,0x80021ea0) */

void FUN_80021ba0(float *param_1,undefined2 *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f27;
  double dVar6;
  undefined8 in_f28;
  double dVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
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
  dVar5 = (double)FUN_8029333c(*param_2);
  dVar10 = (double)((float)((double)CONCAT44(0x43300000,
                                             (int)((double)FLOAT_803de7d0 * dVar5) ^ 0x80000000) -
                           DOUBLE_803de7e0) * FLOAT_803de7f0);
  dVar5 = (double)FUN_80293854(*param_2);
  dVar9 = (double)((float)((double)CONCAT44(0x43300000,
                                            (int)((double)FLOAT_803de7d0 * dVar5) ^ 0x80000000) -
                          DOUBLE_803de7e0) * FLOAT_803de7f0);
  dVar5 = (double)FUN_8029333c(param_2[1]);
  dVar8 = (double)((float)((double)CONCAT44(0x43300000,
                                            (int)((double)FLOAT_803de7d0 * dVar5) ^ 0x80000000) -
                          DOUBLE_803de7e0) * FLOAT_803de7f0);
  dVar5 = (double)FUN_80293854(param_2[1]);
  dVar7 = (double)((float)((double)CONCAT44(0x43300000,
                                            (int)((double)FLOAT_803de7d0 * dVar5) ^ 0x80000000) -
                          DOUBLE_803de7e0) * FLOAT_803de7f0);
  dVar5 = (double)FUN_8029333c(param_2[2]);
  dVar6 = (double)((float)((double)CONCAT44(0x43300000,
                                            (int)((double)FLOAT_803de7d0 * dVar5) ^ 0x80000000) -
                          DOUBLE_803de7e0) * FLOAT_803de7f0);
  dVar5 = (double)FUN_80293854(param_2[2]);
  dVar5 = (double)((float)((double)CONCAT44(0x43300000,
                                            (int)((double)FLOAT_803de7d0 * dVar5) ^ 0x80000000) -
                          DOUBLE_803de7e0) * FLOAT_803de7f0);
  *param_1 = (float)(dVar9 * dVar5) - (float)((double)(float)(dVar8 * dVar6) * dVar10);
  param_1[1] = (float)((double)(float)(dVar8 * dVar5) * dVar10) + (float)(dVar9 * dVar6);
  param_1[2] = -(float)(dVar10 * dVar7);
  fVar1 = FLOAT_803de7c0;
  param_1[3] = FLOAT_803de7c0;
  param_1[4] = -(float)(dVar7 * dVar6);
  param_1[5] = (float)(dVar7 * dVar5);
  param_1[6] = (float)dVar8;
  param_1[7] = fVar1;
  param_1[8] = (float)((double)(float)(dVar8 * dVar6) * dVar9) + (float)(dVar10 * dVar5);
  param_1[9] = (float)(dVar10 * dVar6) - (float)((double)(float)(dVar8 * dVar5) * dVar9);
  param_1[10] = (float)(dVar9 * dVar7);
  param_1[0xb] = fVar1;
  fVar1 = *(float *)(param_2 + 6);
  fVar2 = *(float *)(param_2 + 8);
  fVar3 = *(float *)(param_2 + 10);
  param_1[0xc] = param_1[4] * fVar2 + *param_1 * fVar1 + param_1[8] * fVar3;
  param_1[0xd] = param_1[5] * fVar2 + param_1[1] * fVar1 + param_1[9] * fVar3;
  param_1[0xe] = param_1[6] * fVar2 + param_1[2] * fVar1 + param_1[10] * fVar3;
  param_1[0xf] = FLOAT_803de7c4;
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  __psq_l0(auStack56,uVar4);
  __psq_l1(auStack56,uVar4);
  __psq_l0(auStack72,uVar4);
  __psq_l1(auStack72,uVar4);
  return;
}

