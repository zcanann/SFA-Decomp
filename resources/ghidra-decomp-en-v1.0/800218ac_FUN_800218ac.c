// Function: FUN_800218ac
// Entry: 800218ac
// Size: 540 bytes

/* WARNING: Removing unreachable block (ram,0x80021aa0) */
/* WARNING: Removing unreachable block (ram,0x80021a90) */
/* WARNING: Removing unreachable block (ram,0x80021a88) */
/* WARNING: Removing unreachable block (ram,0x80021a98) */
/* WARNING: Removing unreachable block (ram,0x80021aa8) */

void FUN_800218ac(short *param_1,float *param_2)

{
  undefined4 uVar1;
  double dVar2;
  undefined8 in_f27;
  double dVar3;
  undefined8 in_f28;
  double dVar4;
  undefined8 in_f29;
  double dVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar1 = 0;
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
  dVar7 = (double)*param_2;
  dVar6 = (double)param_2[1];
  dVar5 = (double)param_2[2];
  dVar2 = (double)FUN_80293e80((double)((FLOAT_803de7e8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803de7e0)) / FLOAT_803de7ec));
  dVar3 = (double)(float)(dVar7 * dVar2);
  dVar4 = (double)(float)(dVar5 * dVar2);
  dVar2 = (double)FUN_80294204((double)((FLOAT_803de7e8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803de7e0)) / FLOAT_803de7ec));
  dVar7 = (double)(float)((double)(float)(dVar7 * dVar2) + dVar4);
  dVar5 = (double)(float)((double)(float)(dVar5 * dVar2) - dVar3);
  dVar2 = (double)FUN_80293e80((double)((FLOAT_803de7e8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)param_1[1] ^ 0x80000000) -
                                               DOUBLE_803de7e0)) / FLOAT_803de7ec));
  dVar4 = (double)(float)(dVar6 * dVar2);
  dVar3 = (double)(float)(dVar5 * dVar2);
  dVar2 = (double)FUN_80294204((double)((FLOAT_803de7e8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)param_1[1] ^ 0x80000000) -
                                               DOUBLE_803de7e0)) / FLOAT_803de7ec));
  dVar6 = (double)(float)((double)(float)(dVar6 * dVar2) - dVar3);
  dVar5 = (double)(float)((double)(float)(dVar5 * dVar2) + dVar4);
  dVar2 = (double)FUN_80293e80((double)((FLOAT_803de7e8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)param_1[2] ^ 0x80000000) -
                                               DOUBLE_803de7e0)) / FLOAT_803de7ec));
  dVar4 = (double)(float)(dVar7 * dVar2);
  dVar3 = (double)(float)(dVar6 * dVar2);
  dVar2 = (double)FUN_80294204((double)((FLOAT_803de7e8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)param_1[2] ^ 0x80000000) -
                                               DOUBLE_803de7e0)) / FLOAT_803de7ec));
  *param_2 = (float)((double)(float)(dVar7 * dVar2) - dVar3);
  param_2[1] = (float)((double)(float)(dVar6 * dVar2) + dVar4);
  param_2[2] = (float)dVar5;
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  __psq_l0(auStack24,uVar1);
  __psq_l1(auStack24,uVar1);
  __psq_l0(auStack40,uVar1);
  __psq_l1(auStack40,uVar1);
  __psq_l0(auStack56,uVar1);
  __psq_l1(auStack56,uVar1);
  __psq_l0(auStack72,uVar1);
  __psq_l1(auStack72,uVar1);
  return;
}

