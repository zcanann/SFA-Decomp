// Function: FUN_8010ac48
// Entry: 8010ac48
// Size: 608 bytes

/* WARNING: Removing unreachable block (ram,0x8010ae7c) */
/* WARNING: Removing unreachable block (ram,0x8010ae6c) */
/* WARNING: Removing unreachable block (ram,0x8010ae5c) */
/* WARNING: Removing unreachable block (ram,0x8010ae54) */
/* WARNING: Removing unreachable block (ram,0x8010ae64) */
/* WARNING: Removing unreachable block (ram,0x8010ae74) */
/* WARNING: Removing unreachable block (ram,0x8010ae84) */

double FUN_8010ac48(double param_1,undefined8 param_2,double param_3,undefined4 *param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f25;
  double dVar10;
  undefined8 in_f26;
  double dVar11;
  double dVar12;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar13;
  undefined8 in_f31;
  double dVar14;
  int local_98 [7];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
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
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  iVar6 = 0;
  piVar7 = local_98;
  do {
    iVar5 = (**(code **)(*DAT_803dca9c + 0x1c))(*param_4);
    *piVar7 = iVar5;
    param_4 = param_4 + 1;
    piVar7 = piVar7 + 1;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 4);
  dVar14 = (double)(*(float *)(local_98[2] + 8) - *(float *)(local_98[1] + 8));
  dVar13 = (double)(*(float *)(local_98[2] + 0x10) - *(float *)(local_98[1] + 0x10));
  dVar9 = dVar13;
  dVar10 = dVar14;
  if (local_98[0] != 0) {
    dVar9 = (double)(*(float *)(local_98[1] + 0x10) - *(float *)(local_98[0] + 0x10));
    dVar10 = (double)(*(float *)(local_98[1] + 8) - *(float *)(local_98[0] + 8));
  }
  dVar11 = (double)(FLOAT_803e18a8 * (float)(dVar10 + dVar14));
  dVar10 = (double)(FLOAT_803e18a8 * (float)(dVar9 + dVar13));
  dVar9 = (double)FUN_802931a0((double)(float)(dVar11 * dVar11 + (double)(float)(dVar10 * dVar10)));
  if ((double)FLOAT_803e1888 != dVar9) {
    dVar11 = (double)(float)(dVar11 / dVar9);
    dVar10 = (double)(float)(dVar10 / dVar9);
  }
  dVar9 = (double)(float)(dVar11 * dVar14 + (double)(float)(dVar10 * dVar13));
  if ((double)FLOAT_803e1888 != dVar9) {
    dVar9 = (double)(float)(-(double)(-(float)(dVar11 * (double)*(float *)(local_98[1] + 8) +
                                              (double)(float)(dVar10 * (double)*(float *)(local_98[1
                                                  ] + 0x10))) +
                                     (float)(dVar11 * param_1 + (double)(float)(dVar10 * param_3)))
                           / dVar9);
  }
  fVar1 = (float)((double)*(float *)(local_98[2] + 8) - (double)*(float *)(local_98[1] + 8));
  fVar2 = (float)((double)*(float *)(local_98[2] + 0x10) - (double)*(float *)(local_98[1] + 0x10));
  fVar3 = fVar1;
  fVar4 = fVar2;
  if (local_98[3] != 0) {
    fVar3 = (float)((double)*(float *)(local_98[3] + 8) - (double)*(float *)(local_98[2] + 8));
    fVar4 = (float)((double)*(float *)(local_98[3] + 0x10) - (double)*(float *)(local_98[2] + 0x10))
    ;
  }
  dVar12 = (double)(FLOAT_803e18a8 * (fVar3 + fVar1));
  dVar11 = (double)(FLOAT_803e18a8 * (fVar4 + fVar2));
  dVar10 = (double)FUN_802931a0((double)(float)(dVar12 * dVar12 + (double)(float)(dVar11 * dVar11)))
  ;
  if ((double)FLOAT_803e1888 != dVar10) {
    dVar12 = (double)(float)(dVar12 / dVar10);
    dVar11 = (double)(float)(dVar11 / dVar10);
  }
  dVar10 = (double)(float)(dVar12 * dVar14 + (double)(float)(dVar11 * dVar13));
  if ((double)FLOAT_803e1888 != dVar10) {
    dVar10 = (double)(float)(-(double)(-(float)(dVar12 * (double)*(float *)(local_98[2] + 8) +
                                               (double)(float)(dVar11 * (double)*(float *)(local_98[
                                                  2] + 0x10))) +
                                      (float)(dVar12 * param_1 + (double)(float)(dVar11 * param_3)))
                            / dVar10);
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  __psq_l0(auStack72,uVar8);
  __psq_l1(auStack72,uVar8);
  __psq_l0(auStack88,uVar8);
  __psq_l1(auStack88,uVar8);
  __psq_l0(auStack104,uVar8);
  __psq_l1(auStack104,uVar8);
  return (double)(float)(-dVar9 / (double)(float)(dVar10 - dVar9));
}

