// Function: FUN_8011395c
// Entry: 8011395c
// Size: 628 bytes

/* WARNING: Removing unreachable block (ram,0x80113ba8) */
/* WARNING: Removing unreachable block (ram,0x80113b98) */
/* WARNING: Removing unreachable block (ram,0x80113b90) */
/* WARNING: Removing unreachable block (ram,0x80113ba0) */
/* WARNING: Removing unreachable block (ram,0x80113bb0) */

double FUN_8011395c(double param_1,double param_2,double param_3,short *param_4,int param_5)

{
  float fVar1;
  float fVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
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
  fVar1 = (float)((double)*(float *)(param_5 + 0x18) - param_1);
  fVar2 = (float)((double)*(float *)(param_5 + 0x20) - param_2);
  dVar4 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
  if (dVar4 < param_3) {
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e1c80 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_4 ^ 0x80000000) -
                                                 DOUBLE_803e1c30)) / FLOAT_803e1c84));
    dVar6 = (double)FUN_80294204((double)((FLOAT_803e1c80 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_4 ^ 0x80000000) -
                                                 DOUBLE_803e1c30)) / FLOAT_803e1c84));
    fVar1 = -(float)(dVar5 * (double)(float)(param_1 - dVar5) +
                    (double)(float)(dVar6 * (double)(float)(param_2 - dVar6)));
    dVar7 = (double)(fVar1 + (float)(dVar5 * (double)*(float *)(param_5 + 0x18) +
                                    (double)(float)(dVar6 * (double)*(float *)(param_5 + 0x20))));
    fVar1 = fVar1 + (float)(dVar5 * (double)*(float *)(param_5 + 0x8c) +
                           (double)(float)(dVar6 * (double)*(float *)(param_5 + 0x94)));
    if ((dVar7 <= (double)FLOAT_803e1c2c) || (FLOAT_803e1c48 < fVar1)) {
      if (FLOAT_803e1c48 < fVar1) {
        dVar4 = (double)(float)((double)FLOAT_803e1c40 * param_3);
      }
    }
    else {
      *(float *)(param_5 + 0x18) = -(float)(dVar5 * dVar7 - (double)*(float *)(param_5 + 0x18));
      *(float *)(param_5 + 0x20) = -(float)(dVar6 * dVar7 - (double)*(float *)(param_5 + 0x20));
      FUN_8000e034((double)*(float *)(param_5 + 0x18),(double)*(float *)(param_5 + 0x1c),
                   (double)*(float *)(param_5 + 0x20),param_5 + 0xc,param_5 + 0x10,param_5 + 0x14,
                   *(undefined4 *)(param_5 + 0x30));
    }
  }
  if (dVar4 < param_3) {
    param_1 = (double)*(float *)(param_5 + 0x18);
    param_2 = (double)*(float *)(param_5 + 0x20);
  }
  dVar4 = (double)FUN_80293e80((double)((FLOAT_803e1c80 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_4 + 0x4000U ^
                                                                 0x80000000) - DOUBLE_803e1c30)) /
                                       FLOAT_803e1c84));
  dVar5 = (double)FUN_80294204((double)((FLOAT_803e1c80 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_4 + 0x4000U ^
                                                                 0x80000000) - DOUBLE_803e1c30)) /
                                       FLOAT_803e1c84));
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
  return -(double)(-(float)((double)*(float *)(param_4 + 6) * dVar4 +
                           (double)(float)((double)*(float *)(param_4 + 10) * dVar5)) +
                  (float)(dVar4 * param_1 + (double)(float)(dVar5 * param_2)));
}

