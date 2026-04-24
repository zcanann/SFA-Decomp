// Function: FUN_800d8984
// Entry: 800d8984
// Size: 556 bytes

/* WARNING: Removing unreachable block (ram,0x800d8b88) */
/* WARNING: Removing unreachable block (ram,0x800d8b78) */
/* WARNING: Removing unreachable block (ram,0x800d8b80) */
/* WARNING: Removing unreachable block (ram,0x800d8b90) */

void FUN_800d8984(double param_1,double param_2,short *param_3,int param_4,uint param_5)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar4;
  undefined8 in_f31;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  *(byte *)(param_4 + 0x34c) = *(byte *)(param_4 + 0x34c) | 1;
  if (DAT_803dd434 == '\0') {
    dVar4 = (double)((FLOAT_803e05a4 *
                     (float)((double)CONCAT44(0x43300000,param_5 ^ 0x80000000) - DOUBLE_803e0598)) /
                    FLOAT_803e05a8);
    dVar3 = (double)FUN_80293e80(dVar4);
    dVar3 = (double)(float)(param_2 * (double)(float)((double)*(float *)(param_4 + 0x298) * -dVar3))
    ;
    dVar4 = (double)FUN_80294204(dVar4);
    dVar4 = (double)(float)(param_2 * (double)(float)((double)*(float *)(param_4 + 0x298) * -dVar4))
    ;
    if ((double)*(float *)(param_4 + 0x298) < (double)FLOAT_803e05ac) {
      dVar4 = (double)FLOAT_803e0570;
      dVar3 = dVar4;
    }
    *(float *)(param_3 + 0x12) =
         (float)((double)*(float *)(param_3 + 0x12) +
                (double)((float)(param_1 *
                                (double)(float)(dVar3 - (double)*(float *)(param_3 + 0x12))) /
                        *(float *)(param_4 + 0x2b8)));
    *(float *)(param_3 + 0x16) =
         (float)((double)*(float *)(param_3 + 0x16) +
                (double)((float)(param_1 *
                                (double)(float)(dVar4 - (double)*(float *)(param_3 + 0x16))) /
                        *(float *)(param_4 + 0x2b8)));
  }
  else {
    *(byte *)(param_4 + 0x34c) = *(byte *)(param_4 + 0x34c) & 0xfe;
  }
  dVar3 = (double)FUN_802931a0((double)(*(float *)(param_3 + 0x12) * *(float *)(param_3 + 0x12) +
                                       *(float *)(param_3 + 0x16) * *(float *)(param_3 + 0x16)));
  *(float *)(param_4 + 0x294) = (float)dVar3;
  fVar1 = FLOAT_803e0570;
  if (*(float *)(param_4 + 0x294) < FLOAT_803e05b0) {
    *(float *)(param_4 + 0x294) = FLOAT_803e0570;
    *(float *)(param_3 + 0x12) = fVar1;
    *(float *)(param_3 + 0x16) = fVar1;
  }
  dVar3 = (double)FUN_80293e80((double)((FLOAT_803e05a4 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_3 ^ 0x80000000) -
                                               DOUBLE_803e0598)) / FLOAT_803e05a8));
  dVar4 = (double)FUN_80294204((double)((FLOAT_803e05a4 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_3 ^ 0x80000000) -
                                               DOUBLE_803e0598)) / FLOAT_803e05a8));
  *(float *)(param_4 + 0x284) =
       (float)((double)*(float *)(param_3 + 0x12) * dVar4 -
              (double)(float)((double)*(float *)(param_3 + 0x16) * dVar3));
  *(float *)(param_4 + 0x280) =
       (float)(-(double)*(float *)(param_3 + 0x16) * dVar4 -
              (double)(float)((double)*(float *)(param_3 + 0x12) * dVar3));
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  __psq_l0(auStack40,uVar2);
  __psq_l1(auStack40,uVar2);
  __psq_l0(auStack56,uVar2);
  __psq_l1(auStack56,uVar2);
  return;
}

