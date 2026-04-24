// Function: FUN_80196520
// Entry: 80196520
// Size: 1008 bytes

/* WARNING: Removing unreachable block (ram,0x801968e4) */
/* WARNING: Removing unreachable block (ram,0x801968d4) */
/* WARNING: Removing unreachable block (ram,0x801968dc) */
/* WARNING: Removing unreachable block (ram,0x801968ec) */

void FUN_80196520(undefined2 *param_1,int param_2,int param_3)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 in_f28;
  double dVar4;
  undefined8 in_f29;
  double dVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
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
  *(float *)(param_1 + 6) =
       *(float *)(param_2 + 0x26c) * *(float *)(param_1 + 4) + *(float *)(param_3 + 8);
  *(float *)(param_1 + 8) =
       *(float *)(param_2 + 0x270) * *(float *)(param_1 + 4) + *(float *)(param_3 + 0xc);
  *(float *)(param_1 + 10) =
       *(float *)(param_2 + 0x274) * *(float *)(param_1 + 4) + *(float *)(param_3 + 0x10);
  *param_1 = *(undefined2 *)(param_3 + 0x1a);
  param_1[1] = *(undefined2 *)(param_3 + 0x1c);
  param_1[2] = *(undefined2 *)(param_3 + 0x1e);
  dVar3 = DOUBLE_803e4040;
  fVar1 = FLOAT_803e4030;
  if ((*(byte *)(param_3 + 0x3c) & 1) == 0) {
    *(float *)(param_1 + 0x12) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x20) ^ 0x80000000) -
                DOUBLE_803e4040) / FLOAT_803e4030;
    *(float *)(param_1 + 0x14) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x22) ^ 0x80000000) - dVar3)
         / fVar1;
    *(float *)(param_1 + 0x16) =
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x24) ^ 0x80000000) - dVar3)
         / fVar1;
  }
  else {
    dVar7 = (double)((float)((double)CONCAT44(0x43300000,
                                              (int)*(short *)(param_3 + 0x20) ^ 0x80000000) -
                            DOUBLE_803e4040) / FLOAT_803e4030);
    dVar6 = (double)(*(float *)(param_1 + 6) -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x42) ^ 0x80000000
                                            ) - DOUBLE_803e4040));
    dVar5 = (double)(*(float *)(param_1 + 8) -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x44) ^ 0x80000000
                                            ) - DOUBLE_803e4040));
    dVar4 = (double)(*(float *)(param_1 + 10) -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x46) ^ 0x80000000
                                            ) - DOUBLE_803e4040));
    dVar3 = (double)FUN_802931a0((double)(float)(dVar4 * dVar4 +
                                                (double)(float)(dVar6 * dVar6 +
                                                               (double)(float)(dVar5 * dVar5))));
    if ((double)FLOAT_803e4034 != dVar3) {
      dVar6 = (double)(float)(dVar6 / dVar3);
      dVar5 = (double)(float)(dVar5 / dVar3);
      dVar4 = (double)(float)(dVar4 / dVar3);
    }
    *(float *)(param_1 + 0x12) = (float)(dVar7 * dVar6);
    *(float *)(param_1 + 0x14) = (float)(dVar7 * dVar5);
    *(float *)(param_1 + 0x16) = (float)(dVar7 * dVar4);
  }
  dVar3 = DOUBLE_803e4040;
  *(float *)(param_2 + 0x278) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2c) ^ 0x80000000) -
              DOUBLE_803e4040);
  *(float *)(param_2 + 0x27c) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2e) ^ 0x80000000) - dVar3);
  *(float *)(param_2 + 0x280) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x30) ^ 0x80000000) - dVar3);
  if (FLOAT_803e4034 < *(float *)(param_1 + 0x12)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 1;
  }
  if (FLOAT_803e4034 < *(float *)(param_1 + 0x16)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 2;
  }
  if (FLOAT_803e4034 < *(float *)(param_2 + 0x278)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 4;
  }
  if (FLOAT_803e4034 < *(float *)(param_2 + 0x27c)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 8;
  }
  if (FLOAT_803e4034 < *(float *)(param_2 + 0x280)) {
    *(byte *)(param_2 + 0x29f) = *(byte *)(param_2 + 0x29f) | 0x10;
  }
  dVar3 = DOUBLE_803e4040;
  fVar1 = FLOAT_803e4038;
  *(float *)(param_2 + 0x284) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x32) ^ 0x80000000) -
              DOUBLE_803e4040) / FLOAT_803e4038;
  *(float *)(param_2 + 0x288) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x34) ^ 0x80000000) - dVar3) /
       fVar1;
  *(float *)(param_2 + 0x28c) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x36) ^ 0x80000000) - dVar3) /
       fVar1;
  fVar1 = FLOAT_803e403c;
  *(float *)(param_2 + 0x290) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x26) ^ 0x80000000) - dVar3) /
       FLOAT_803e403c;
  *(float *)(param_2 + 0x294) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x28) ^ 0x80000000) - dVar3) /
       fVar1;
  *(float *)(param_2 + 0x298) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2a) ^ 0x80000000) - dVar3) /
       fVar1;
  *(undefined2 *)(param_2 + 0x29c) = 0;
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

