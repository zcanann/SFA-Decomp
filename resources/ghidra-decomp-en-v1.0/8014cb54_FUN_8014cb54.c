// Function: FUN_8014cb54
// Entry: 8014cb54
// Size: 456 bytes

/* WARNING: Removing unreachable block (ram,0x8014ccf8) */
/* WARNING: Removing unreachable block (ram,0x8014cce8) */
/* WARNING: Removing unreachable block (ram,0x8014ccd8) */
/* WARNING: Removing unreachable block (ram,0x8014ccd0) */
/* WARNING: Removing unreachable block (ram,0x8014cce0) */
/* WARNING: Removing unreachable block (ram,0x8014ccf0) */
/* WARNING: Removing unreachable block (ram,0x8014cd00) */

double FUN_8014cb54(double param_1,double param_2,double param_3,double param_4,double param_5,
                   double param_6,double param_7,int param_8)

{
  undefined4 uVar1;
  double dVar2;
  undefined8 in_f25;
  undefined8 in_f26;
  double dVar3;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar4;
  undefined8 in_f31;
  double dVar5;
  undefined auStack104 [16];
  undefined auStack88 [16];
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
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  dVar3 = (double)(float)(param_1 - (double)*(float *)(param_8 + 0x18));
  dVar5 = (double)(float)(param_2 - (double)*(float *)(param_8 + 0x1c));
  dVar4 = (double)(float)(param_3 - (double)*(float *)(param_8 + 0x20));
  dVar2 = (double)FUN_802931a0((double)(float)(dVar3 * dVar3 + (double)(float)(dVar4 * dVar4)));
  if (dVar2 <= param_4) {
    if ((double)FLOAT_803e2574 < dVar2) {
      *(float *)(param_8 + 0x24) =
           FLOAT_803db414 * (float)(param_5 * (double)(float)(dVar3 / param_4)) +
           *(float *)(param_8 + 0x24);
      *(float *)(param_8 + 0x2c) =
           FLOAT_803db414 * (float)(param_5 * (double)(float)(dVar4 / param_4)) +
           *(float *)(param_8 + 0x2c);
    }
  }
  else {
    *(float *)(param_8 + 0x24) =
         FLOAT_803db414 * (float)(param_5 * (double)(float)(dVar3 / dVar2)) +
         *(float *)(param_8 + 0x24);
    *(float *)(param_8 + 0x2c) =
         FLOAT_803db414 * (float)(param_5 * (double)(float)(dVar4 / dVar2)) +
         *(float *)(param_8 + 0x2c);
  }
  dVar2 = -param_6;
  if (dVar2 <= (double)*(float *)(param_8 + 0x24)) {
    if (param_6 < (double)*(float *)(param_8 + 0x24)) {
      *(float *)(param_8 + 0x24) = (float)param_6;
    }
  }
  else {
    *(float *)(param_8 + 0x24) = (float)dVar2;
  }
  if (dVar2 <= (double)*(float *)(param_8 + 0x2c)) {
    if (param_6 < (double)*(float *)(param_8 + 0x2c)) {
      *(float *)(param_8 + 0x2c) = (float)param_6;
    }
  }
  else {
    *(float *)(param_8 + 0x2c) = (float)dVar2;
  }
  if ((double)FLOAT_803e2574 != param_7) {
    dVar2 = (double)FUN_80292b44(param_7,(double)FLOAT_803db414);
    *(float *)(param_8 + 0x24) = (float)((double)*(float *)(param_8 + 0x24) * dVar2);
    dVar2 = (double)FUN_80292b44(param_7,(double)FLOAT_803db414);
    *(float *)(param_8 + 0x2c) = (float)((double)*(float *)(param_8 + 0x2c) * dVar2);
  }
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
  __psq_l0(auStack88,uVar1);
  __psq_l1(auStack88,uVar1);
  __psq_l0(auStack104,uVar1);
  __psq_l1(auStack104,uVar1);
  return dVar5;
}

