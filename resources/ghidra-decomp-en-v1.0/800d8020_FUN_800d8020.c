// Function: FUN_800d8020
// Entry: 800d8020
// Size: 332 bytes

/* WARNING: Removing unreachable block (ram,0x800d8148) */
/* WARNING: Removing unreachable block (ram,0x800d8138) */
/* WARNING: Removing unreachable block (ram,0x800d8130) */
/* WARNING: Removing unreachable block (ram,0x800d8140) */
/* WARNING: Removing unreachable block (ram,0x800d8150) */

void FUN_800d8020(double param_1,double param_2,double param_3,double param_4,double param_5,
                 int param_6,int param_7)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar4;
  undefined8 in_f31;
  double dVar5;
  undefined auStack72 [16];
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
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  dVar5 = (double)(float)((double)*(float *)(param_6 + 0xc) - param_1);
  dVar4 = (double)(float)((double)*(float *)(param_6 + 0x14) - param_2);
  dVar3 = (double)FUN_802931a0((double)(float)(dVar5 * dVar5 + (double)(float)(dVar4 * dVar4)));
  *(float *)(param_7 + 700) = (float)dVar3;
  if ((double)FLOAT_803e0570 != dVar3) {
    dVar5 = (double)(float)(dVar5 / dVar3);
    dVar4 = (double)(float)(dVar4 / dVar3);
  }
  if (*(float *)(param_7 + 700) <= (float)(param_3 + param_4)) {
    *(float *)(param_7 + 0x294) = *(float *)(param_7 + 0x294) * FLOAT_803e0574;
    fVar1 = FLOAT_803e0570;
    *(float *)(param_7 + 0x290) = FLOAT_803e0570;
    *(float *)(param_7 + 0x28c) = fVar1;
  }
  else {
    *(float *)(param_7 + 0x290) = (float)(dVar5 * param_5);
    *(float *)(param_7 + 0x28c) = (float)(-dVar4 * param_5);
  }
  if (FLOAT_803e0578 < *(float *)(param_7 + 0x290)) {
    *(float *)(param_7 + 0x290) = FLOAT_803e0578;
  }
  if (*(float *)(param_7 + 0x290) < FLOAT_803e057c) {
    *(float *)(param_7 + 0x290) = FLOAT_803e057c;
  }
  if (FLOAT_803e0578 < *(float *)(param_7 + 0x28c)) {
    *(float *)(param_7 + 0x28c) = FLOAT_803e0578;
  }
  if (*(float *)(param_7 + 0x28c) < FLOAT_803e057c) {
    *(float *)(param_7 + 0x28c) = FLOAT_803e057c;
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  __psq_l0(auStack40,uVar2);
  __psq_l1(auStack40,uVar2);
  __psq_l0(auStack56,uVar2);
  __psq_l1(auStack56,uVar2);
  __psq_l0(auStack72,uVar2);
  __psq_l1(auStack72,uVar2);
  return;
}

