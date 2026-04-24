// Function: FUN_800d816c
// Entry: 800d816c
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x800d8284) */
/* WARNING: Removing unreachable block (ram,0x800d827c) */
/* WARNING: Removing unreachable block (ram,0x800d828c) */

void FUN_800d816c(double param_1,double param_2,double param_3,int param_4,uint *param_5)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar4;
  undefined8 in_f31;
  double dVar5;
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
  *param_5 = *param_5 & 0xffefffff;
  dVar5 = (double)(float)((double)*(float *)(param_4 + 0xc) - param_1);
  dVar4 = (double)(float)((double)*(float *)(param_4 + 0x14) - param_2);
  dVar3 = (double)FUN_802931a0((double)(float)(dVar5 * dVar5 + (double)(float)(dVar4 * dVar4)));
  param_5[0xaf] = (uint)(float)dVar3;
  fVar1 = FLOAT_803e0578;
  if ((float)param_5[0xaf] < FLOAT_803e0580) {
    fVar1 = FLOAT_803e0584 * (float)param_5[0xaf];
    param_5[0xa5] = (uint)((float)param_5[0xa5] * FLOAT_803e0574);
  }
  if ((double)fVar1 < dVar3) {
    dVar3 = (double)(float)(dVar3 / (double)fVar1);
    dVar5 = (double)(float)(dVar5 / dVar3);
    dVar4 = (double)(float)(dVar4 / dVar3);
  }
  param_5[0xa4] = (uint)(float)dVar5;
  param_5[0xa3] = (uint)(float)-dVar4;
  param_5[0xa4] = (uint)(float)((double)(float)param_5[0xa4] * param_3);
  param_5[0xa3] = (uint)(float)((double)(float)param_5[0xa3] * param_3);
  if (FLOAT_803e0578 < (float)param_5[0xa4]) {
    param_5[0xa4] = (uint)FLOAT_803e0578;
  }
  if ((float)param_5[0xa4] < FLOAT_803e057c) {
    param_5[0xa4] = (uint)FLOAT_803e057c;
  }
  if (FLOAT_803e0578 < (float)param_5[0xa3]) {
    param_5[0xa3] = (uint)FLOAT_803e0578;
  }
  if ((float)param_5[0xa3] < FLOAT_803e057c) {
    param_5[0xa3] = (uint)FLOAT_803e057c;
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  __psq_l0(auStack40,uVar2);
  __psq_l1(auStack40,uVar2);
  return;
}

