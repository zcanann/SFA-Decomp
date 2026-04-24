// Function: FUN_8014c678
// Entry: 8014c678
// Size: 680 bytes

/* WARNING: Removing unreachable block (ram,0x8014c8f0) */
/* WARNING: Removing unreachable block (ram,0x8014c8e0) */
/* WARNING: Removing unreachable block (ram,0x8014c8d8) */
/* WARNING: Removing unreachable block (ram,0x8014c8e8) */
/* WARNING: Removing unreachable block (ram,0x8014c8f8) */

void FUN_8014c678(double param_1,double param_2,double param_3,int param_4,int param_5,
                 float *param_6,char param_7)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack200 [12];
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  undefined auStack164 [52];
  undefined4 local_70;
  uint uStack108;
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
  dVar3 = (double)FUN_802477f0(param_5 + 0x2b8);
  if (dVar3 <= (double)FLOAT_803e2574) {
    local_b0 = FLOAT_803e2574;
    local_ac = FLOAT_803e2574;
    local_a8 = FLOAT_803e2574;
  }
  else {
    local_a8 = (float)((double)FLOAT_803e256c / dVar3);
    local_b0 = *(float *)(param_5 + 0x2b8) * local_a8;
    local_ac = *(float *)(param_5 + 700) * local_a8;
    local_a8 = *(float *)(param_5 + 0x2c0) * local_a8;
    FUN_80247794(&local_b0,&local_b0);
  }
  dVar4 = (double)FUN_802477f0(param_6);
  if (dVar4 <= (double)FLOAT_803e2574) {
    local_bc = FLOAT_803e2574;
    local_b8 = FLOAT_803e2574;
    local_b4 = FLOAT_803e2574;
  }
  else {
    local_b4 = (float)((double)FLOAT_803e256c / dVar4);
    local_bc = *param_6 * local_b4;
    local_b8 = param_6[1] * local_b4;
    local_b4 = param_6[2] * local_b4;
  }
  FUN_8024784c(&local_b0,&local_bc,auStack200);
  dVar5 = (double)FUN_802477f0(auStack200);
  if ((double)FLOAT_803e2574 < dVar5) {
    FUN_8024782c(&local_b0,&local_bc);
    dVar5 = (double)FUN_80291ff4();
    uStack108 = ((uint)(byte)((param_3 < dVar5) << 2) << 0x1c) >> 0x1e ^ 0x80000000;
    local_70 = 0x43300000;
    if (ABS((double)(float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e2580)) !=
        (double)FLOAT_803e2574) {
      fVar1 = FLOAT_803e25c4;
      if ((double)FLOAT_803e2574 < dVar5) {
        fVar1 = FLOAT_803e256c;
      }
      FUN_802471e0((double)(float)(param_3 * (double)fVar1),auStack164,auStack200);
      FUN_80247574(auStack164,&local_b0,&local_bc);
    }
  }
  dVar5 = (double)(float)(dVar4 * (double)FLOAT_803e25e8);
  dVar4 = (double)(float)(dVar3 + param_2);
  if ((dVar5 <= dVar4) && (dVar4 = dVar5, dVar5 < (double)(float)(dVar3 - param_2))) {
    dVar4 = (double)(float)(dVar3 - param_2);
  }
  if (param_1 < dVar4) {
    dVar4 = param_1;
  }
  *(float *)(param_4 + 0x24) = (float)((double)local_bc * dVar4);
  *(float *)(param_4 + 0x28) = (float)((double)local_b8 * dVar4);
  *(float *)(param_4 + 0x2c) = (float)((double)local_b4 * dVar4);
  if ((param_7 != '\0') && (*(float *)(param_4 + 0x28) < FLOAT_803e2574)) {
    fVar1 = FLOAT_803e25d0 + *(float *)(*(int *)(param_5 + 0x29c) + 0x10);
    if (*(float *)(param_4 + 0x10) < fVar1) {
      *(float *)(param_4 + 0x28) =
           *(float *)(param_4 + 0x28) *
           (FLOAT_803e256c - (fVar1 - *(float *)(param_4 + 0x10)) / FLOAT_803e25d0);
    }
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

