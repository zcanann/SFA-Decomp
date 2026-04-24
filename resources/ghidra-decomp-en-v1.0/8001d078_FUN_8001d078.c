// Function: FUN_8001d078
// Entry: 8001d078
// Size: 240 bytes

/* WARNING: Removing unreachable block (ram,0x8001d148) */

double FUN_8001d078(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f31;
  undefined auStack40 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (*(int *)(param_2 + 0xc4) != 0) {
    param_2 = *(int *)(param_2 + 0xc4);
  }
  FUN_80247754(param_2 + 0x18,param_1 + 0x10,auStack40);
  dVar5 = (double)FUN_802477f0(auStack40);
  fVar3 = -(float)((double)*(float *)(param_2 + 0xa8) * (double)*(float *)(param_2 + 8) - dVar5);
  if ((FLOAT_803de768 < fVar3) || (*(float *)(param_1 + 0x144) < fVar3)) {
    dVar5 = (double)FLOAT_803de75c;
  }
  else {
    fVar1 = *(float *)(param_1 + 0x140);
    fVar2 = FLOAT_803de760;
    if (fVar1 <= fVar3) {
      fVar2 = FLOAT_803de760 - (fVar3 - fVar1) / (*(float *)(param_1 + 0x144) - fVar1);
    }
    dVar5 = (double)fVar2;
    if (*(int *)(param_1 + 0xb8) != 0) {
      FUN_80247778((double)(FLOAT_803de760 / fVar3),auStack40,auStack40);
      FUN_8024782c(param_1 + 0x34,auStack40);
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return dVar5;
}

