// Function: FUN_80165b3c
// Entry: 80165b3c
// Size: 336 bytes

void FUN_80165b3c(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  undefined auStack156 [24];
  undefined auStack132 [64];
  float local_44;
  undefined local_30;
  
  local_b8 = FLOAT_803e3020;
  *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) - FLOAT_803e2ff4;
  fVar1 = FLOAT_803e3024;
  *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * FLOAT_803e3024;
  *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * fVar1;
  *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar1;
  local_a8 = *(float *)(param_1 + 0xc);
  local_a4 = *(float *)(param_1 + 0x10);
  local_a0 = *(float *)(param_1 + 0x14);
  local_b4 = local_a8 + *(float *)(param_1 + 0x24);
  local_b0 = local_a4 + *(float *)(param_1 + 0x28);
  local_ac = local_a0 + *(float *)(param_1 + 0x2c);
  local_44 = FLOAT_803e2fdc;
  local_30 = 3;
  FUN_8006961c(auStack156,&local_a8,&local_b4,&local_b8,1);
  FUN_800691c0(param_1,auStack156,0,1);
  iVar2 = FUN_80067958(param_1,&local_a8,&local_b4,1,auStack132,0x20);
  if (iVar2 == 0) {
    *(float *)(param_1 + 0xc) = local_b4;
    *(float *)(param_1 + 0x10) = local_b0;
    *(float *)(param_1 + 0x14) = local_ac;
  }
  else {
    *(byte *)(param_2 + 0x92) = *(byte *)(param_2 + 0x92) & 0xfb;
    FUN_80166840(param_1,param_2,auStack132,&local_b4);
  }
  return;
}

