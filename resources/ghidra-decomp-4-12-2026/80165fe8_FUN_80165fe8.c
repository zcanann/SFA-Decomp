// Function: FUN_80165fe8
// Entry: 80165fe8
// Size: 336 bytes

void FUN_80165fe8(int param_1,int param_2)

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
  uint auStack_9c [6];
  float afStack_84 [16];
  float local_44;
  undefined local_30;
  
  local_b8 = FLOAT_803e3cb8;
  *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) - FLOAT_803e3c8c;
  fVar1 = FLOAT_803e3cbc;
  *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * FLOAT_803e3cbc;
  *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * fVar1;
  *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar1;
  local_a8 = *(float *)(param_1 + 0xc);
  local_a4 = *(float *)(param_1 + 0x10);
  local_a0 = *(float *)(param_1 + 0x14);
  local_b4 = local_a8 + *(float *)(param_1 + 0x24);
  local_b0 = local_a4 + *(float *)(param_1 + 0x28);
  local_ac = local_a0 + *(float *)(param_1 + 0x2c);
  local_44 = FLOAT_803e3c74;
  local_30 = 3;
  FUN_80069798(auStack_9c,&local_a8,&local_b4,&local_b8,1);
  FUN_8006933c(param_1,auStack_9c,0,'\x01');
  iVar2 = FUN_80067ad4();
  if (iVar2 == 0) {
    *(float *)(param_1 + 0xc) = local_b4;
    *(float *)(param_1 + 0x10) = local_b0;
    *(float *)(param_1 + 0x14) = local_ac;
  }
  else {
    *(byte *)(param_2 + 0x92) = *(byte *)(param_2 + 0x92) & 0xfb;
    FUN_80166cec(param_1,param_2,afStack_84,&local_b4);
  }
  return;
}

