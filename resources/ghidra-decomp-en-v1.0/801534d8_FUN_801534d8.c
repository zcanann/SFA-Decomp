// Function: FUN_801534d8
// Entry: 801534d8
// Size: 132 bytes

void FUN_801534d8(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e28dc;
  *(undefined4 *)(param_2 + 0x2e4) = 0x1009;
  *(float *)(param_2 + 0x308) = FLOAT_803e28e0;
  *(float *)(param_2 + 0x300) = FLOAT_803e28e4;
  *(float *)(param_2 + 0x304) = FLOAT_803e28e8;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e28bc;
  *(float *)(param_2 + 0x314) = FLOAT_803e28bc;
  *(undefined *)(param_2 + 0x321) = 1;
  fVar2 = FLOAT_803e28d0;
  *(float *)(param_2 + 0x318) = FLOAT_803e28d0;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  fVar1 = FLOAT_803e28b0;
  *(float *)(param_2 + 0x324) = FLOAT_803e28b0;
  *(float *)(param_2 + 0x328) = fVar1;
  *(float *)(param_2 + 0x32c) = fVar1;
  *(float *)(param_2 + 0x2fc) = fVar2;
  if (*(short *)(param_1 + 0x46) != 0x7c6) {
    *(undefined *)(param_2 + 0x33b) = 0;
    return;
  }
  *(undefined *)(param_2 + 0x33b) = 1;
  return;
}

