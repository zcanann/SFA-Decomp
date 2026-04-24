// Function: FUN_801503ec
// Entry: 801503ec
// Size: 92 bytes

void FUN_801503ec(undefined4 param_1,int param_2)

{
  float fVar1;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e33c0;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x80;
  *(float *)(param_2 + 0x308) = FLOAT_803e33c4;
  *(float *)(param_2 + 0x300) = FLOAT_803e33c8;
  *(float *)(param_2 + 0x304) = FLOAT_803e33cc;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e33d0;
  *(float *)(param_2 + 0x314) = FLOAT_803e33d0;
  *(undefined *)(param_2 + 0x321) = 0;
  *(float *)(param_2 + 0x318) = FLOAT_803e33d4;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  return;
}

