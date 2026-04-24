// Function: FUN_8014ff58
// Entry: 8014ff58
// Size: 92 bytes

void FUN_8014ff58(undefined4 param_1,int param_2)

{
  float fVar1;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e2728;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x80;
  *(float *)(param_2 + 0x308) = FLOAT_803e272c;
  *(float *)(param_2 + 0x300) = FLOAT_803e2730;
  *(float *)(param_2 + 0x304) = FLOAT_803e2734;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e2738;
  *(float *)(param_2 + 0x314) = FLOAT_803e2738;
  *(undefined *)(param_2 + 0x321) = 0;
  *(float *)(param_2 + 0x318) = FLOAT_803e273c;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  return;
}

