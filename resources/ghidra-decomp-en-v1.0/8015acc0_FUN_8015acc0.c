// Function: FUN_8015acc0
// Entry: 8015acc0
// Size: 156 bytes

void FUN_8015acc0(int param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e2cc0;
  *(char *)(param_2 + 0x33b) = (char)(int)*(float *)(param_2 + 0x2a8);
  *(float *)(param_2 + 0x2a8) = FLOAT_803e2cc4;
  *(undefined4 *)(param_2 + 0x2e4) = 0x42003;
  *(float *)(param_2 + 0x308) = FLOAT_803e2cc8;
  *(float *)(param_2 + 0x300) = FLOAT_803e2ccc;
  *(float *)(param_2 + 0x304) = FLOAT_803e2cd0;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e2cd4;
  *(float *)(param_2 + 0x314) = FLOAT_803e2cd4;
  *(undefined *)(param_2 + 0x321) = 10;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 7;
  *(float *)(param_2 + 0x31c) = fVar1;
  *(undefined *)(param_2 + 0x33a) = 1;
  uVar2 = countLeadingZeros(0x84b - *(short *)(param_1 + 0x46));
  *(short *)(param_2 + 0x338) = (short)(uVar2 >> 5);
  return;
}

