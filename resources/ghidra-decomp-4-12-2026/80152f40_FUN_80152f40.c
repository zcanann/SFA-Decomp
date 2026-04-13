// Function: FUN_80152f40
// Entry: 80152f40
// Size: 152 bytes

void FUN_80152f40(uint param_1,int param_2)

{
  float fVar1;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e34e8;
  *(undefined4 *)(param_2 + 0x2e4) = 0x29;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x7000;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x20000;
  *(float *)(param_2 + 0x308) = FLOAT_803e34ec;
  *(float *)(param_2 + 0x300) = FLOAT_803e34f0;
  *(float *)(param_2 + 0x304) = FLOAT_803e34f4;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e34b8;
  *(float *)(param_2 + 0x314) = FLOAT_803e34b8;
  *(undefined *)(param_2 + 0x321) = 0;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  *(float *)(param_2 + 0x32c) = FLOAT_803e34ac;
  *(float *)(param_1 + 0xa8) = FLOAT_803e34f8;
  FUN_8000dcdc(param_1,0xe8);
  return;
}

