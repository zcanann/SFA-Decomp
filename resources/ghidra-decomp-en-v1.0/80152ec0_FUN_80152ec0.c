// Function: FUN_80152ec0
// Entry: 80152ec0
// Size: 232 bytes

void FUN_80152ec0(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float local_18;
  float local_14 [3];
  
  fVar1 = FLOAT_803e286c;
  *(float *)(param_2 + 0x2ac) = FLOAT_803e286c;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(float *)(param_2 + 0x308) = FLOAT_803e28a0;
  *(float *)(param_2 + 0x300) = FLOAT_803e28a4;
  fVar2 = FLOAT_803e2894;
  *(float *)(param_2 + 0x304) = FLOAT_803e2894;
  *(undefined *)(param_2 + 800) = 1;
  *(float *)(param_2 + 0x314) = fVar2;
  *(undefined *)(param_2 + 0x321) = 3;
  *(float *)(param_2 + 0x318) = fVar2;
  *(undefined *)(param_2 + 0x322) = 1;
  *(float *)(param_2 + 0x31c) = fVar2;
  *(undefined4 *)(param_2 + 0x324) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_2 + 0x328) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_2 + 0x32c) = *(undefined4 *)(param_1 + 0x14);
  *(undefined *)(param_2 + 0x33a) = 0;
  *(undefined *)(param_2 + 0x33b) = 0;
  *(undefined2 *)(param_2 + 0x338) = 0;
  *(float *)(param_2 + 0x330) = fVar1;
  *(float *)(param_2 + 0x334) = fVar1;
  *(float *)(param_2 + 0x2fc) = FLOAT_803e28a8;
  FUN_80293018(*(undefined2 *)(param_2 + 0x338),local_14,&local_18);
  *(float *)(param_1 + 0xc) =
       local_14[0] * *(float *)(param_2 + 0x2a8) + *(float *)(param_2 + 0x324);
  *(float *)(param_1 + 0x14) = local_18 * *(float *)(param_2 + 0x2a8) + *(float *)(param_2 + 0x32c);
  return;
}

