// Function: FUN_80155aac
// Entry: 80155aac
// Size: 100 bytes

void FUN_80155aac(undefined4 param_1,int param_2)

{
  float fVar1;
  float fVar2;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e2a34;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  fVar1 = FLOAT_803e2a38;
  *(float *)(param_2 + 0x308) = FLOAT_803e2a38;
  *(float *)(param_2 + 0x300) = fVar1;
  *(float *)(param_2 + 0x304) = FLOAT_803e2a3c;
  *(undefined *)(param_2 + 800) = 0;
  fVar2 = FLOAT_803e2a40;
  *(float *)(param_2 + 0x314) = FLOAT_803e2a40;
  *(undefined *)(param_2 + 0x321) = 4;
  fVar1 = FLOAT_803e2a04;
  *(float *)(param_2 + 0x318) = FLOAT_803e2a04;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar2;
  *(float *)(param_2 + 0x324) = FLOAT_803e2a00;
  *(undefined *)(param_2 + 0x33a) = 0;
  *(undefined *)(param_2 + 0x33b) = 0;
  *(float *)(param_2 + 0x2fc) = fVar1;
  return;
}

