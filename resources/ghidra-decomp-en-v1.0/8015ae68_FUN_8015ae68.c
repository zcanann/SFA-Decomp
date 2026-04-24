// Function: FUN_8015ae68
// Entry: 8015ae68
// Size: 168 bytes

void FUN_8015ae68(undefined4 param_1,int param_2)

{
  float fVar1;
  undefined4 uVar2;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e2ce8;
  *(char *)(param_2 + 0x33b) = (char)(int)*(float *)(param_2 + 0x2a8);
  *(float *)(param_2 + 0x2a8) = FLOAT_803e2cec;
  *(undefined4 *)(param_2 + 0x2e4) = 0x42001;
  *(float *)(param_2 + 0x308) = FLOAT_803e2cf0;
  *(float *)(param_2 + 0x300) = FLOAT_803e2cf4;
  *(float *)(param_2 + 0x304) = FLOAT_803e2cf8;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e2cfc;
  *(float *)(param_2 + 0x314) = FLOAT_803e2cfc;
  *(undefined *)(param_2 + 0x321) = 5;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 7;
  *(float *)(param_2 + 0x31c) = fVar1;
  *(undefined *)(param_2 + 0x33a) = 1;
  *(undefined *)(param_2 + 0x33b) = 0;
  uVar2 = FUN_8002b588();
  FUN_8002853c(uVar2,FUN_80070510);
  return;
}

