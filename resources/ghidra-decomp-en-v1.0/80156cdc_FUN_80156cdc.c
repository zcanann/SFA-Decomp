// Function: FUN_80156cdc
// Entry: 80156cdc
// Size: 104 bytes

void FUN_80156cdc(undefined4 param_1,int param_2)

{
  float fVar1;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e2b08;
  *(undefined4 *)(param_2 + 0x2e4) = 0x46001;
  *(float *)(param_2 + 0x308) = FLOAT_803e2b0c;
  *(float *)(param_2 + 0x300) = FLOAT_803e2b10;
  *(float *)(param_2 + 0x304) = FLOAT_803e2b14;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e2b04;
  *(float *)(param_2 + 0x314) = FLOAT_803e2b04;
  *(undefined *)(param_2 + 0x321) = 4;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 3;
  *(float *)(param_2 + 0x31c) = fVar1;
  *(undefined *)(param_2 + 0x33a) = 1;
  *(undefined2 *)(param_2 + 0x2b0) = 10;
  return;
}

