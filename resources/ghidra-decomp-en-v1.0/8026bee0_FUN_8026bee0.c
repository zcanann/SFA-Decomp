// Function: FUN_8026bee0
// Entry: 8026bee0
// Size: 60 bytes

void FUN_8026bee0(byte **param_1,byte *param_2)

{
  *param_1 = param_2;
  param_1[1] = &DAT_00000002;
  *(byte *)(param_1 + 2) = **param_1 >> 4 & 7;
  *(byte *)((int)param_1 + 9) = **param_1 & 0xf;
  *param_1 = *param_1 + 1;
  return;
}

