// Function: FUN_8018664c
// Entry: 8018664c
// Size: 176 bytes

void FUN_8018664c(undefined2 *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[1] = (short)((int)*(short *)(param_2 + 0x1c) << 8);
  *(float *)(param_1 + 4) = FLOAT_803e3a8c;
  *(float *)(iVar2 + 4) = *(float *)(param_1 + 0x54) * *(float *)(param_1 + 4) * FLOAT_803e3a90;
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar1 != 0) {
    param_1[3] = param_1[3] | 0x4000;
    param_1[0x58] = param_1[0x58] | 0xe000;
  }
  *(undefined4 *)(iVar2 + 8) = 0xffffffff;
  return;
}

