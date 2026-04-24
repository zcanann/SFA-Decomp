// Function: FUN_80186ba4
// Entry: 80186ba4
// Size: 176 bytes

void FUN_80186ba4(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[1] = (short)((int)*(short *)(param_2 + 0x1c) << 8);
  *(float *)(param_1 + 4) = FLOAT_803e4724;
  *(float *)(iVar2 + 4) = *(float *)(param_1 + 0x54) * *(float *)(param_1 + 4) * FLOAT_803e4728;
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar1 != 0) {
    param_1[3] = param_1[3] | 0x4000;
    param_1[0x58] = param_1[0x58] | 0xe000;
  }
  *(undefined4 *)(iVar2 + 8) = 0xffffffff;
  return;
}

