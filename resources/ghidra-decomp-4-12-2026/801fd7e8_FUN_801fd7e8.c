// Function: FUN_801fd7e8
// Entry: 801fd7e8
// Size: 184 bytes

void FUN_801fd7e8(undefined2 *param_1,int param_2)

{
  uint uVar1;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  **(undefined2 **)(param_1 + 0x5c) = *(undefined2 *)(param_2 + 0x20);
  *(undefined **)(param_1 + 0x5e) = &LAB_801fd774;
  if (param_1[0x23] == 0x3cb) {
    uVar1 = FUN_80020078(0x4e9);
    if (uVar1 != 0) {
      *(float *)(param_1 + 4) = FLOAT_803e6ddc * *(float *)(*(int *)(param_1 + 0x28) + 4);
    }
    uVar1 = FUN_80020078(0x63c);
    if (uVar1 != 0) {
      *(float *)(param_1 + 4) = FLOAT_803e6de0 * *(float *)(*(int *)(param_1 + 0x28) + 4);
    }
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

