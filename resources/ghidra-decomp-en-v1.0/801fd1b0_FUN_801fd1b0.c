// Function: FUN_801fd1b0
// Entry: 801fd1b0
// Size: 184 bytes

void FUN_801fd1b0(undefined2 *param_1,int param_2)

{
  int iVar1;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  **(undefined2 **)(param_1 + 0x5c) = *(undefined2 *)(param_2 + 0x20);
  *(undefined **)(param_1 + 0x5e) = &LAB_801fd13c;
  if (param_1[0x23] == 0x3cb) {
    iVar1 = FUN_8001ffb4(0x4e9);
    if (iVar1 != 0) {
      *(float *)(param_1 + 4) = FLOAT_803e6144 * *(float *)(*(int *)(param_1 + 0x28) + 4);
    }
    iVar1 = FUN_8001ffb4(0x63c);
    if (iVar1 != 0) {
      *(float *)(param_1 + 4) = FLOAT_803e6148 * *(float *)(*(int *)(param_1 + 0x28) + 4);
    }
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

