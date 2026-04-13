// Function: FUN_8022576c
// Entry: 8022576c
// Size: 144 bytes

void FUN_8022576c(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_1 + 0x36) = 0;
  *(undefined *)(param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  if (*(char *)(*(int *)(param_1 + 0x50) + 0x55) <= *(char *)(param_1 + 0xad)) {
    *(undefined *)(param_1 + 0xad) = 0;
  }
  FUN_800359cc(param_1,*(int *)(param_1 + 0x54),(int)*(char *)(param_1 + 0xad));
  *(char *)(iVar1 + 0x283) = (char)*(undefined2 *)(param_2 + 0x1a);
  *(float *)(iVar1 + 0x274) = FLOAT_803e7a38 + *(float *)(param_2 + 0xc);
  return;
}

