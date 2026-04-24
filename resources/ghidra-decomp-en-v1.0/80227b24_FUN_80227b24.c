// Function: FUN_80227b24
// Entry: 80227b24
// Size: 140 bytes

void FUN_80227b24(int param_1,int param_2)

{
  undefined4 uVar1;
  
  *(float *)(param_1 + 0x10) = FLOAT_803e6dfc + *(float *)(param_2 + 0xc);
  *(undefined *)(param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  if (*(char *)(*(int *)(param_1 + 0x50) + 0x55) <= *(char *)(param_1 + 0xad)) {
    *(undefined *)(param_1 + 0xad) = 0;
  }
  *(undefined2 *)(*(int *)(param_1 + 0xb8) + 8) = *(undefined2 *)(param_2 + 0x1a);
  uVar1 = FUN_8002b588(param_1);
  FUN_8002852c(uVar1,FUN_800284cc);
  *(undefined *)(param_1 + 0x36) = 0;
  return;
}

