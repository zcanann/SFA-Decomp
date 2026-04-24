// Function: FUN_801c0178
// Entry: 801c0178
// Size: 100 bytes

void FUN_801c0178(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
    iVar1 = *(int *)(iVar1 + 4);
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_80060630(iVar1);
    }
  }
  return;
}

