// Function: FUN_801e3a44
// Entry: 801e3a44
// Size: 108 bytes

void FUN_801e3a44(int param_1)

{
  char in_r8;
  
  if ((((*(int *)(param_1 + 0x30) == 0) || (*(short *)(*(int *)(param_1 + 0x30) + 0x46) != 0x139))
      && (in_r8 != '\0')) &&
     ((*(char *)(*(int *)(param_1 + 0xb8) + 0xc) != '\0' &&
      (*(char *)(*(int *)(param_1 + 0xb8) + 0xd) != '\0')))) {
    FUN_8003b9ec(param_1);
  }
  return;
}

