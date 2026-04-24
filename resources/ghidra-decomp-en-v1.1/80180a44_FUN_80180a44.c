// Function: FUN_80180a44
// Entry: 80180a44
// Size: 80 bytes

void FUN_80180a44(int param_1)

{
  char in_r8;
  
  if (((in_r8 != '\0') && (*(char *)(*(int *)(param_1 + 0xb8) + 0x1b) != '\0')) &&
     (*(char *)(*(int *)(param_1 + 0xb8) + 0x1c) == '\0')) {
    FUN_8003b9ec(param_1);
  }
  return;
}

