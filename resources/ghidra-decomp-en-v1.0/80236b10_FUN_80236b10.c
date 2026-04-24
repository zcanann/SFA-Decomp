// Function: FUN_80236b10
// Entry: 80236b10
// Size: 40 bytes

int FUN_80236b10(int param_1)

{
  if (*(char *)(*(int *)(param_1 + 0x4c) + 0x1b) == '\x0f') {
    return (int)*(char *)(*(int *)(param_1 + 0xb8) + 0x23);
  }
  return -1;
}

