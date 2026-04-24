// Function: FUN_802371d4
// Entry: 802371d4
// Size: 40 bytes

int FUN_802371d4(int param_1)

{
  if (*(char *)(*(int *)(param_1 + 0x4c) + 0x1b) == '\x0f') {
    return (int)*(char *)(*(int *)(param_1 + 0xb8) + 0x23);
  }
  return -1;
}

