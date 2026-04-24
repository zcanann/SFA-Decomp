// Function: FUN_80296ba0
// Entry: 80296ba0
// Size: 28 bytes

int FUN_80296ba0(int param_1)

{
  if (*(int *)(param_1 + 0xb8) != 0) {
    return (int)*(short *)(*(int *)(param_1 + 0xb8) + 0x80a);
  }
  return 0;
}

