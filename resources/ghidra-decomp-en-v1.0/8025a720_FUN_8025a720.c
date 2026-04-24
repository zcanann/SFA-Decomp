// Function: FUN_8025a720
// Entry: 8025a720
// Size: 16 bytes

int FUN_8025a720(int param_1)

{
  return (*(uint *)(param_1 + 8) & 0x3ff) + 1;
}

