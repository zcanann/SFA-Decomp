// Function: FUN_8002b660
// Entry: 8002b660
// Size: 28 bytes

void FUN_8002b660(int param_1,ushort param_2)

{
  if (4 < param_2) {
    param_2 = 0;
  }
  *(char *)(param_1 + 0xe8) = (char)param_2;
  return;
}

