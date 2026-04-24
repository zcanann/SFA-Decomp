// Function: FUN_8025a730
// Entry: 8025a730
// Size: 16 bytes

int FUN_8025a730(int param_1)

{
  return (*(uint *)(param_1 + 8) >> 10 & 0x3ff) + 1;
}

