// Function: FUN_8025ae94
// Entry: 8025ae94
// Size: 16 bytes

int FUN_8025ae94(int param_1)

{
  return (*(uint *)(param_1 + 8) >> 10 & 0x3ff) + 1;
}

