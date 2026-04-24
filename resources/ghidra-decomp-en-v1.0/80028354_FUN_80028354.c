// Function: FUN_80028354
// Entry: 80028354
// Size: 16 bytes

int FUN_80028354(int param_1,int param_2)

{
  return *(int *)(param_1 + 0x5c) + param_2 * 8;
}

