// Function: FUN_800606ec
// Entry: 800606ec
// Size: 16 bytes

int FUN_800606ec(int param_1,int param_2)

{
  return *(int *)(param_1 + 0x50) + param_2 * 0x14;
}

