// Function: FUN_80060858
// Entry: 80060858
// Size: 16 bytes

int FUN_80060858(int param_1,int param_2)

{
  return *(int *)(param_1 + 0x4c) + param_2 * 8;
}

