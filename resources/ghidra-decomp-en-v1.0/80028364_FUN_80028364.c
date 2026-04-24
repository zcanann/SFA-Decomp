// Function: FUN_80028364
// Entry: 80028364
// Size: 16 bytes

int FUN_80028364(int param_1,int param_2)

{
  return *(int *)(param_1 + 0x60) + param_2 * 0x14;
}

