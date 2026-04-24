// Function: FUN_80028418
// Entry: 80028418
// Size: 16 bytes

int FUN_80028418(int param_1,int param_2)

{
  return *(int *)(param_1 + 0x5c) + param_2 * 8;
}

