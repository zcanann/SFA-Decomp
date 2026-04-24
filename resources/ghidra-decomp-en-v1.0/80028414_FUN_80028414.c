// Function: FUN_80028414
// Entry: 80028414
// Size: 16 bytes

int FUN_80028414(int param_1,int param_2)

{
  return *(int *)(param_1 + 0x28) + param_2 * 6;
}

