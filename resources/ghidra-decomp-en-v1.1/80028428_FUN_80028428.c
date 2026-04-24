// Function: FUN_80028428
// Entry: 80028428
// Size: 16 bytes

int FUN_80028428(int param_1,int param_2)

{
  return *(int *)(param_1 + 0x60) + param_2 * 0x14;
}

