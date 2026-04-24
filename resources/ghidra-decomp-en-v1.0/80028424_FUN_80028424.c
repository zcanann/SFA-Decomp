// Function: FUN_80028424
// Entry: 80028424
// Size: 16 bytes

int FUN_80028424(int param_1,int param_2)

{
  return *(int *)(param_1 + 0x38) + param_2 * 0x44;
}

