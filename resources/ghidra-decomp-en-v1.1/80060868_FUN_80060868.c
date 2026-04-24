// Function: FUN_80060868
// Entry: 80060868
// Size: 16 bytes

int FUN_80060868(int param_1,int param_2)

{
  return *(int *)(param_1 + 0x50) + param_2 * 0x14;
}

