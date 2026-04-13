// Function: FUN_80060878
// Entry: 80060878
// Size: 16 bytes

int FUN_80060878(int param_1,int param_2)

{
  return *(int *)(param_1 + 0x68) + param_2 * 0x1c;
}

