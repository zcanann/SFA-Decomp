// Function: FUN_80060888
// Entry: 80060888
// Size: 16 bytes

int FUN_80060888(int param_1,int param_2)

{
  return *(int *)(param_1 + 100) + param_2 * 0x44;
}

