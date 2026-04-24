// Function: FUN_8001db3c
// Entry: 8001db3c
// Size: 24 bytes

void FUN_8001db3c(int param_1,int param_2)

{
  *(int *)(param_1 + 0x5c) = param_2;
  *(char *)(param_1 + 100) = (char)(1 << param_2);
  return;
}

