// Function: FUN_8001dc00
// Entry: 8001dc00
// Size: 24 bytes

void FUN_8001dc00(int param_1,int param_2)

{
  *(int *)(param_1 + 0x5c) = param_2;
  *(char *)(param_1 + 100) = (char)(1 << param_2);
  return;
}

