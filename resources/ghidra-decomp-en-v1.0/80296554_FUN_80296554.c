// Function: FUN_80296554
// Entry: 80296554
// Size: 24 bytes

uint FUN_80296554(int param_1,uint param_2)

{
  return (int)*(char *)(*(int *)(*(int *)(param_1 + 0xb8) + 0x35c) + 2) & param_2;
}

