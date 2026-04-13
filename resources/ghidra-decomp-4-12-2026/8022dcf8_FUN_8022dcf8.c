// Function: FUN_8022dcf8
// Entry: 8022dcf8
// Size: 24 bytes

void FUN_8022dcf8(int param_1,char param_2)

{
  *(char *)(*(int *)(param_1 + 0xb8) + 0x469) =
       *(char *)(*(int *)(param_1 + 0xb8) + 0x469) + param_2;
  return;
}

