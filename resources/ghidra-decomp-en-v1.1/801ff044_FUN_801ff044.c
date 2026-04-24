// Function: FUN_801ff044
// Entry: 801ff044
// Size: 80 bytes

void FUN_801ff044(int param_1)

{
  char cVar1;
  char in_r8;
  
  if ((((in_r8 != '\0') && (cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 0x118), cVar1 != '\f')) &&
      (cVar1 != '\x04')) && (cVar1 != '\v')) {
    FUN_8003b9ec(param_1);
  }
  return;
}

