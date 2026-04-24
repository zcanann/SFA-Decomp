// Function: FUN_801d1dbc
// Entry: 801d1dbc
// Size: 100 bytes

void FUN_801d1dbc(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e5310);
    FUN_8003842c(param_1,0,iVar1 + 0x20,iVar1 + 0x24,iVar1 + 0x28,0);
  }
  return;
}

