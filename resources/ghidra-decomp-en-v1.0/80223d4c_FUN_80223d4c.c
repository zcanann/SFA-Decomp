// Function: FUN_80223d4c
// Entry: 80223d4c
// Size: 88 bytes

void FUN_80223d4c(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e6d18);
    FUN_80114dec(param_1,iVar1 + 0x35c,0);
  }
  return;
}

