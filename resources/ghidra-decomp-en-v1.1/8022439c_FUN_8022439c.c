// Function: FUN_8022439c
// Entry: 8022439c
// Size: 88 bytes

void FUN_8022439c(short *param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  if (in_r8 != '\0') {
    FUN_8003b9ec((int)param_1);
    FUN_80115088(param_1,iVar1 + 0x35c,0);
  }
  return;
}

