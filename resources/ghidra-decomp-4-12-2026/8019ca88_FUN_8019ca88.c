// Function: FUN_8019ca88
// Entry: 8019ca88
// Size: 88 bytes

void FUN_8019ca88(short *param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  if (in_r8 != '\0') {
    FUN_8003b9ec((int)param_1);
    FUN_80115088(param_1,iVar1,0);
  }
  return;
}

