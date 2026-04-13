// Function: FUN_801fa8a0
// Entry: 801fa8a0
// Size: 136 bytes

void FUN_801fa8a0(void)

{
  int iVar1;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if ((in_r8 != '\0') && (*(char *)(iVar1 + 0x36) != '\0')) {
    FUN_8005404c(8);
    FUN_8003b9ec(iVar1);
    FUN_80054038(8);
  }
  FUN_8028688c();
  return;
}

