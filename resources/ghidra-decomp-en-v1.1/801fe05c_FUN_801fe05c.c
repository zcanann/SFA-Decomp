// Function: FUN_801fe05c
// Entry: 801fe05c
// Size: 120 bytes

void FUN_801fe05c(void)

{
  int iVar1;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if (in_r8 != '\0') {
    FUN_8003b700(0xff,0xe6,0xd7);
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

