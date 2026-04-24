// Function: FUN_801f7978
// Entry: 801f7978
// Size: 144 bytes

void FUN_801f7978(void)

{
  int iVar1;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if ((in_r8 != '\0') && (*(char *)(*(int *)(iVar1 + 0xb8) + 0xd) != '\0')) {
    FUN_8005d2c4();
    FUN_8003b9ec(iVar1);
    FUN_8005d2c8();
  }
  FUN_8028688c();
  return;
}

