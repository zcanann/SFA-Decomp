// Function: FUN_80238d40
// Entry: 80238d40
// Size: 148 bytes

void FUN_80238d40(void)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80286840();
  iVar2 = *(int *)(*(int *)(iVar1 + 0xb8) + 4);
  if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0')) {
    FUN_80060630(iVar2);
  }
  if (*(int *)(iVar1 + 0xc4) == 0) {
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

