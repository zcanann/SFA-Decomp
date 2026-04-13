// Function: FUN_80230514
// Entry: 80230514
// Size: 128 bytes

void FUN_80230514(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_8028683c();
  iVar3 = *(int *)(iVar1 + 0xb8);
  iVar2 = *(int *)(iVar3 + 0x20);
  if ((iVar2 != 0) && (iVar2 = FUN_8001dc28(iVar2), iVar2 != 0)) {
    FUN_80060630(*(int *)(iVar3 + 0x20));
  }
  FUN_8003b9ec(iVar1);
  FUN_80286888();
  return;
}

