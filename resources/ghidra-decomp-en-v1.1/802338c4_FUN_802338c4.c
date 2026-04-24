// Function: FUN_802338c4
// Entry: 802338c4
// Size: 128 bytes

void FUN_802338c4(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_8028683c();
  iVar3 = *(int *)(iVar1 + 0xb8);
  iVar2 = *(int *)(iVar3 + 4);
  if ((iVar2 != 0) && (iVar2 = FUN_8001dc28(iVar2), iVar2 != 0)) {
    FUN_80060630(*(int *)(iVar3 + 4));
  }
  FUN_8003b9ec(iVar1);
  FUN_80286888();
  return;
}

