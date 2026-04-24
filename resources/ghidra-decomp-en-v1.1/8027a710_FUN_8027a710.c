// Function: FUN_8027a710
// Entry: 8027a710
// Size: 128 bytes

void FUN_8027a710(int param_1)

{
  bool bVar1;
  int iVar2;
  
  if (param_1 != -1) {
    bVar1 = FUN_802839b8(param_1);
    if (bVar1) {
      FUN_80283ba0(param_1);
    }
    iVar2 = param_1 * 0x404;
    *(int *)(DAT_803deee8 + iVar2 + 0xf4) = param_1;
    FUN_8027a2fc(DAT_803deee8 + iVar2);
    *(undefined *)(DAT_803deee8 + iVar2 + 0x11c) = 0;
  }
  return;
}

