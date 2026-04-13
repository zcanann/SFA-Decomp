// Function: FUN_80283ba0
// Entry: 80283ba0
// Size: 80 bytes

void FUN_80283ba0(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_803defc4 + param_1 * 0xf4;
  if ((*(char *)(iVar1 + 0xec) == '\x01') && (DAT_803deff0 == 0)) {
    *(undefined *)(iVar1 + 0xee) = 1;
  }
  iVar1 = DAT_803defc4 + param_1 * 0xf4 + (uint)DAT_803deff0 * 4;
  *(uint *)(iVar1 + 0x24) = *(uint *)(iVar1 + 0x24) | 0x20;
  return;
}

