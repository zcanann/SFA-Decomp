// Function: FUN_80283e4c
// Entry: 80283e4c
// Size: 40 bytes

void FUN_80283e4c(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_803defc4 + param_1 * 0xf4 + (uint)DAT_803deff0 * 4;
  *(uint *)(iVar1 + 0x24) = *(uint *)(iVar1 + 0x24) | 0x40;
  return;
}

