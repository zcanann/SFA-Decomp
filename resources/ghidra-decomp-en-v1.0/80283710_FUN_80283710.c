// Function: FUN_80283710
// Entry: 80283710
// Size: 120 bytes

void FUN_80283710(int param_1,ushort param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803de344 + param_1 * 0xf4;
  if (0x3fff < param_2) {
    param_2 = 0x3fff;
  }
  if ((*(byte *)(iVar2 + 0xe4) != 0xff) &&
     (*(int *)(iVar2 + (uint)*(byte *)(iVar2 + 0xe4) * 4 + 0x38) == (uint)param_2 << 4)) {
    return;
  }
  *(uint *)(iVar2 + (uint)DAT_803de370 * 4 + 0x38) = (uint)param_2 << 4;
  iVar1 = iVar2 + (uint)DAT_803de370 * 4;
  *(uint *)(iVar1 + 0x24) = *(uint *)(iVar1 + 0x24) | 8;
  *(byte *)(iVar2 + 0xe4) = DAT_803de370;
  return;
}

