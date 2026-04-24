// Function: FUN_80283e74
// Entry: 80283e74
// Size: 120 bytes

void FUN_80283e74(int param_1,ushort param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = (uint)param_2;
  iVar3 = DAT_803defc4 + param_1 * 0xf4;
  if (0x3fff < param_2) {
    uVar2 = 0x3fff;
  }
  if ((*(byte *)(iVar3 + 0xe4) != 0xff) &&
     (*(int *)(iVar3 + (uint)*(byte *)(iVar3 + 0xe4) * 4 + 0x38) == uVar2 << 4)) {
    return;
  }
  *(uint *)(iVar3 + (uint)DAT_803deff0 * 4 + 0x38) = uVar2 << 4;
  iVar1 = iVar3 + (uint)DAT_803deff0 * 4;
  *(uint *)(iVar1 + 0x24) = *(uint *)(iVar1 + 0x24) | 8;
  *(byte *)(iVar3 + 0xe4) = DAT_803deff0;
  return;
}

