// Function: FUN_80283c08
// Entry: 80283c08
// Size: 164 bytes

/* WARNING: Removing unreachable block (ram,0x80283c48) */

int FUN_80283c08(int param_1)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = DAT_803de344 + param_1 * 0xf4;
  if (*(char *)(iVar4 + 0xec) != '\x02') {
    return 0;
  }
  bVar1 = *(byte *)(iVar4 + 0x90);
  if (bVar1 == 3) {
    return *(int *)(iVar4 + 0x20) - *(int *)(iVar4 + 0x78);
  }
  if (bVar1 < 3) {
    if (1 < bVar1) {
      return *(int *)(iVar4 + 0x20) - (*(uint *)(iVar4 + 0x78) >> 1);
    }
  }
  else if (5 < bVar1) {
    return param_1;
  }
  iVar4 = DAT_803de344 + param_1 * 0xf4;
  uVar3 = *(uint *)(iVar4 + 0x20);
  uVar2 = uVar3 & 0xf;
  iVar4 = (uVar3 + *(int *)(iVar4 + 0x78) * -2 >> 4) * 0xe;
  if (uVar2 < 2) {
    return iVar4;
  }
  return uVar2 + iVar4 + -2;
}

