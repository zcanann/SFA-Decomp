// Function: FUN_80283f44
// Entry: 80283f44
// Size: 92 bytes

void FUN_80283f44(int param_1,char param_2)

{
  int iVar1;
  
  if (param_2 == '\0') {
    iVar1 = param_1 * 0xf4;
    *(uint *)(DAT_803defc4 + iVar1 + 0xf0) = *(uint *)(DAT_803defc4 + iVar1 + 0xf0) | 0x80000000;
    *(undefined2 *)(DAT_803defc4 + iVar1 + 0xd0) = 0x10;
    *(undefined2 *)(DAT_803defc4 + iVar1 + 0xd2) = 0x10;
    return;
  }
  iVar1 = DAT_803defc4 + param_1 * 0xf4;
  *(uint *)(iVar1 + 0xf0) = *(uint *)(iVar1 + 0xf0) & 0x7fffffff;
  return;
}

