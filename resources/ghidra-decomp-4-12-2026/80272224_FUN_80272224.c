// Function: FUN_80272224
// Entry: 80272224
// Size: 140 bytes

undefined4 FUN_80272224(uint param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar3 = 0;
  if (DAT_803deeb8 != '\0') {
    for (uVar1 = FUN_80279c00(param_1); uVar1 != 0xffffffff;
        uVar1 = *(uint *)(DAT_803deee8 + (uVar1 & 0xff) * 0x404 + 0xec)) {
      iVar2 = (uVar1 & 0xff) * 0x404;
      if (uVar1 == *(uint *)(DAT_803deee8 + iVar2 + 0xf4)) {
        FUN_80278d74((int *)(DAT_803deee8 + iVar2));
        uVar3 = 1;
      }
    }
  }
  return uVar3;
}

