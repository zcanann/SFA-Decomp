// Function: FUN_80271ac0
// Entry: 80271ac0
// Size: 140 bytes

undefined4 FUN_80271ac0(void)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar3 = 0;
  if (DAT_803de238 != '\0') {
    for (uVar1 = FUN_8027949c(); uVar1 != 0xffffffff;
        uVar1 = *(uint *)(DAT_803de268 + (uVar1 & 0xff) * 0x404 + 0xec)) {
      iVar2 = (uVar1 & 0xff) * 0x404;
      if (uVar1 == *(uint *)(DAT_803de268 + iVar2 + 0xf4)) {
        FUN_80278610(DAT_803de268 + iVar2);
        uVar3 = 1;
      }
    }
  }
  return uVar3;
}

