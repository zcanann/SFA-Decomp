// Function: FUN_8025f9e0
// Entry: 8025f9e0
// Size: 196 bytes

uint FUN_8025f9e0(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 1;
  iVar1 = FUN_802473cc();
  for (uVar3 = 0;
      (DAT_803dd268 = iVar1 * 0x41c64e6d + 0x3039, uVar2 = (DAT_803dd268 >> 0x10 & 0x1f) + 1,
      uVar2 < 4 && (uVar3 < 10)); uVar3 = uVar3 + 1) {
    iVar1 = FUN_802473cc();
    iVar1 = iVar1 << uVar4;
    uVar4 = uVar4 + 1;
    if (0x10 < uVar4) {
      uVar4 = 1;
    }
  }
  if (uVar2 < 4) {
    uVar2 = 4;
  }
  return uVar2;
}

