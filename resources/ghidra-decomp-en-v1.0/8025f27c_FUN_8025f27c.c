// Function: FUN_8025f27c
// Entry: 8025f27c
// Size: 196 bytes

uint FUN_8025f27c(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 1;
  iVar1 = FUN_80246c68();
  for (uVar3 = 0;
      (DAT_803dc600 = iVar1 * 0x41c64e6d + 0x3039, uVar2 = (DAT_803dc600 >> 0x10 & 0x1f) + 1,
      uVar2 < 4 && (uVar3 < 10)); uVar3 = uVar3 + 1) {
    iVar1 = FUN_80246c68();
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

