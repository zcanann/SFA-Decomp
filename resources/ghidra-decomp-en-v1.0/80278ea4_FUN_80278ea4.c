// Function: FUN_80278ea4
// Entry: 80278ea4
// Size: 104 bytes

void FUN_80278ea4(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  DAT_803de2e4 = 0;
  iVar3 = 0;
  DAT_803de2d4 = 0;
  DAT_803de2d8 = 0;
  DAT_803de2e0 = 0;
  for (uVar4 = 0; uVar4 < DAT_803bd360; uVar4 = uVar4 + 1) {
    iVar2 = iVar3 + 0x4c;
    *(undefined4 *)(DAT_803de268 + iVar3 + 0x34) = 0;
    iVar1 = iVar3 + 0xaa;
    iVar3 = iVar3 + 0x404;
    *(undefined4 *)(DAT_803de268 + iVar2) = 2;
    *(undefined2 *)(DAT_803de268 + iVar1) = 0;
  }
  return;
}

