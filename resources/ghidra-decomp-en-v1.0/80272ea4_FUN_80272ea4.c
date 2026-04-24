// Function: FUN_80272ea4
// Entry: 80272ea4
// Size: 200 bytes

void FUN_80272ea4(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  
  DAT_803de280 = 0;
  DAT_803de281 = 3;
  uVar1 = (uint)DAT_803bd360;
  iVar4 = 0;
  if (uVar1 != 0) {
    if (8 < uVar1) {
      uVar5 = uVar1 - 1 >> 3;
      iVar2 = -0x7fc41c88;
      if (0 < (int)(uVar1 - 8)) {
        do {
          *(undefined *)(iVar2 + 8) = 0;
          iVar4 = iVar4 + 8;
          *(undefined *)(iVar2 + 0x6c) = 0;
          *(undefined *)(iVar2 + 0xd0) = 0;
          *(undefined *)(iVar2 + 0x134) = 0;
          *(undefined *)(iVar2 + 0x198) = 0;
          *(undefined *)(iVar2 + 0x1fc) = 0;
          *(undefined *)(iVar2 + 0x260) = 0;
          *(undefined *)(iVar2 + 0x2c4) = 0;
          iVar2 = iVar2 + 800;
          uVar5 = uVar5 - 1;
        } while (uVar5 != 0);
      }
    }
    iVar3 = iVar4 * 100 + -0x7fc41c88;
    iVar2 = (uint)DAT_803bd360 - iVar4;
    if (iVar4 < (int)(uint)DAT_803bd360) {
      do {
        *(undefined *)(iVar3 + 8) = 0;
        iVar3 = iVar3 + 100;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  DAT_803de284 = 0;
  return;
}

