// Function: FUN_80137a00
// Entry: 80137a00
// Size: 384 bytes

void FUN_80137a00(undefined4 param_1,undefined4 param_2,byte *param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_802860d4();
  iVar1 = (int)((ulonglong)uVar13 >> 0x20);
  if (DAT_803dda28 != '\0') {
    iVar10 = 0;
    iVar8 = ((int)uVar13 + 1) * 0x280;
    iVar9 = (int)uVar13 * 0x280;
    do {
      iVar7 = 0;
      iVar6 = iVar1 + iVar9;
      iVar11 = iVar1 + iVar8;
      iVar5 = (iVar11 + 1) * 2;
      iVar4 = iVar11 * 2;
      iVar3 = (iVar6 + 1) * 2;
      iVar2 = iVar6 * 2;
      iVar12 = 4;
      do {
        if ((1 << iVar7 & (uint)*param_3) != 0) {
          *(undefined2 *)(DAT_803dda30 + iVar2) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar3) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar4) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar5) = 0xc080;
        }
        if ((1 << iVar7 + 1 & (uint)*param_3) != 0) {
          *(undefined2 *)(DAT_803dda30 + iVar2 + 2) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar3 + 2) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar4 + 2) = 0xc080;
          *(undefined2 *)(DAT_803dda30 + iVar5 + 2) = 0xc080;
        }
        iVar2 = iVar2 + 4;
        iVar3 = iVar3 + 4;
        iVar4 = iVar4 + 4;
        iVar5 = iVar5 + 4;
        iVar7 = iVar7 + 2;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
      FUN_80241a1c(DAT_803dda30 + iVar6 * 2,0x10);
      FUN_80241a1c(DAT_803dda30 + iVar11 * 2,0x10);
      iVar9 = iVar9 + 0x500;
      iVar8 = iVar8 + 0x500;
      iVar10 = iVar10 + 1;
      param_3 = param_3 + 1;
    } while (iVar10 < 5);
  }
  FUN_80286120();
  return;
}

