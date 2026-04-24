// Function: FUN_80253dc8
// Entry: 80253dc8
// Size: 568 bytes

undefined4 FUN_80253dc8(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined *puVar7;
  undefined4 uVar8;
  int iVar9;
  uint uVar10;
  
  iVar9 = param_1 * 0x14;
  iVar2 = param_1 * 0x40;
  uVar8 = 0;
  do {
    if ((*(uint *)(&DAT_803af06c + iVar2) & 4) == 0) {
      return 0;
    }
  } while ((*(uint *)(&DAT_cc00680c + iVar9) & 1) != 0);
  FUN_80243e74();
  if ((*(uint *)(&DAT_803af06c + iVar2) & 4) != 0) {
    if ((*(uint *)(&DAT_803af06c + iVar2) & 3) != 0) {
      if ((*(uint *)(&DAT_803af06c + iVar2) & 2) != 0) {
        iVar4 = *(int *)(&DAT_803af070 + iVar2);
        if (iVar4 != 0) {
          puVar7 = *(undefined **)(&DAT_803af074 + iVar2);
          uVar6 = *(uint *)(&DAT_cc006810 + iVar9);
          iVar5 = 0;
          if (0 < iVar4) {
            if ((8 < iVar4) && (uVar10 = iVar4 - 1U >> 3, 0 < iVar4 + -8)) {
              do {
                *puVar7 = (char)(uVar6 >> (3 - iVar5) * 8);
                puVar7[1] = (char)(uVar6 >> (3 - (iVar5 + 1)) * 8);
                puVar7[2] = (char)(uVar6 >> (3 - (iVar5 + 2)) * 8);
                puVar7[3] = (char)(uVar6 >> iVar5 * -8);
                puVar7[4] = (char)(uVar6 >> (3 - (iVar5 + 4)) * 8);
                puVar7[5] = (char)(uVar6 >> (3 - (iVar5 + 5)) * 8);
                puVar7[6] = (char)(uVar6 >> (3 - (iVar5 + 6)) * 8);
                puVar7[7] = (char)(uVar6 >> (3 - (iVar5 + 7)) * 8);
                puVar7 = puVar7 + 8;
                iVar5 = iVar5 + 8;
                uVar10 = uVar10 - 1;
              } while (uVar10 != 0);
            }
            iVar3 = iVar4 - iVar5;
            if (iVar5 < iVar4) {
              do {
                *puVar7 = (char)(uVar6 >> (3 - iVar5) * 8);
                puVar7 = puVar7 + 1;
                iVar5 = iVar5 + 1;
                iVar3 = iVar3 + -1;
              } while (iVar3 != 0);
            }
          }
        }
      }
      *(uint *)(&DAT_803af06c + iVar2) = *(uint *)(&DAT_803af06c + iVar2) & 0xfffffffc;
    }
    uVar6 = FUN_80241418();
    if (((((uVar6 != 0xff) || (*(int *)(&DAT_803af070 + iVar2) != 4)) ||
         (((&DAT_cc006800)[param_1 * 5] & 0x70) != 0)) ||
        (((piVar1 = (int *)(&DAT_cc006810 + iVar9), *piVar1 != 0x1010000 && (*piVar1 != 0x5070000))
         && (*piVar1 != 0x4220001)))) || (DAT_800030e6 == -0x7e00)) {
      uVar8 = 1;
    }
  }
  FUN_80243e9c();
  return uVar8;
}

