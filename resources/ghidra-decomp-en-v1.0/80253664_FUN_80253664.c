// Function: FUN_80253664
// Entry: 80253664
// Size: 568 bytes

undefined4 FUN_80253664(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined *puVar8;
  undefined4 uVar9;
  int iVar10;
  uint uVar11;
  
  iVar10 = param_1 * 0x14;
  iVar2 = param_1 * 0x40;
  uVar9 = 0;
  do {
    if ((*(uint *)(&DAT_803ae40c + iVar2) & 4) == 0) {
      return 0;
    }
  } while ((*(uint *)(&DAT_cc00680c + iVar10) & 1) != 0);
  uVar4 = FUN_8024377c();
  if ((*(uint *)(&DAT_803ae40c + iVar2) & 4) != 0) {
    if ((*(uint *)(&DAT_803ae40c + iVar2) & 3) != 0) {
      if ((*(uint *)(&DAT_803ae40c + iVar2) & 2) != 0) {
        iVar5 = *(int *)(&DAT_803ae410 + iVar2);
        if (iVar5 != 0) {
          puVar8 = *(undefined **)(&DAT_803ae414 + iVar2);
          uVar7 = *(uint *)(&DAT_cc006810 + iVar10);
          iVar6 = 0;
          if (0 < iVar5) {
            if ((8 < iVar5) && (uVar11 = iVar5 - 1U >> 3, 0 < iVar5 + -8)) {
              do {
                *puVar8 = (char)(uVar7 >> (3 - iVar6) * 8);
                puVar8[1] = (char)(uVar7 >> (3 - (iVar6 + 1)) * 8);
                puVar8[2] = (char)(uVar7 >> (3 - (iVar6 + 2)) * 8);
                puVar8[3] = (char)(uVar7 >> iVar6 * -8);
                puVar8[4] = (char)(uVar7 >> (3 - (iVar6 + 4)) * 8);
                puVar8[5] = (char)(uVar7 >> (3 - (iVar6 + 5)) * 8);
                puVar8[6] = (char)(uVar7 >> (3 - (iVar6 + 6)) * 8);
                puVar8[7] = (char)(uVar7 >> (3 - (iVar6 + 7)) * 8);
                puVar8 = puVar8 + 8;
                iVar6 = iVar6 + 8;
                uVar11 = uVar11 - 1;
              } while (uVar11 != 0);
            }
            iVar3 = iVar5 - iVar6;
            if (iVar6 < iVar5) {
              do {
                *puVar8 = (char)(uVar7 >> (3 - iVar6) * 8);
                puVar8 = puVar8 + 1;
                iVar6 = iVar6 + 1;
                iVar3 = iVar3 + -1;
              } while (iVar3 != 0);
            }
          }
        }
      }
      *(uint *)(&DAT_803ae40c + iVar2) = *(uint *)(&DAT_803ae40c + iVar2) & 0xfffffffc;
    }
    iVar5 = FUN_80240d20();
    if (((((iVar5 != 0xff) || (*(int *)(&DAT_803ae410 + iVar2) != 4)) ||
         (((&DAT_cc006800)[param_1 * 5] & 0x70) != 0)) ||
        (((piVar1 = (int *)(&DAT_cc006810 + iVar10), *piVar1 != 0x1010000 && (*piVar1 != 0x5070000))
         && (*piVar1 != 0x4220001)))) || (DAT_800030e6 == -0x7e00)) {
      uVar9 = 1;
    }
  }
  FUN_802437a4(uVar4);
  return uVar9;
}

