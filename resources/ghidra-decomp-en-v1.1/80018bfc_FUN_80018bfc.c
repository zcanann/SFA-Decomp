// Function: FUN_80018bfc
// Entry: 80018bfc
// Size: 780 bytes

void FUN_80018bfc(void)

{
  undefined *puVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined2 *puVar5;
  uint *puVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  undefined8 uVar12;
  int local_28 [10];
  
  uVar12 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  iVar8 = 0;
  iVar7 = 0;
  if (iVar3 != 0) {
    while (uVar4 = FUN_80015cf0((byte *)(iVar3 + iVar8),local_28), uVar4 != 0) {
      iVar8 = iVar8 + local_28[0];
      if ((0xdfff < uVar4) && (uVar4 < 0xf900)) {
        iVar7 = iVar7 + 1;
        if (0x10 < iVar7) break;
        puVar5 = &DAT_8033a8a4;
        puVar6 = &DAT_802c8e70;
        iVar11 = 0x17;
        do {
          if (*puVar6 == uVar4) {
            uVar2 = puVar6[1];
            goto LAB_80018cb8;
          }
          if (puVar6[2] == uVar4) {
            uVar2 = puVar6[3];
            goto LAB_80018cb8;
          }
          puVar6 = puVar6 + 4;
          iVar11 = iVar11 + -1;
        } while (iVar11 != 0);
        uVar2 = 0;
LAB_80018cb8:
        if (4 < (int)uVar2) {
          uVar2 = 4;
        }
        iVar11 = 0;
        DAT_8033a8a0 = uVar4;
        if (0 < (int)uVar2) {
          if ((8 < (int)uVar2) && (uVar4 = uVar2 - 1 >> 3, 0 < (int)(uVar2 - 8))) {
            do {
              *puVar5 = CONCAT11(*(undefined *)(iVar3 + iVar8),*(undefined *)(iVar3 + iVar8 + 1));
              puVar5[1] = CONCAT11(*(undefined *)(iVar3 + iVar8 + 2),
                                   *(undefined *)(iVar3 + iVar8 + 3));
              puVar5[2] = CONCAT11(*(undefined *)(iVar3 + iVar8 + 4),
                                   *(undefined *)(iVar3 + iVar8 + 5));
              puVar5[3] = CONCAT11(*(undefined *)(iVar3 + iVar8 + 6),
                                   *(undefined *)(iVar3 + iVar8 + 7));
              puVar5[4] = CONCAT11(*(undefined *)(iVar3 + iVar8 + 8),
                                   *(undefined *)(iVar3 + iVar8 + 9));
              puVar5[5] = CONCAT11(*(undefined *)(iVar3 + iVar8 + 10),
                                   *(undefined *)(iVar3 + iVar8 + 0xb));
              iVar9 = iVar8 + 0xe;
              puVar5[6] = CONCAT11(*(undefined *)(iVar3 + iVar8 + 0xc),
                                   *(undefined *)(iVar3 + iVar8 + 0xd));
              iVar10 = iVar8 + 0xf;
              iVar8 = iVar8 + 0x10;
              puVar5[7] = CONCAT11(*(undefined *)(iVar3 + iVar9),*(undefined *)(iVar3 + iVar10));
              puVar5 = puVar5 + 8;
              iVar11 = iVar11 + 8;
              uVar4 = uVar4 - 1;
            } while (uVar4 != 0);
          }
          iVar9 = uVar2 - iVar11;
          if (iVar11 < (int)uVar2) {
            do {
              iVar11 = iVar8 + 1;
              puVar1 = (undefined *)(iVar3 + iVar8);
              iVar8 = iVar8 + 2;
              *puVar5 = CONCAT11(*puVar1,*(undefined *)(iVar3 + iVar11));
              puVar5 = puVar5 + 1;
              iVar9 = iVar9 + -1;
            } while (iVar9 != 0);
          }
        }
      }
    }
    if (iVar7 != 0) {
      uVar4 = FUN_80023d8c(iVar7 * 0xc,0x1a);
      FUN_80003494(uVar4,0x8033a8a0,iVar7 * 0xc);
      *(int *)uVar12 = iVar7;
    }
  }
  FUN_8028688c();
  return;
}

