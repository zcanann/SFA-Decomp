// Function: FUN_80018bc4
// Entry: 80018bc4
// Size: 780 bytes

void FUN_80018bc4(void)

{
  undefined *puVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  undefined2 *puVar6;
  uint *puVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  int local_28 [10];
  
  uVar13 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar13 >> 0x20);
  iVar9 = 0;
  iVar8 = 0;
  if (iVar3 == 0) {
    uVar4 = 0;
  }
  else {
    while (uVar5 = FUN_80015cb8(iVar3 + iVar9,local_28), uVar5 != 0) {
      iVar9 = iVar9 + local_28[0];
      if ((0xdfff < uVar5) && (uVar5 < 0xf900)) {
        iVar8 = iVar8 + 1;
        if (0x10 < iVar8) break;
        puVar6 = &DAT_80339c44;
        puVar7 = &DAT_802c86f0;
        iVar12 = 0x17;
        do {
          if (*puVar7 == uVar5) {
            uVar2 = puVar7[1];
            goto LAB_80018c80;
          }
          if (puVar7[2] == uVar5) {
            uVar2 = puVar7[3];
            goto LAB_80018c80;
          }
          puVar7 = puVar7 + 4;
          iVar12 = iVar12 + -1;
        } while (iVar12 != 0);
        uVar2 = 0;
LAB_80018c80:
        if (4 < (int)uVar2) {
          uVar2 = 4;
        }
        iVar12 = 0;
        DAT_80339c40 = uVar5;
        if (0 < (int)uVar2) {
          if ((8 < (int)uVar2) && (uVar5 = uVar2 - 1 >> 3, 0 < (int)(uVar2 - 8))) {
            do {
              *puVar6 = CONCAT11(*(undefined *)(iVar3 + iVar9),*(undefined *)(iVar3 + iVar9 + 1));
              puVar6[1] = CONCAT11(*(undefined *)(iVar3 + iVar9 + 2),
                                   *(undefined *)(iVar3 + iVar9 + 3));
              puVar6[2] = CONCAT11(*(undefined *)(iVar3 + iVar9 + 4),
                                   *(undefined *)(iVar3 + iVar9 + 5));
              puVar6[3] = CONCAT11(*(undefined *)(iVar3 + iVar9 + 6),
                                   *(undefined *)(iVar3 + iVar9 + 7));
              puVar6[4] = CONCAT11(*(undefined *)(iVar3 + iVar9 + 8),
                                   *(undefined *)(iVar3 + iVar9 + 9));
              puVar6[5] = CONCAT11(*(undefined *)(iVar3 + iVar9 + 10),
                                   *(undefined *)(iVar3 + iVar9 + 0xb));
              iVar10 = iVar9 + 0xe;
              puVar6[6] = CONCAT11(*(undefined *)(iVar3 + iVar9 + 0xc),
                                   *(undefined *)(iVar3 + iVar9 + 0xd));
              iVar11 = iVar9 + 0xf;
              iVar9 = iVar9 + 0x10;
              puVar6[7] = CONCAT11(*(undefined *)(iVar3 + iVar10),*(undefined *)(iVar3 + iVar11));
              puVar6 = puVar6 + 8;
              iVar12 = iVar12 + 8;
              uVar5 = uVar5 - 1;
            } while (uVar5 != 0);
          }
          iVar10 = uVar2 - iVar12;
          if (iVar12 < (int)uVar2) {
            do {
              iVar12 = iVar9 + 1;
              puVar1 = (undefined *)(iVar3 + iVar9);
              iVar9 = iVar9 + 2;
              *puVar6 = CONCAT11(*puVar1,*(undefined *)(iVar3 + iVar12));
              puVar6 = puVar6 + 1;
              iVar10 = iVar10 + -1;
            } while (iVar10 != 0);
          }
        }
      }
    }
    if (iVar8 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = FUN_80023cc8(iVar8 * 0xc,0x1a,0);
      FUN_80003494(uVar4,&DAT_80339c40,iVar8 * 0xc);
      *(int *)uVar13 = iVar8;
    }
  }
  FUN_80286128(uVar4);
  return;
}

