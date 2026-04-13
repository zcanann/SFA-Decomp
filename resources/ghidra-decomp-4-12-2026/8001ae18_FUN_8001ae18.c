// Function: FUN_8001ae18
// Entry: 8001ae18
// Size: 1592 bytes

void FUN_8001ae18(void)

{
  undefined *puVar1;
  ushort *puVar2;
  undefined2 *puVar3;
  ushort uVar4;
  undefined2 uVar5;
  int iVar6;
  undefined2 *puVar7;
  int iVar8;
  int *piVar9;
  undefined2 *puVar10;
  ushort *puVar11;
  int iVar12;
  undefined *puVar13;
  ushort *puVar14;
  undefined2 *puVar15;
  int *piVar16;
  int iVar17;
  int *piVar18;
  int *piVar19;
  int iVar20;
  uint uVar21;
  uint uVar22;
  ushort *puVar23;
  ushort *puVar24;
  uint uVar25;
  uint uVar26;
  
  iVar8 = FUN_80286828();
  FUN_80242114(*(uint *)(iVar8 + 0x3c),*(int *)(iVar8 + 0x40));
  if (*(char *)(iVar8 + 0x4b) == '\x01') {
    piVar18 = &DAT_8033bbc8;
  }
  else if (*(char *)(iVar8 + 0x4b) == '\x03') {
    piVar18 = &DAT_8033bc18;
  }
  else {
    piVar18 = (int *)&DAT_8033bba0;
    DAT_803dd65c = (uint)*(byte *)(iVar8 + 0x48);
    DAT_803dd664 = (uint)*(byte *)(iVar8 + 0x49);
  }
  piVar9 = *(int **)(iVar8 + 0x3c);
  piVar18[2] = *piVar9;
  if (piVar18[2] == 0) {
    piVar18[7] = 3;
    *(undefined4 *)(iVar8 + 0x44) = 6;
    goto LAB_8001b438;
  }
  *piVar18 = (int)(piVar9 + 1);
  iVar6 = piVar18[2];
  piVar18[3] = (uint)*(ushort *)(piVar9 + iVar6 * 4 + 1);
  uVar4 = *(ushort *)((int)piVar9 + iVar6 * 0x10 + 6);
  piVar18[1] = (int)(piVar9 + iVar6 * 4 + 2);
  piVar9 = piVar9 + iVar6 * 4 + 2 + piVar18[3] * 3;
  iVar20 = *piVar9;
  piVar19 = piVar9 + 1;
  iVar6 = 0;
  for (iVar17 = 0; iVar17 < piVar18[3]; iVar17 = iVar17 + 1) {
    *(int **)(piVar18[1] + iVar6 + 8) = piVar19 + *(int *)(piVar18[1] + iVar6 + 8);
    iVar6 = iVar6 + 0xc;
  }
  iVar6 = iVar20 * 4 + 4;
  iVar17 = 0;
  if (0 < iVar20) {
    if ((8 < iVar20) && (uVar25 = iVar20 - 1U >> 3, piVar16 = piVar19, 0 < iVar20 + -8)) {
      do {
        *piVar16 = (int)piVar9 + *piVar16 + iVar6;
        piVar16[1] = (int)piVar9 + piVar16[1] + iVar6;
        piVar16[2] = (int)piVar9 + piVar16[2] + iVar6;
        piVar16[3] = (int)piVar9 + piVar16[3] + iVar6;
        piVar16[4] = (int)piVar9 + piVar16[4] + iVar6;
        piVar16[5] = (int)piVar9 + piVar16[5] + iVar6;
        piVar16[6] = (int)piVar9 + piVar16[6] + iVar6;
        piVar16[7] = (int)piVar9 + piVar16[7] + iVar6;
        piVar16 = piVar16 + 8;
        iVar17 = iVar17 + 8;
        uVar25 = uVar25 - 1;
      } while (uVar25 != 0);
    }
    piVar16 = piVar19 + iVar17;
    iVar12 = iVar20 - iVar17;
    if (iVar17 < iVar20) {
      do {
        *piVar16 = (int)piVar9 + *piVar16 + iVar6;
        piVar16 = piVar16 + 1;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
    }
  }
  piVar9 = (int *)((int)piVar9 + (uint)uVar4 + iVar6);
  puVar23 = (ushort *)((int)piVar9 + *piVar9 + 4);
  puVar24 = puVar23;
  piVar9 = piVar18;
  while( true ) {
    uVar25 = (uint)*puVar24;
    uVar4 = puVar24[1];
    uVar22 = (uint)puVar24[2];
    uVar21 = (uint)puVar24[3];
    puVar24 = puVar24 + 4;
    if ((uVar22 == 0) && (uVar21 == 0)) break;
    if (uVar25 == 2) {
      uVar25 = 0;
    }
    else if ((uVar25 < 2) && (uVar25 != 0)) {
      uVar25 = 5;
    }
    if (piVar9[4] != 0) {
      FUN_800238f8(0);
      FUN_800238c4(piVar9[4]);
      FUN_800238f8(2);
    }
    iVar6 = FUN_80054e14(uVar22,uVar21,uVar25,'\0',0,0,0,1,1);
    piVar9[4] = iVar6;
    iVar6 = piVar9[4];
    if (iVar6 != 0) {
      if (uVar4 == 4) {
        puVar13 = (undefined *)(iVar6 + 0x60);
        uVar25 = (int)(uVar22 * uVar21) >> 1;
        if (uVar25 != 0) {
          uVar26 = uVar25 >> 3;
          puVar14 = puVar24;
          if (uVar26 != 0) {
            do {
              *puVar13 = *(undefined *)puVar14;
              puVar13[1] = *(undefined *)((int)puVar14 + 1);
              puVar13[2] = *(undefined *)(puVar14 + 1);
              puVar13[3] = *(undefined *)((int)puVar14 + 3);
              puVar13[4] = *(undefined *)(puVar14 + 2);
              puVar13[5] = *(undefined *)((int)puVar14 + 5);
              puVar13[6] = *(undefined *)(puVar14 + 3);
              puVar1 = (undefined *)((int)puVar14 + 7);
              puVar14 = puVar14 + 4;
              puVar13[7] = *puVar1;
              puVar13 = puVar13 + 8;
              uVar26 = uVar26 - 1;
            } while (uVar26 != 0);
            uVar25 = uVar25 & 7;
            if (uVar25 == 0) goto LAB_8001b160;
          }
          do {
            *puVar13 = *(undefined *)puVar14;
            puVar13 = puVar13 + 1;
            uVar25 = uVar25 - 1;
            puVar14 = (ushort *)((int)puVar14 + 1);
          } while (uVar25 != 0);
        }
LAB_8001b160:
        FUN_802420e0(piVar9[4] + 0x60,*(int *)(piVar9[4] + 0x44));
      }
      else {
        puVar14 = (ushort *)(iVar6 + 0x60);
        uVar25 = uVar22 * uVar21;
        if (uVar25 != 0) {
          uVar26 = uVar25 >> 3;
          puVar11 = puVar24;
          if (uVar26 != 0) {
            do {
              *puVar14 = *puVar11;
              puVar14[1] = puVar11[1];
              puVar14[2] = puVar11[2];
              puVar14[3] = puVar11[3];
              puVar14[4] = puVar11[4];
              puVar14[5] = puVar11[5];
              puVar14[6] = puVar11[6];
              puVar2 = puVar11 + 7;
              puVar11 = puVar11 + 8;
              puVar14[7] = *puVar2;
              puVar14 = puVar14 + 8;
              uVar26 = uVar26 - 1;
            } while (uVar26 != 0);
            uVar25 = uVar25 & 7;
            if (uVar25 == 0) goto LAB_8001b208;
          }
          do {
            *puVar14 = *puVar11;
            puVar14 = puVar14 + 1;
            uVar25 = uVar25 - 1;
            puVar11 = puVar11 + 1;
          } while (uVar25 != 0);
        }
LAB_8001b208:
        FUN_802420e0(piVar9[4] + 0x60,*(int *)(piVar9[4] + 0x44));
      }
    }
    puVar24 = puVar24 + ((int)(uVar22 * uVar21 * (uint)uVar4) >> 4);
    piVar9 = piVar9 + 1;
  }
  uVar21 = (int)puVar23 - *(int *)(iVar8 + 0x3c);
  puVar10 = (undefined2 *)FUN_80023d8c(uVar21,0x1a);
  uVar25 = uVar21 >> 1;
  puVar7 = *(undefined2 **)(iVar8 + 0x3c);
  iVar6 = (int)puVar10 - (int)puVar7;
  if (uVar25 != 0) {
    uVar21 = uVar21 >> 4;
    puVar15 = puVar10;
    if (uVar21 != 0) {
      do {
        *puVar15 = *puVar7;
        puVar15[1] = puVar7[1];
        puVar15[2] = puVar7[2];
        puVar15[3] = puVar7[3];
        puVar15[4] = puVar7[4];
        puVar15[5] = puVar7[5];
        puVar15[6] = puVar7[6];
        puVar3 = puVar7 + 7;
        puVar7 = puVar7 + 8;
        puVar15[7] = *puVar3;
        puVar15 = puVar15 + 8;
        uVar21 = uVar21 - 1;
      } while (uVar21 != 0);
      uVar25 = uVar25 & 7;
      if (uVar25 == 0) goto LAB_8001b2ec;
    }
    do {
      uVar5 = *puVar7;
      puVar7 = puVar7 + 1;
      *puVar15 = uVar5;
      uVar25 = uVar25 - 1;
      puVar15 = puVar15 + 1;
    } while (uVar25 != 0);
  }
LAB_8001b2ec:
  *piVar18 = *piVar18 + iVar6;
  piVar18[1] = piVar18[1] + iVar6;
  iVar17 = 0;
  for (iVar12 = 0; iVar12 < piVar18[3]; iVar12 = iVar12 + 1) {
    *(int *)(piVar18[1] + iVar17 + 8) = *(int *)(piVar18[1] + iVar17 + 8) + iVar6;
    iVar17 = iVar17 + 0xc;
  }
  iVar17 = 0;
  if (0 < iVar20) {
    if ((8 < iVar20) &&
       (uVar25 = iVar20 - 1U >> 3, piVar9 = (int *)((int)piVar19 + iVar6), 0 < iVar20 + -8)) {
      do {
        *piVar9 = *piVar9 + iVar6;
        piVar9[1] = piVar9[1] + iVar6;
        piVar9[2] = piVar9[2] + iVar6;
        piVar9[3] = piVar9[3] + iVar6;
        piVar9[4] = piVar9[4] + iVar6;
        piVar9[5] = piVar9[5] + iVar6;
        piVar9[6] = piVar9[6] + iVar6;
        piVar9[7] = piVar9[7] + iVar6;
        piVar9 = piVar9 + 8;
        iVar17 = iVar17 + 8;
        uVar25 = uVar25 - 1;
      } while (uVar25 != 0);
    }
    piVar9 = (int *)((int)piVar19 + iVar6) + iVar17;
    iVar12 = iVar20 - iVar17;
    if (iVar17 < iVar20) {
      do {
        *piVar9 = *piVar9 + iVar6;
        piVar9 = piVar9 + 1;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
    }
  }
  FUN_800238f8(0);
  FUN_800238c4(*(uint *)(iVar8 + 0x3c));
  *(undefined4 *)(iVar8 + 0x3c) = 0;
  FUN_800238f8(2);
  *(undefined2 **)(iVar8 + 0x3c) = puVar10;
  piVar18[7] = 2;
  *(undefined4 *)(iVar8 + 0x44) = 3;
LAB_8001b438:
  FUN_80286874();
  return;
}

