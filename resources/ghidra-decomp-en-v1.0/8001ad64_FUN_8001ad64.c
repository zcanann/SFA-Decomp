// Function: FUN_8001ad64
// Entry: 8001ad64
// Size: 1592 bytes

void FUN_8001ad64(void)

{
  undefined *puVar1;
  ushort *puVar2;
  undefined2 *puVar3;
  ushort uVar4;
  undefined2 uVar5;
  int *piVar6;
  uint uVar7;
  undefined2 *puVar8;
  int iVar9;
  int **ppiVar10;
  int *piVar11;
  undefined2 *puVar12;
  ushort *puVar13;
  int iVar14;
  undefined2 *puVar15;
  int **ppiVar16;
  int iVar17;
  int iVar18;
  ushort uVar19;
  int **ppiVar20;
  int **ppiVar21;
  uint uVar22;
  ushort *puVar23;
  ushort *puVar24;
  uint uVar25;
  uint uVar26;
  
  iVar9 = FUN_802860c4();
  FUN_80241a1c(*(undefined4 *)(iVar9 + 0x3c),*(undefined4 *)(iVar9 + 0x40));
  if (*(char *)(iVar9 + 0x4b) == '\x01') {
    ppiVar20 = (int **)&DAT_8033af68;
  }
  else if (*(char *)(iVar9 + 0x4b) == '\x03') {
    ppiVar20 = (int **)&DAT_8033afb8;
  }
  else {
    ppiVar20 = (int **)&DAT_8033af40;
    DAT_803dc9dc = (uint)*(byte *)(iVar9 + 0x48);
    DAT_803dc9e4 = (uint)*(byte *)(iVar9 + 0x49);
  }
  ppiVar10 = *(int ***)(iVar9 + 0x3c);
  ppiVar20[2] = *ppiVar10;
  if (ppiVar20[2] == (int *)0x0) {
    ppiVar20[7] = (int *)0x3;
    *(undefined4 *)(iVar9 + 0x44) = 6;
    goto LAB_8001b384;
  }
  *ppiVar20 = (int *)(ppiVar10 + 1);
  piVar6 = ppiVar20[2];
  ppiVar20[3] = (int *)(uint)*(ushort *)(ppiVar10 + (int)piVar6 * 4 + 1);
  uVar19 = *(ushort *)((int)ppiVar10 + (int)piVar6 * 0x10 + 6);
  ppiVar20[1] = (int *)(ppiVar10 + (int)piVar6 * 4 + 2);
  ppiVar10 = ppiVar10 + (int)piVar6 * 4 + 2 + (int)ppiVar20[3] * 3;
  piVar6 = *ppiVar10;
  ppiVar21 = ppiVar10 + 1;
  iVar14 = 0;
  for (iVar18 = 0; iVar18 < (int)ppiVar20[3]; iVar18 = iVar18 + 1) {
    *(int ***)((int)ppiVar20[1] + iVar14 + 8) = ppiVar21 + *(int *)((int)ppiVar20[1] + iVar14 + 8);
    iVar14 = iVar14 + 0xc;
  }
  ppiVar10 = ppiVar10 + (int)piVar6 + 1;
  iVar14 = 0;
  if (0 < (int)piVar6) {
    if ((8 < (int)piVar6) &&
       (uVar25 = (int)piVar6 - 1U >> 3, ppiVar16 = ppiVar21, 0 < (int)(piVar6 + -2))) {
      do {
        *ppiVar16 = (int *)((int)ppiVar10 + (int)*ppiVar16);
        ppiVar16[1] = (int *)((int)ppiVar10 + (int)ppiVar16[1]);
        ppiVar16[2] = (int *)((int)ppiVar10 + (int)ppiVar16[2]);
        ppiVar16[3] = (int *)((int)ppiVar10 + (int)ppiVar16[3]);
        ppiVar16[4] = (int *)((int)ppiVar10 + (int)ppiVar16[4]);
        ppiVar16[5] = (int *)((int)ppiVar10 + (int)ppiVar16[5]);
        ppiVar16[6] = (int *)((int)ppiVar10 + (int)ppiVar16[6]);
        ppiVar16[7] = (int *)((int)ppiVar10 + (int)ppiVar16[7]);
        ppiVar16 = ppiVar16 + 8;
        iVar14 = iVar14 + 8;
        uVar25 = uVar25 - 1;
      } while (uVar25 != 0);
    }
    ppiVar16 = ppiVar21 + iVar14;
    iVar18 = (int)piVar6 - iVar14;
    if (iVar14 < (int)piVar6) {
      do {
        *ppiVar16 = (int *)((int)ppiVar10 + (int)*ppiVar16);
        ppiVar16 = ppiVar16 + 1;
        iVar18 = iVar18 + -1;
      } while (iVar18 != 0);
    }
  }
  piVar11 = (int *)((int)ppiVar10 + (uint)uVar19);
  puVar23 = (ushort *)((int)piVar11 + *piVar11 + 4);
  puVar24 = puVar23;
  ppiVar10 = ppiVar20;
  while( true ) {
    uVar19 = *puVar24;
    uVar4 = puVar24[1];
    uVar22 = (uint)puVar24[2];
    uVar25 = (uint)puVar24[3];
    puVar24 = puVar24 + 4;
    if ((uVar22 == 0) && (uVar25 == 0)) break;
    if (uVar19 == 2) {
      uVar19 = 0;
    }
    else if ((uVar19 < 2) && (uVar19 != 0)) {
      uVar19 = 5;
    }
    if (ppiVar10[4] != (int *)0x0) {
      FUN_80023834(0);
      FUN_80023800(ppiVar10[4]);
      FUN_80023834(2);
    }
    piVar11 = (int *)FUN_80054c98(uVar22,uVar25,uVar19,0,0,0,0,1,1);
    ppiVar10[4] = piVar11;
    piVar11 = ppiVar10[4];
    if (piVar11 != (int *)0x0) {
      if (uVar4 == 4) {
        piVar11 = piVar11 + 0x18;
        uVar7 = (int)(uVar22 * uVar25) >> 1;
        if (uVar7 != 0) {
          uVar26 = uVar7 >> 3;
          puVar13 = puVar24;
          if (uVar26 != 0) {
            do {
              *(undefined *)piVar11 = *(undefined *)puVar13;
              *(undefined *)((int)piVar11 + 1) = *(undefined *)((int)puVar13 + 1);
              *(undefined *)((int)piVar11 + 2) = *(undefined *)(puVar13 + 1);
              *(undefined *)((int)piVar11 + 3) = *(undefined *)((int)puVar13 + 3);
              *(undefined *)(piVar11 + 1) = *(undefined *)(puVar13 + 2);
              *(undefined *)((int)piVar11 + 5) = *(undefined *)((int)puVar13 + 5);
              *(undefined *)((int)piVar11 + 6) = *(undefined *)(puVar13 + 3);
              puVar1 = (undefined *)((int)puVar13 + 7);
              puVar13 = puVar13 + 4;
              *(undefined *)((int)piVar11 + 7) = *puVar1;
              piVar11 = piVar11 + 2;
              uVar26 = uVar26 - 1;
            } while (uVar26 != 0);
            uVar7 = uVar7 & 7;
            if (uVar7 == 0) goto LAB_8001b0ac;
          }
          do {
            *(undefined *)piVar11 = *(undefined *)puVar13;
            piVar11 = (int *)((int)piVar11 + 1);
            uVar7 = uVar7 - 1;
            puVar13 = (ushort *)((int)puVar13 + 1);
          } while (uVar7 != 0);
        }
LAB_8001b0ac:
        FUN_802419e8(ppiVar10[4] + 0x18,ppiVar10[4][0x11]);
      }
      else {
        piVar11 = piVar11 + 0x18;
        uVar7 = uVar22 * uVar25;
        if (uVar7 != 0) {
          uVar26 = uVar7 >> 3;
          puVar13 = puVar24;
          if (uVar26 != 0) {
            do {
              *(ushort *)piVar11 = *puVar13;
              *(ushort *)((int)piVar11 + 2) = puVar13[1];
              *(ushort *)(piVar11 + 1) = puVar13[2];
              *(ushort *)((int)piVar11 + 6) = puVar13[3];
              *(ushort *)(piVar11 + 2) = puVar13[4];
              *(ushort *)((int)piVar11 + 10) = puVar13[5];
              *(ushort *)(piVar11 + 3) = puVar13[6];
              puVar2 = puVar13 + 7;
              puVar13 = puVar13 + 8;
              *(ushort *)((int)piVar11 + 0xe) = *puVar2;
              piVar11 = piVar11 + 4;
              uVar26 = uVar26 - 1;
            } while (uVar26 != 0);
            uVar7 = uVar7 & 7;
            if (uVar7 == 0) goto LAB_8001b154;
          }
          do {
            *(ushort *)piVar11 = *puVar13;
            piVar11 = (int *)((int)piVar11 + 2);
            uVar7 = uVar7 - 1;
            puVar13 = puVar13 + 1;
          } while (uVar7 != 0);
        }
LAB_8001b154:
        FUN_802419e8(ppiVar10[4] + 0x18,ppiVar10[4][0x11]);
      }
    }
    puVar24 = puVar24 + ((int)(uVar22 * uVar25 * (uint)uVar4) >> 4);
    ppiVar10 = ppiVar10 + 1;
  }
  uVar22 = (int)puVar23 - *(int *)(iVar9 + 0x3c);
  puVar12 = (undefined2 *)FUN_80023cc8(uVar22,0x1a,0);
  uVar25 = uVar22 >> 1;
  puVar8 = *(undefined2 **)(iVar9 + 0x3c);
  iVar14 = (int)puVar12 - (int)puVar8;
  if (uVar25 != 0) {
    uVar22 = uVar22 >> 4;
    puVar15 = puVar12;
    if (uVar22 != 0) {
      do {
        *puVar15 = *puVar8;
        puVar15[1] = puVar8[1];
        puVar15[2] = puVar8[2];
        puVar15[3] = puVar8[3];
        puVar15[4] = puVar8[4];
        puVar15[5] = puVar8[5];
        puVar15[6] = puVar8[6];
        puVar3 = puVar8 + 7;
        puVar8 = puVar8 + 8;
        puVar15[7] = *puVar3;
        puVar15 = puVar15 + 8;
        uVar22 = uVar22 - 1;
      } while (uVar22 != 0);
      uVar25 = uVar25 & 7;
      if (uVar25 == 0) goto LAB_8001b238;
    }
    do {
      uVar5 = *puVar8;
      puVar8 = puVar8 + 1;
      *puVar15 = uVar5;
      uVar25 = uVar25 - 1;
      puVar15 = puVar15 + 1;
    } while (uVar25 != 0);
  }
LAB_8001b238:
  *ppiVar20 = (int *)((int)*ppiVar20 + iVar14);
  ppiVar20[1] = (int *)((int)ppiVar20[1] + iVar14);
  iVar18 = 0;
  for (iVar17 = 0; iVar17 < (int)ppiVar20[3]; iVar17 = iVar17 + 1) {
    *(int *)((int)ppiVar20[1] + iVar18 + 8) = *(int *)((int)ppiVar20[1] + iVar18 + 8) + iVar14;
    iVar18 = iVar18 + 0xc;
  }
  iVar18 = 0;
  if (0 < (int)piVar6) {
    if ((8 < (int)piVar6) &&
       (uVar25 = (int)piVar6 - 1U >> 3, piVar11 = (int *)((int)ppiVar21 + iVar14),
       0 < (int)(piVar6 + -2))) {
      do {
        *piVar11 = *piVar11 + iVar14;
        piVar11[1] = piVar11[1] + iVar14;
        piVar11[2] = piVar11[2] + iVar14;
        piVar11[3] = piVar11[3] + iVar14;
        piVar11[4] = piVar11[4] + iVar14;
        piVar11[5] = piVar11[5] + iVar14;
        piVar11[6] = piVar11[6] + iVar14;
        piVar11[7] = piVar11[7] + iVar14;
        piVar11 = piVar11 + 8;
        iVar18 = iVar18 + 8;
        uVar25 = uVar25 - 1;
      } while (uVar25 != 0);
    }
    piVar11 = (int *)((int)ppiVar21 + iVar14) + iVar18;
    iVar17 = (int)piVar6 - iVar18;
    if (iVar18 < (int)piVar6) {
      do {
        *piVar11 = *piVar11 + iVar14;
        piVar11 = piVar11 + 1;
        iVar17 = iVar17 + -1;
      } while (iVar17 != 0);
    }
  }
  FUN_80023834(0);
  FUN_80023800(*(undefined4 *)(iVar9 + 0x3c));
  *(undefined4 *)(iVar9 + 0x3c) = 0;
  FUN_80023834(2);
  *(undefined2 **)(iVar9 + 0x3c) = puVar12;
  ppiVar20[7] = (int *)&DAT_00000002;
  *(undefined4 *)(iVar9 + 0x44) = 3;
LAB_8001b384:
  FUN_80286110();
  return;
}

