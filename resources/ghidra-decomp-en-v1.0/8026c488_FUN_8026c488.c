// Function: FUN_8026c488
// Entry: 8026c488
// Size: 2800 bytes

undefined4
FUN_8026c488(int *param_1,int *param_2,int param_3,int *param_4,uint *param_5,undefined param_6,
            undefined2 param_7)

{
  bool bVar1;
  byte bVar2;
  int **ppiVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  int *piVar7;
  undefined *puVar8;
  int *piVar9;
  int **ppiVar10;
  int iVar11;
  uint uVar12;
  char cVar13;
  undefined1 *puVar14;
  int **ppiVar15;
  uint uVar16;
  int iVar17;
  
  ppiVar3 = DAT_803de22c;
  if (DAT_803de22c == (int **)0x0) {
    uVar6 = 0xffffffff;
  }
  else {
    DAT_803de22c = (int **)*DAT_803de22c;
    if (DAT_803de22c != (int **)0x0) {
      ((int *)DAT_803de22c)[1] = 0;
    }
    bVar1 = DAT_803de234 != (int **)0x0;
    *ppiVar3 = (int *)DAT_803de234;
    if (bVar1) {
      *(int ***)((int)DAT_803de234 + 4) = ppiVar3;
    }
    ppiVar3[1] = (int *)0x0;
    DAT_803de234 = ppiVar3;
    *(undefined *)(ppiVar3 + 2) = 1;
    ppiVar3[0x541] = (int *)0x0;
    ppiVar3[0x54f] = (int *)0x0;
    ppiVar3[0x55d] = (int *)0x0;
    ppiVar3[0x56b] = (int *)0x0;
    ppiVar3[0x579] = (int *)0x0;
    ppiVar3[0x587] = (int *)0x0;
    ppiVar3[0x595] = (int *)0x0;
    ppiVar3[0x5a3] = (int *)0x0;
    ppiVar3[0x5b1] = (int *)0x0;
    ppiVar3[0x5bf] = (int *)0x0;
    ppiVar3[0x5cd] = (int *)0x0;
    ppiVar3[0x5db] = (int *)0x0;
    ppiVar3[0x5e9] = (int *)0x0;
    ppiVar3[0x5f7] = (int *)0x0;
    ppiVar3[0x605] = (int *)0x0;
    ppiVar3[0x613] = (int *)0x0;
    bVar2 = *(byte *)((int)ppiVar3 + 9);
    uVar16 = (uint)bVar2;
    *(undefined *)(ppiVar3 + 0x3b8) = 0;
    ppiVar3[4] = param_1;
    ppiVar3[0x25] = param_2;
    ppiVar3[0x46] = param_4;
    *(undefined2 *)((int)ppiVar3 + 10) = param_7;
    piVar7 = ppiVar3[4];
    for (uVar12 = 0; (uVar12 & 0xff) < 0x80; uVar12 = uVar12 + 8) {
      *(undefined *)((int)ppiVar3 + (uVar12 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 1 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 2 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 3 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 4 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 5 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 6 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 7 & 0xff) + 0x14) = 0xff;
    }
    cVar13 = '\0';
    for (; *(byte *)(piVar7 + 1) != 0xff; piVar7 = (int *)((int)piVar7 + 6)) {
      *(char *)((int)ppiVar3 + *(byte *)(piVar7 + 1) + 0x14) = cVar13;
      cVar13 = cVar13 + '\x01';
    }
    piVar7 = ppiVar3[0x25];
    for (uVar12 = 0; (uVar12 & 0xff) < 0x80; uVar12 = uVar12 + 8) {
      *(undefined *)((int)ppiVar3 + (uVar12 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 1 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 2 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 3 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 4 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 5 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 6 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)ppiVar3 + (uVar12 + 7 & 0xff) + 0x98) = 0xff;
    }
    cVar13 = '\0';
    for (; *(byte *)(piVar7 + 1) != 0xff; piVar7 = (int *)((int)piVar7 + 6)) {
      *(char *)((int)ppiVar3 + *(byte *)(piVar7 + 1) + 0x98) = cVar13;
      cVar13 = cVar13 + '\x01';
    }
    iVar11 = 0;
    *(byte *)(ppiVar3 + 0x3ac) = bVar2 + 0x17;
    iVar17 = 2;
    do {
      puVar8 = (undefined *)((int)ppiVar3 + iVar11 + 0x324);
      *puVar8 = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[1] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[2] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[3] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[4] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[5] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[6] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[7] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8 = (undefined *)((int)ppiVar3 + iVar11 + 0x32c);
      *puVar8 = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[1] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[2] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[3] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[4] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[5] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[6] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[7] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8 = (undefined *)((int)ppiVar3 + iVar11 + 0x334);
      *puVar8 = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[1] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[2] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[3] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[4] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[5] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[6] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[7] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8 = (undefined *)((int)ppiVar3 + iVar11 + 0x33c);
      iVar11 = iVar11 + 0x20;
      *puVar8 = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[1] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[2] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[3] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[4] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[5] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[6] = *(undefined *)(ppiVar3 + 0x3ac);
      puVar8[7] = *(undefined *)(ppiVar3 + 0x3ac);
      iVar17 = iVar17 + -1;
    } while (iVar17 != 0);
    *(undefined *)((int)ppiVar3 + 0xee1) = param_6;
    if (param_5 == (uint *)0x0) {
      ppiVar3[0x47] = (int *)0xffffffff;
      ppiVar3[0x48] = (int *)0xffffffff;
      *(undefined2 *)((int)ppiVar3 + 0x151a) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x1552) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x158a) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x15c2) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x15fa) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x1632) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x166a) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x16a2) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x16da) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x1712) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x174a) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x1782) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x17ba) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x17f2) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x182a) = 0x100;
      *(undefined2 *)((int)ppiVar3 + 0x1862) = 0x100;
      FUN_80271b4c(0x7f,0,*(undefined *)(ppiVar3 + 0x3ac),0,0xffffffff);
    }
    else {
      if ((*param_5 & 1) == 0) {
        ppiVar3[0x47] = (int *)0xffffffff;
        ppiVar3[0x48] = (int *)0xffffffff;
      }
      else {
        ppiVar3[0x47] = (int *)param_5[1];
        ppiVar3[0x48] = (int *)param_5[2];
      }
      if ((*param_5 & 2) == 0) {
        *(undefined2 *)((int)ppiVar3 + 0x151a) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x1552) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x158a) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x15c2) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x15fa) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x1632) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x166a) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x16a2) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x16da) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x1712) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x174a) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x1782) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x17ba) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x17f2) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x182a) = 0x100;
        *(undefined2 *)((int)ppiVar3 + 0x1862) = 0x100;
      }
      else {
        *(undefined2 *)((int)ppiVar3 + 0x151a) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x1552) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x158a) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x15c2) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x15fa) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x1632) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x166a) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x16a2) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x16da) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x1712) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x174a) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x1782) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x17ba) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x17f2) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x182a) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)ppiVar3 + 0x1862) = *(undefined2 *)(param_5 + 3);
      }
      if ((*param_5 & 8) != 0) {
        iVar17 = 0;
        for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)((int)param_5 + 0x12); iVar11 = iVar11 + 1) {
          *(byte *)((int)ppiVar3 + *(byte *)(param_5[5] + iVar17) + 0x324) =
               ((byte *)(param_5[5] + iVar17))[1];
          FUN_80271fb0(*(undefined *)(param_5[5] + iVar17 + 1),0);
          iVar17 = iVar17 + 2;
        }
      }
      if ((*param_5 & 4) != 0) {
        FUN_80271b4c(*(undefined *)(param_5 + 4),*(undefined2 *)((int)param_5 + 0xe),
                     *(undefined *)(ppiVar3 + 0x3ac),0,0xffffffff);
        for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(param_5 + 6); iVar11 = iVar11 + 1) {
          FUN_80271b4c(*(undefined *)(param_5 + 4),*(undefined2 *)((int)param_5 + 0xe),
                       *(undefined *)(param_5[7] + iVar11),0,0xffffffff);
        }
      }
    }
    if ((param_4[4] & 0x80000000U) == 0) {
      ppiVar3[0x539] = (int *)0x0;
    }
    else {
      ppiVar3[0x539] = (int *)(param_4[0x15] + (int)param_4);
    }
    piVar7 = (int *)(param_4[4] & 0xfffffff);
    if ((param_4[4] & 0x40000000U) == 0) {
      piVar7 = (int *)((int)piVar7 << 10);
    }
    uVar12 = 0;
    ppiVar10 = ppiVar3;
    do {
      ppiVar10[0x53c] = piVar7;
      FUN_8026f53c((uint)piVar7 >> 10,uVar16,uVar12 & 0xff);
      if (param_4[3] == 0) {
        ppiVar10[0x53a] = (int *)0x0;
      }
      else {
        ppiVar10[0x53a] = (int *)(param_4[3] + (int)param_4);
        ppiVar10[0x53b] = ppiVar10[0x53a];
      }
      *(undefined *)((int)ppiVar10 + 0x151e) = 0;
      uVar12 = uVar12 + 1;
      *(undefined2 *)(ppiVar10 + 0x547) = 0;
      ppiVar10 = ppiVar10 + 0xe;
    } while ((int)uVar12 < 0x10);
    iVar11 = 0x10;
    puVar14 = &DAT_803bd964;
    piVar7 = (int *)(*param_4 + (int)param_4);
    ppiVar10 = ppiVar3;
    ppiVar15 = ppiVar3;
    do {
      *puVar14 = 0x7f;
      ppiVar10[0xdb] = (int *)0x0;
      if (*piVar7 == 0) {
        ppiVar15[0x49] = (int *)0x0;
        ppiVar15[0x4a] = (int *)0x0;
      }
      else {
        piVar9 = (int *)((int)param_4 + *piVar7);
        ppiVar15[0x49] = piVar9;
        ppiVar15[0x4a] = piVar9;
      }
      puVar14[1] = 0x7f;
      ppiVar10[0xe6] = (int *)0x0;
      if (piVar7[1] == 0) {
        ppiVar15[0x4b] = (int *)0x0;
        ppiVar15[0x4c] = (int *)0x0;
      }
      else {
        piVar9 = (int *)((int)param_4 + piVar7[1]);
        ppiVar15[0x4b] = piVar9;
        ppiVar15[0x4c] = piVar9;
      }
      puVar14[2] = 0x7f;
      ppiVar10[0xf1] = (int *)0x0;
      if (piVar7[2] == 0) {
        ppiVar15[0x4d] = (int *)0x0;
        ppiVar15[0x4e] = (int *)0x0;
      }
      else {
        piVar9 = (int *)((int)param_4 + piVar7[2]);
        ppiVar15[0x4d] = piVar9;
        ppiVar15[0x4e] = piVar9;
      }
      puVar14[3] = 0x7f;
      ppiVar10[0xfc] = (int *)0x0;
      if (piVar7[3] == 0) {
        ppiVar15[0x4f] = (int *)0x0;
        ppiVar15[0x50] = (int *)0x0;
      }
      else {
        piVar9 = (int *)((int)param_4 + piVar7[3]);
        ppiVar15[0x4f] = piVar9;
        ppiVar15[0x50] = piVar9;
      }
      puVar14 = puVar14 + 4;
      ppiVar10 = ppiVar10 + 0x2c;
      piVar7 = piVar7 + 4;
      ppiVar15 = ppiVar15 + 8;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    uVar12 = 0;
    ppiVar3[0x399] = (int *)0x0;
    ppiVar3[0x39a] = (int *)0x0;
    ppiVar3[0x39b] = (int *)0x0;
    do {
      FUN_80281a30(uVar12 & 0xff,uVar16,1);
      uVar12 = uVar12 + 1;
    } while ((int)uVar12 < 0x10);
    *(undefined2 *)(ppiVar3 + 0x39c) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x39d) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x39e) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x39f) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x3a0) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x3a1) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x3a2) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x3a3) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x3a4) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x3a5) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x3a6) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x3a7) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x3a8) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x3a9) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x3aa) = 0xffff;
    *(undefined2 *)(ppiVar3 + 0x3ab) = 0xffff;
    uVar12 = 0;
    do {
      FUN_80281dec(uVar12 & 0xff,uVar16);
      uVar12 = uVar12 + 1;
    } while ((int)uVar12 < 0x10);
    if (param_3 != 0) {
      uVar12 = 0;
      do {
        uVar5 = uVar12 & 0xff;
        bVar2 = *(byte *)(param_3 + 4);
        (&DAT_803bcc90)[DAT_803de220 * 0x10 + (uVar12 & 0xff)] = 0xffff;
        if (uVar5 == 9) {
          uVar5 = (uint)*(byte *)((int)ppiVar3 + bVar2 + 0x98);
          if (uVar5 != 0xff) {
            iVar11 = uVar5 * 6;
            *(undefined2 *)(ppiVar3 + 0x3a5) = *(undefined2 *)((int)ppiVar3[0x25] + iVar11);
            *(undefined *)((int)ppiVar3 + 0xe96) = *(undefined *)((int)ppiVar3[0x25] + iVar11 + 2);
            *(undefined *)((int)ppiVar3 + 0xe97) = *(undefined *)((int)ppiVar3[0x25] + iVar11 + 3);
          }
        }
        else {
          uVar4 = (uint)*(byte *)((int)ppiVar3 + bVar2 + 0x14);
          if (uVar4 != 0xff) {
            iVar11 = uVar4 * 6;
            *(undefined2 *)(ppiVar3 + uVar5 + 0x39c) = *(undefined2 *)((int)ppiVar3[4] + iVar11);
            *(undefined *)((int)ppiVar3 + uVar5 * 4 + 0xe72) =
                 *(undefined *)((int)ppiVar3[4] + iVar11 + 2);
            *(undefined *)((int)ppiVar3 + uVar5 * 4 + 0xe73) =
                 *(undefined *)((int)ppiVar3[4] + iVar11 + 3);
          }
        }
        FUN_80281338(7,uVar12 & 0xff,uVar16,*(undefined *)(param_3 + 5));
        FUN_80281338(10,uVar12 & 0xff,uVar16,*(undefined *)(param_3 + 6));
        FUN_80281338(0x5b,uVar12 & 0xff,uVar16,*(undefined *)(param_3 + 7));
        FUN_80281338(0x5d,uVar12 & 0xff,uVar16,*(undefined *)(param_3 + 8));
        uVar12 = uVar12 + 1;
        param_3 = param_3 + 5;
      } while ((int)uVar12 < 0x10);
    }
    (&DAT_803bcc90)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bcc92)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bcc94)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bcc96)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bcc98)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bcc9a)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bcc9c)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bcc9e)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bcca0)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bcca2)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bcca4)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bcca6)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bcca8)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bccaa)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bccac)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bccae)[uVar16 * 0x10] = 0xffff;
    iVar11 = 2;
    ppiVar10 = ppiVar3;
    do {
      ppiVar10[0x543] = (int *)0x0;
      ppiVar10[0x542] = (int *)0x0;
      ppiVar10[0x545] = (int *)0x0;
      ppiVar10[0x544] = (int *)0x0;
      *(undefined *)(ppiVar10 + 0x546) = 0;
      ppiVar10[0x551] = (int *)0x0;
      ppiVar10[0x550] = (int *)0x0;
      ppiVar10[0x553] = (int *)0x0;
      ppiVar10[0x552] = (int *)0x0;
      *(undefined *)(ppiVar10 + 0x554) = 0;
      ppiVar10[0x55f] = (int *)0x0;
      ppiVar10[0x55e] = (int *)0x0;
      ppiVar10[0x561] = (int *)0x0;
      ppiVar10[0x560] = (int *)0x0;
      *(undefined *)(ppiVar10 + 0x562) = 0;
      ppiVar10[0x56d] = (int *)0x0;
      ppiVar10[0x56c] = (int *)0x0;
      ppiVar10[0x56f] = (int *)0x0;
      ppiVar10[0x56e] = (int *)0x0;
      *(undefined *)(ppiVar10 + 0x570) = 0;
      ppiVar10[0x57b] = (int *)0x0;
      ppiVar10[0x57a] = (int *)0x0;
      ppiVar10[0x57d] = (int *)0x0;
      ppiVar10[0x57c] = (int *)0x0;
      *(undefined *)(ppiVar10 + 0x57e) = 0;
      ppiVar10[0x589] = (int *)0x0;
      ppiVar10[0x588] = (int *)0x0;
      ppiVar10[0x58b] = (int *)0x0;
      ppiVar10[0x58a] = (int *)0x0;
      *(undefined *)(ppiVar10 + 0x58c) = 0;
      ppiVar10[0x597] = (int *)0x0;
      ppiVar10[0x596] = (int *)0x0;
      ppiVar10[0x599] = (int *)0x0;
      ppiVar10[0x598] = (int *)0x0;
      *(undefined *)(ppiVar10 + 0x59a) = 0;
      ppiVar10[0x5a5] = (int *)0x0;
      ppiVar10[0x5a4] = (int *)0x0;
      ppiVar10[0x5a7] = (int *)0x0;
      ppiVar10[0x5a6] = (int *)0x0;
      *(undefined *)(ppiVar10 + 0x5a8) = 0;
      ppiVar10 = ppiVar10 + 0x70;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    *(undefined *)((int)ppiVar3 + 0xee2) = 0;
    if ((param_5 != (uint *)0x0) && ((*param_5 & 0x10) != 0)) {
      FUN_8026d060(ppiVar3);
    }
    uVar6 = DAT_803de218;
    DAT_803de218 = ppiVar3;
    FUN_8026e864();
    DAT_803de218 = (int **)uVar6;
    uVar6 = FUN_8026c380(uVar16);
  }
  return uVar6;
}

