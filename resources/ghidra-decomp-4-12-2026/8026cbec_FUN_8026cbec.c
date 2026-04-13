// Function: FUN_8026cbec
// Entry: 8026cbec
// Size: 2800 bytes

int FUN_8026cbec(int param_1,int param_2,int param_3,int *param_4,uint *param_5,undefined param_6,
                undefined2 param_7)

{
  bool bVar1;
  byte bVar2;
  byte bVar3;
  undefined4 uVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  undefined *puVar8;
  int *piVar9;
  uint uVar10;
  char cVar11;
  undefined1 *puVar12;
  int *piVar13;
  int *piVar14;
  uint uVar15;
  uint uVar16;
  int iVar17;
  
  piVar5 = DAT_803deeac;
  if (DAT_803deeac == (int *)0x0) {
    iVar7 = -1;
  }
  else {
    DAT_803deeac = (int *)*DAT_803deeac;
    if (DAT_803deeac != (int *)0x0) {
      DAT_803deeac[1] = 0;
    }
    bVar1 = DAT_803deeb4 != (int *)0x0;
    *piVar5 = (int)DAT_803deeb4;
    if (bVar1) {
      DAT_803deeb4[1] = (int)piVar5;
    }
    piVar5[1] = 0;
    DAT_803deeb4 = piVar5;
    *(undefined *)(piVar5 + 2) = 1;
    piVar5[0x541] = 0;
    piVar5[0x54f] = 0;
    piVar5[0x55d] = 0;
    piVar5[0x56b] = 0;
    piVar5[0x579] = 0;
    piVar5[0x587] = 0;
    piVar5[0x595] = 0;
    piVar5[0x5a3] = 0;
    piVar5[0x5b1] = 0;
    piVar5[0x5bf] = 0;
    piVar5[0x5cd] = 0;
    piVar5[0x5db] = 0;
    piVar5[0x5e9] = 0;
    piVar5[0x5f7] = 0;
    piVar5[0x605] = 0;
    piVar5[0x613] = 0;
    bVar2 = *(byte *)((int)piVar5 + 9);
    uVar16 = (uint)bVar2;
    *(undefined *)(piVar5 + 0x3b8) = 0;
    piVar5[4] = param_1;
    piVar5[0x25] = param_2;
    piVar5[0x46] = (int)param_4;
    *(undefined2 *)((int)piVar5 + 10) = param_7;
    iVar7 = piVar5[4];
    for (uVar10 = 0; (uVar10 & 0xff) < 0x80; uVar10 = uVar10 + 8) {
      *(undefined *)((int)piVar5 + (uVar10 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 1 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 2 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 3 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 4 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 5 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 6 & 0xff) + 0x14) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 7 & 0xff) + 0x14) = 0xff;
    }
    cVar11 = '\0';
    for (; *(byte *)(iVar7 + 4) != 0xff; iVar7 = iVar7 + 6) {
      *(char *)((int)piVar5 + *(byte *)(iVar7 + 4) + 0x14) = cVar11;
      cVar11 = cVar11 + '\x01';
    }
    iVar7 = piVar5[0x25];
    for (uVar10 = 0; (uVar10 & 0xff) < 0x80; uVar10 = uVar10 + 8) {
      *(undefined *)((int)piVar5 + (uVar10 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 1 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 2 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 3 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 4 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 5 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 6 & 0xff) + 0x98) = 0xff;
      *(undefined *)((int)piVar5 + (uVar10 + 7 & 0xff) + 0x98) = 0xff;
    }
    cVar11 = '\0';
    for (; *(byte *)(iVar7 + 4) != 0xff; iVar7 = iVar7 + 6) {
      *(char *)((int)piVar5 + *(byte *)(iVar7 + 4) + 0x98) = cVar11;
      cVar11 = cVar11 + '\x01';
    }
    iVar7 = 0;
    *(byte *)(piVar5 + 0x3ac) = bVar2 + 0x17;
    iVar17 = 2;
    do {
      puVar8 = (undefined *)((int)piVar5 + iVar7 + 0x324);
      *puVar8 = *(undefined *)(piVar5 + 0x3ac);
      puVar8[1] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[2] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[3] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[4] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[5] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[6] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[7] = *(undefined *)(piVar5 + 0x3ac);
      puVar8 = (undefined *)((int)piVar5 + iVar7 + 0x32c);
      *puVar8 = *(undefined *)(piVar5 + 0x3ac);
      puVar8[1] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[2] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[3] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[4] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[5] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[6] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[7] = *(undefined *)(piVar5 + 0x3ac);
      puVar8 = (undefined *)((int)piVar5 + iVar7 + 0x334);
      *puVar8 = *(undefined *)(piVar5 + 0x3ac);
      puVar8[1] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[2] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[3] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[4] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[5] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[6] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[7] = *(undefined *)(piVar5 + 0x3ac);
      puVar8 = (undefined *)((int)piVar5 + iVar7 + 0x33c);
      iVar7 = iVar7 + 0x20;
      *puVar8 = *(undefined *)(piVar5 + 0x3ac);
      puVar8[1] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[2] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[3] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[4] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[5] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[6] = *(undefined *)(piVar5 + 0x3ac);
      puVar8[7] = *(undefined *)(piVar5 + 0x3ac);
      iVar17 = iVar17 + -1;
    } while (iVar17 != 0);
    *(undefined *)((int)piVar5 + 0xee1) = param_6;
    if (param_5 == (uint *)0x0) {
      piVar5[0x47] = -1;
      piVar5[0x48] = -1;
      *(undefined2 *)((int)piVar5 + 0x151a) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x1552) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x158a) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x15c2) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x15fa) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x1632) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x166a) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x16a2) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x16da) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x1712) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x174a) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x1782) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x17ba) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x17f2) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x182a) = 0x100;
      *(undefined2 *)((int)piVar5 + 0x1862) = 0x100;
      FUN_802722b0(0x7f,0,(uint)*(byte *)(piVar5 + 0x3ac),0,0xffffffff);
    }
    else {
      if ((*param_5 & 1) == 0) {
        piVar5[0x47] = -1;
        piVar5[0x48] = -1;
      }
      else {
        piVar5[0x47] = param_5[1];
        piVar5[0x48] = param_5[2];
      }
      if ((*param_5 & 2) == 0) {
        *(undefined2 *)((int)piVar5 + 0x151a) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x1552) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x158a) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x15c2) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x15fa) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x1632) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x166a) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x16a2) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x16da) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x1712) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x174a) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x1782) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x17ba) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x17f2) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x182a) = 0x100;
        *(undefined2 *)((int)piVar5 + 0x1862) = 0x100;
      }
      else {
        *(undefined2 *)((int)piVar5 + 0x151a) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x1552) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x158a) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x15c2) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x15fa) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x1632) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x166a) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x16a2) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x16da) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x1712) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x174a) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x1782) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x17ba) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x17f2) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x182a) = *(undefined2 *)(param_5 + 3);
        *(undefined2 *)((int)piVar5 + 0x1862) = *(undefined2 *)(param_5 + 3);
      }
      if ((*param_5 & 8) != 0) {
        iVar17 = 0;
        for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)((int)param_5 + 0x12); iVar7 = iVar7 + 1) {
          *(byte *)((int)piVar5 + *(byte *)(param_5[5] + iVar17) + 0x324) =
               ((byte *)(param_5[5] + iVar17))[1];
          FUN_80272714((uint)*(byte *)(param_5[5] + iVar17 + 1),0);
          iVar17 = iVar17 + 2;
        }
      }
      if ((*param_5 & 4) != 0) {
        FUN_802722b0((uint)*(byte *)(param_5 + 4),(uint)*(ushort *)((int)param_5 + 0xe),
                     (uint)*(byte *)(piVar5 + 0x3ac),0,0xffffffff);
        for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(param_5 + 6); iVar7 = iVar7 + 1) {
          FUN_802722b0((uint)*(byte *)(param_5 + 4),(uint)*(ushort *)((int)param_5 + 0xe),
                       (uint)*(byte *)(param_5[7] + iVar7),0,0xffffffff);
        }
      }
    }
    if ((param_4[4] & 0x80000000U) == 0) {
      piVar5[0x539] = 0;
    }
    else {
      piVar5[0x539] = param_4[0x15] + (int)param_4;
    }
    uVar10 = param_4[4] & 0xfffffff;
    if ((param_4[4] & 0x40000000U) == 0) {
      uVar10 = uVar10 << 10;
    }
    uVar15 = 0;
    piVar9 = piVar5;
    do {
      piVar9[0x53c] = uVar10;
      FUN_8026fca0(uVar10 >> 10,bVar2,uVar15 & 0xff);
      if (param_4[3] == 0) {
        piVar9[0x53a] = 0;
      }
      else {
        piVar9[0x53a] = param_4[3] + (int)param_4;
        piVar9[0x53b] = piVar9[0x53a];
      }
      *(undefined *)((int)piVar9 + 0x151e) = 0;
      uVar15 = uVar15 + 1;
      *(undefined2 *)(piVar9 + 0x547) = 0;
      piVar9 = piVar9 + 0xe;
    } while ((int)uVar15 < 0x10);
    iVar7 = 0x10;
    puVar12 = &DAT_803be5c4;
    piVar13 = (int *)(*param_4 + (int)param_4);
    piVar9 = piVar5;
    piVar14 = piVar5;
    do {
      *puVar12 = 0x7f;
      piVar9[0xdb] = 0;
      if (*piVar13 == 0) {
        piVar14[0x49] = 0;
        piVar14[0x4a] = 0;
      }
      else {
        iVar17 = (int)param_4 + *piVar13;
        piVar14[0x49] = iVar17;
        piVar14[0x4a] = iVar17;
      }
      puVar12[1] = 0x7f;
      piVar9[0xe6] = 0;
      if (piVar13[1] == 0) {
        piVar14[0x4b] = 0;
        piVar14[0x4c] = 0;
      }
      else {
        iVar17 = (int)param_4 + piVar13[1];
        piVar14[0x4b] = iVar17;
        piVar14[0x4c] = iVar17;
      }
      puVar12[2] = 0x7f;
      piVar9[0xf1] = 0;
      if (piVar13[2] == 0) {
        piVar14[0x4d] = 0;
        piVar14[0x4e] = 0;
      }
      else {
        iVar17 = (int)param_4 + piVar13[2];
        piVar14[0x4d] = iVar17;
        piVar14[0x4e] = iVar17;
      }
      puVar12[3] = 0x7f;
      piVar9[0xfc] = 0;
      if (piVar13[3] == 0) {
        piVar14[0x4f] = 0;
        piVar14[0x50] = 0;
      }
      else {
        iVar17 = (int)param_4 + piVar13[3];
        piVar14[0x4f] = iVar17;
        piVar14[0x50] = iVar17;
      }
      puVar12 = puVar12 + 4;
      piVar9 = piVar9 + 0x2c;
      piVar13 = piVar13 + 4;
      piVar14 = piVar14 + 8;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    uVar10 = 0;
    piVar5[0x399] = 0;
    piVar5[0x39a] = 0;
    piVar5[0x39b] = 0;
    do {
      FUN_80282194(uVar10 & 0xff,uVar16,1);
      uVar10 = uVar10 + 1;
    } while ((int)uVar10 < 0x10);
    *(undefined2 *)(piVar5 + 0x39c) = 0xffff;
    *(undefined2 *)(piVar5 + 0x39d) = 0xffff;
    *(undefined2 *)(piVar5 + 0x39e) = 0xffff;
    *(undefined2 *)(piVar5 + 0x39f) = 0xffff;
    *(undefined2 *)(piVar5 + 0x3a0) = 0xffff;
    *(undefined2 *)(piVar5 + 0x3a1) = 0xffff;
    *(undefined2 *)(piVar5 + 0x3a2) = 0xffff;
    *(undefined2 *)(piVar5 + 0x3a3) = 0xffff;
    *(undefined2 *)(piVar5 + 0x3a4) = 0xffff;
    *(undefined2 *)(piVar5 + 0x3a5) = 0xffff;
    *(undefined2 *)(piVar5 + 0x3a6) = 0xffff;
    *(undefined2 *)(piVar5 + 0x3a7) = 0xffff;
    *(undefined2 *)(piVar5 + 0x3a8) = 0xffff;
    *(undefined2 *)(piVar5 + 0x3a9) = 0xffff;
    *(undefined2 *)(piVar5 + 0x3aa) = 0xffff;
    *(undefined2 *)(piVar5 + 0x3ab) = 0xffff;
    uVar10 = 0;
    do {
      FUN_80282550(uVar10 & 0xff,uVar16);
      uVar10 = uVar10 + 1;
    } while ((int)uVar10 < 0x10);
    if (param_3 != 0) {
      uVar10 = 0;
      do {
        uVar15 = uVar10 & 0xff;
        bVar3 = *(byte *)(param_3 + 4);
        (&DAT_803bd8f0)[DAT_803deea0 * 0x10 + (uVar10 & 0xff)] = 0xffff;
        if (uVar15 == 9) {
          uVar15 = (uint)*(byte *)((int)piVar5 + bVar3 + 0x98);
          if (uVar15 != 0xff) {
            iVar7 = uVar15 * 6;
            *(undefined2 *)(piVar5 + 0x3a5) = *(undefined2 *)(piVar5[0x25] + iVar7);
            *(undefined *)((int)piVar5 + 0xe96) = *(undefined *)(piVar5[0x25] + iVar7 + 2);
            *(undefined *)((int)piVar5 + 0xe97) = *(undefined *)(piVar5[0x25] + iVar7 + 3);
          }
        }
        else {
          uVar6 = (uint)*(byte *)((int)piVar5 + bVar3 + 0x14);
          if (uVar6 != 0xff) {
            iVar7 = uVar6 * 6;
            *(undefined2 *)(piVar5 + uVar15 + 0x39c) = *(undefined2 *)(piVar5[4] + iVar7);
            *(undefined *)((int)piVar5 + uVar15 * 4 + 0xe72) = *(undefined *)(piVar5[4] + iVar7 + 2)
            ;
            *(undefined *)((int)piVar5 + uVar15 * 4 + 0xe73) = *(undefined *)(piVar5[4] + iVar7 + 3)
            ;
          }
        }
        bVar3 = (byte)uVar10;
        FUN_80281a9c(7,bVar3,bVar2,*(byte *)(param_3 + 5));
        FUN_80281a9c(10,bVar3,bVar2,*(byte *)(param_3 + 6));
        FUN_80281a9c(0x5b,bVar3,bVar2,*(byte *)(param_3 + 7));
        FUN_80281a9c(0x5d,bVar3,bVar2,*(byte *)(param_3 + 8));
        uVar10 = uVar10 + 1;
        param_3 = param_3 + 5;
      } while ((int)uVar10 < 0x10);
    }
    (&DAT_803bd8f0)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd8f2)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd8f4)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd8f6)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd8f8)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd8fa)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd8fc)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd8fe)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd900)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd902)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd904)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd906)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd908)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd90a)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd90c)[uVar16 * 0x10] = 0xffff;
    (&DAT_803bd90e)[uVar16 * 0x10] = 0xffff;
    iVar7 = 2;
    piVar9 = piVar5;
    do {
      piVar9[0x543] = 0;
      piVar9[0x542] = 0;
      piVar9[0x545] = 0;
      piVar9[0x544] = 0;
      *(undefined *)(piVar9 + 0x546) = 0;
      piVar9[0x551] = 0;
      piVar9[0x550] = 0;
      piVar9[0x553] = 0;
      piVar9[0x552] = 0;
      *(undefined *)(piVar9 + 0x554) = 0;
      piVar9[0x55f] = 0;
      piVar9[0x55e] = 0;
      piVar9[0x561] = 0;
      piVar9[0x560] = 0;
      *(undefined *)(piVar9 + 0x562) = 0;
      piVar9[0x56d] = 0;
      piVar9[0x56c] = 0;
      piVar9[0x56f] = 0;
      piVar9[0x56e] = 0;
      *(undefined *)(piVar9 + 0x570) = 0;
      piVar9[0x57b] = 0;
      piVar9[0x57a] = 0;
      piVar9[0x57d] = 0;
      piVar9[0x57c] = 0;
      *(undefined *)(piVar9 + 0x57e) = 0;
      piVar9[0x589] = 0;
      piVar9[0x588] = 0;
      piVar9[0x58b] = 0;
      piVar9[0x58a] = 0;
      *(undefined *)(piVar9 + 0x58c) = 0;
      piVar9[0x597] = 0;
      piVar9[0x596] = 0;
      piVar9[0x599] = 0;
      piVar9[0x598] = 0;
      *(undefined *)(piVar9 + 0x59a) = 0;
      piVar9[0x5a5] = 0;
      piVar9[0x5a4] = 0;
      piVar9[0x5a7] = 0;
      piVar9[0x5a6] = 0;
      *(undefined *)(piVar9 + 0x5a8) = 0;
      piVar9 = piVar9 + 0x70;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    *(undefined *)((int)piVar5 + 0xee2) = 0;
    if ((param_5 != (uint *)0x0) && ((*param_5 & 0x10) != 0)) {
      FUN_8026d7c4(piVar5);
    }
    uVar4 = DAT_803dee98;
    DAT_803dee98 = piVar5;
    FUN_8026efc8();
    DAT_803dee98 = (int *)uVar4;
    iVar7 = FUN_8026cae4(uVar16);
  }
  return iVar7;
}

