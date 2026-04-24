// Function: FUN_8004b7d4
// Entry: 8004b7d4
// Size: 2352 bytes

undefined4 FUN_8004b7d4(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  ushort uVar4;
  uint uVar5;
  ushort *puVar6;
  byte *pbVar7;
  ushort *puVar8;
  byte *pbVar9;
  uint uVar10;
  undefined *puVar11;
  int iVar12;
  int iVar13;
  undefined *puVar14;
  undefined *puVar15;
  int iVar16;
  uint uVar17;
  uint uVar18;
  undefined *puVar19;
  undefined2 *puVar20;
  short *psVar21;
  int iVar22;
  int iVar23;
  uint uVar24;
  int iVar25;
  uint uVar26;
  undefined1 *puVar27;
  undefined1 *puVar28;
  uint uVar29;
  uint uVar30;
  bool bVar31;
  
  pbVar9 = (byte *)(param_3 + -1);
  uVar10 = 0;
  uVar17 = 0;
  puVar6 = (ushort *)(param_1 + 2);
  do {
    bVar1 = *(byte *)puVar6;
    uVar5 = uVar17 & 0x1f;
    pbVar7 = (byte *)((int)puVar6 + ((int)(uVar10 + 1) >> 3));
    uVar10 = uVar10 + 1 & 7;
    uVar17 = 0x20 - uVar10 & 0x1f;
    uVar18 = ((uint)*pbVar7 << uVar17 & 0xff | (uint)(*pbVar7 >> 0x20 - uVar17) |
             (uint)pbVar7[1] << 8 - uVar10) & 3;
    puVar6 = (ushort *)(pbVar7 + ((int)(uVar10 + 2) >> 3));
    uVar10 = uVar10 + 2 & 7;
    bVar31 = uVar10 < 0x21;
    uVar17 = 0x20 - uVar10;
    if (uVar18 == 0) {
      if (uVar10 != 0) {
        puVar6 = (ushort *)((int)puVar6 + 1);
        uVar10 = 0;
      }
      uVar4 = *puVar6;
      puVar8 = (ushort *)((int)puVar6 + 1);
      puVar6 = puVar6 + 2;
      uVar18 = (uint)uVar4 | (uint)*puVar8 << 8;
      do {
        bVar2 = *(byte *)puVar6;
        puVar6 = (ushort *)((int)puVar6 + 1);
        pbVar9 = pbVar9 + 1;
        *pbVar9 = bVar2;
        uVar24 = (uint)bVar31;
        bVar31 = CARRY4(uVar18,uVar24 - 1);
        uVar18 = uVar18 + (uVar24 - 1);
      } while (uVar18 != 0);
    }
    else {
      if (uVar18 == 1) {
        puVar11 = &DAT_8030d440;
        iVar12 = -0x7fcf2aa0;
        iVar13 = 9;
        puVar14 = &DAT_8030d960;
        puVar15 = &DAT_8030d980;
        iVar16 = 5;
      }
      else {
        puVar11 = &DAT_803603a0;
        iVar12 = -0x7fc9fb40;
        puVar14 = &DAT_803704c0;
        puVar15 = &DAT_803704e0;
        iVar13 = 8;
        puVar19 = &DAT_803dd9a0;
        do {
          *puVar19 = 0;
          puVar19 = puVar19 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x13;
        puVar19 = &DAT_803784e0;
        do {
          *puVar19 = 0;
          puVar19 = puVar19 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x10;
        puVar20 = &DAT_803784f4;
        do {
          *puVar20 = 0;
          puVar20 = puVar20 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x120;
        puVar19 = puVar11;
        do {
          *puVar19 = 0;
          puVar19 = puVar19 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x10;
        puVar20 = &DAT_80378514;
        do {
          *puVar20 = 0;
          puVar20 = puVar20 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x20;
        puVar19 = puVar14;
        do {
          *puVar19 = 0;
          puVar19 = puVar19 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar16 = (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                   (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                  (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 0x1f) + 0x101;
        pbVar7 = (byte *)((int)puVar6 + ((int)(uVar10 + 5) >> 3));
        uVar10 = uVar10 + 5 & 7;
        uVar17 = 0x20 - uVar10 & 0x1f;
        iVar23 = (((uint)*pbVar7 << uVar17 & 0xff | (uint)(*pbVar7 >> 0x20 - uVar17) |
                  (uint)pbVar7[1] << 8 - uVar10) & 0x1f) + 1;
        pbVar7 = pbVar7 + ((int)(uVar10 + 5) >> 3);
        uVar24 = uVar10 + 5 & 7;
        bVar2 = pbVar7[1];
        bVar3 = *pbVar7;
        uVar18 = 0x20 - uVar24 & 0x1f;
        uVar10 = uVar24 + 4;
        puVar6 = (ushort *)(pbVar7 + ((int)uVar10 >> 3));
        puVar28 = &DAT_802c23d0;
        iVar13 = 0;
        while( true ) {
          uVar10 = uVar10 & 7;
          uVar17 = 0x20 - uVar10;
          if (iVar13 == (((uint)bVar3 << uVar18 & 0xff | (uint)(bVar3 >> 0x20 - uVar18) |
                         (uint)bVar2 << 8 - uVar24) & 0xf) + 4) break;
          uVar17 = ((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                    (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                   (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 7;
          (&DAT_803784e0)[(byte)(&DAT_802c23d0)[iVar13]] = (char)uVar17;
          uVar10 = uVar10 + 3;
          (&DAT_803dd9a0)[uVar17] = (&DAT_803dd9a0)[uVar17] + '\x01';
          puVar6 = (ushort *)((int)puVar6 + ((int)uVar10 >> 3));
          iVar13 = iVar13 + 1;
        }
        for (iVar13 = 7; (&DAT_803dd9a0)[iVar13] == '\0'; iVar13 = iVar13 + -1) {
        }
        iVar22 = 0;
        for (iVar25 = 1; iVar25 <= iVar13; iVar25 = iVar25 + 1) {
          if ((byte)(&DAT_803dd9a0)[iVar25] != 0) {
            (&DAT_803dd998)[iVar25] = (char)iVar22;
            iVar22 = iVar22 + ((uint)(byte)(&DAT_803dd9a0)[iVar25] << iVar13 - iVar25);
          }
        }
        for (iVar22 = 0; iVar22 < 0x13; iVar22 = iVar22 + 1) {
          puVar28 = &DAT_803dd998;
          uVar18 = (uint)(byte)(&DAT_803784e0)[iVar22];
          if (uVar18 != 0) {
            for (iVar25 = 0; iVar25 < 1 << iVar13 - uVar18; iVar25 = iVar25 + 1) {
              bVar2 = (&DAT_803dd998)[uVar18];
              (&DAT_803dd998)[uVar18] = bVar2 + 1;
              (&DAT_80378534)[bVar2] = (char)iVar22;
            }
          }
        }
        puVar20 = &DAT_803784f4;
        iVar22 = 0;
        puVar19 = puVar11;
        do {
          uVar18 = 0;
          if (8 - iVar13 < (int)uVar10) {
            uVar18 = (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10;
          }
          uVar24 = iVar13 + 0x18U & 0x1f;
          puVar27 = (undefined1 *)
                    (uint)(byte)(&DAT_80378534)
                                [(uint)(byte)(&DAT_8030d9a0)
                                             [((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                                               (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                                              uVar18) & (1 << iVar13) - 1U] << uVar24 & 0xff |
                                 (uint)((byte)(&DAT_8030d9a0)
                                              [((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                                                (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                                               uVar18) & (1 << iVar13) - 1U] >> 0x20 - uVar24)];
          puVar6 = (ushort *)
                   ((int)puVar6 + ((int)(uVar10 + (byte)(&DAT_803784e0)[(int)puVar27]) >> 3));
          uVar10 = uVar10 + (byte)(&DAT_803784e0)[(int)puVar27] & 7;
          bVar31 = uVar10 < 0x21;
          uVar17 = 0x20 - uVar10;
          if (puVar27 == (undefined1 *)0x10) {
            uVar18 = (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                       (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                      (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 3) + 3;
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + 2) >> 3));
            uVar10 = uVar10 + 2 & 7;
            bVar31 = uVar10 < 0x21;
            uVar17 = 0x20 - uVar10;
            puVar27 = puVar28;
          }
          else if (puVar27 == (undefined1 *)0x11) {
            puVar27 = (undefined1 *)0x0;
            uVar18 = (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                       (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                      (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 7) + 3;
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + 3) >> 3));
            uVar10 = uVar10 + 3 & 7;
            bVar31 = uVar10 < 0x21;
            uVar17 = 0x20 - uVar10;
          }
          else if (puVar27 == (undefined1 *)0x12) {
            puVar27 = (undefined1 *)0x0;
            uVar18 = (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                       (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                      (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 0x7f) + 0xb;
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + 7) >> 3));
            uVar10 = uVar10 + 7 & 7;
            bVar31 = uVar10 < 0x21;
            uVar17 = 0x20 - uVar10;
          }
          else {
            uVar18 = 1;
          }
          do {
            puVar19[iVar22] = (char)puVar27;
            iVar22 = iVar22 + 1;
            puVar20[(int)puVar27] = puVar20[(int)puVar27] + 1;
            if ((puVar19 == &DAT_803603a0) && (iVar22 == iVar16)) {
              puVar20 = &DAT_80378514;
              iVar22 = 0;
              puVar19 = puVar14;
            }
            uVar24 = (uint)bVar31;
            bVar31 = CARRY4(uVar18,uVar24 - 1);
            uVar18 = uVar18 + (uVar24 - 1);
          } while (uVar18 != 0);
          puVar28 = puVar27;
        } while ((puVar19 == &DAT_803603a0) || (iVar22 < iVar23));
        iVar13 = 0xf;
        for (psVar21 = &DAT_80378512; *psVar21 == 0; psVar21 = psVar21 + -1) {
          iVar13 = iVar13 + -1;
        }
        iVar22 = 0;
        for (iVar25 = 1; iVar25 <= iVar13; iVar25 = iVar25 + 1) {
          uVar4 = (&DAT_803784f4)[iVar25];
          if (uVar4 != 0) {
            *(short *)(iVar25 * 2 + -0x7fc87a4c) = (short)iVar22;
            iVar22 = iVar22 + ((uint)uVar4 << iVar13 - iVar25);
          }
        }
        for (iVar22 = 0; iVar22 < iVar16; iVar22 = iVar22 + 1) {
          uVar18 = (uint)(byte)(&DAT_803603a0)[iVar22];
          if (uVar18 != 0) {
            for (iVar25 = 0; iVar25 < 1 << iVar13 - uVar18; iVar25 = iVar25 + 1) {
              puVar8 = (ushort *)(uVar18 * 2 + -0x7fc87a4c);
              uVar4 = *puVar8;
              *puVar8 = uVar4 + 1;
              *(short *)((uint)uVar4 * 2 + -0x7fc9fb40) = (short)iVar22;
            }
          }
        }
        for (iVar16 = 0xf; (&DAT_80378514)[iVar16] == 0; iVar16 = iVar16 + -1) {
        }
        iVar22 = 0;
        for (iVar25 = 1; iVar25 <= iVar16; iVar25 = iVar25 + 1) {
          if ((ushort)(&DAT_80378514)[iVar25] != 0) {
            (&DAT_803785d4)[iVar25] = (short)iVar22;
            iVar22 = iVar22 + ((uint)(ushort)(&DAT_80378514)[iVar25] << iVar16 - iVar25);
          }
        }
        for (iVar22 = 0; iVar22 < iVar23; iVar22 = iVar22 + 1) {
          uVar18 = (uint)(byte)(&DAT_803704c0)[iVar22];
          if (uVar18 != 0) {
            for (iVar25 = 0; iVar25 < 1 << iVar16 - uVar18; iVar25 = iVar25 + 1) {
              uVar4 = (&DAT_803785d4)[uVar18];
              (&DAT_803785d4)[uVar18] = uVar4 + 1;
              (&DAT_803704e0)[uVar4] = (char)iVar22;
            }
          }
        }
      }
      do {
        uVar24 = ((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                  (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                  (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10 |
                 (uint)*(byte *)(puVar6 + 1) << 0x10 - uVar10) & (1 << iVar13) - 1U;
        uVar17 = iVar13 - 8U & 0x1f;
        uVar18 = iVar13 + 0x10U & 0x1f;
        uVar4 = *(ushort *)
                 (iVar12 + ((uint)(byte)(&DAT_8030d9a0)[uVar24 & 0xff] << uVar17 & 0xffff |
                            (uint)((byte)(&DAT_8030d9a0)[uVar24 & 0xff] >> 0x20 - uVar17) |
                           (uint)(byte)(&DAT_8030d9a0)[uVar24 >> 8] << uVar18 & 0xff |
                           (uint)((byte)(&DAT_8030d9a0)[uVar24 >> 8] >> 0x20 - uVar18)) * 2);
        uVar18 = (uint)uVar4;
        puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + (byte)puVar11[uVar18]) >> 3));
        uVar10 = uVar10 + (byte)puVar11[uVar18] & 7;
        uVar17 = 0x20 - uVar10;
        if (uVar18 < 0x100) {
          pbVar9 = pbVar9 + 1;
          *pbVar9 = (byte)uVar4;
        }
        else {
          if (uVar18 == 0x100) break;
          iVar23 = (uVar18 - 0x101) * 4;
          uVar29 = (uint)*(ushort *)(&DAT_802c23e4 + iVar23);
          uVar24 = (uint)*(ushort *)(&DAT_802c23e6 + iVar23);
          if (uVar24 != 0) {
            uVar29 = uVar29 + (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                                (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                               (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & (1 << uVar24) - 1U)
            ;
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + uVar24) >> 3));
            uVar10 = uVar10 + uVar24 & 7;
            uVar17 = 0x20 - uVar10;
          }
          uVar26 = ((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                    (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                    (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10 |
                   (uint)*(byte *)(puVar6 + 1) << 0x10 - uVar10) & (1 << iVar16) - 1U;
          uVar24 = iVar16 - 8U & 0x1f;
          uVar30 = iVar16 + 0x10U & 0x1f;
          puVar6 = (ushort *)
                   ((int)puVar6 +
                   ((int)(uVar10 + (byte)puVar14[(byte)puVar15[(uint)(byte)(&DAT_8030d9a0)
                                                                           [uVar26 & 0xff] << uVar24
                                                               & 0xffff |
                                                               (uint)((byte)(&DAT_8030d9a0)
                                                                            [uVar26 & 0xff] >>
                                                                     0x20 - uVar24) |
                                                               (uint)(byte)(&DAT_8030d9a0)
                                                                           [uVar26 >> 8] << uVar30 &
                                                               0xff | (uint)((byte)(&DAT_8030d9a0)
                                                                                   [uVar26 >> 8] >>
                                                                            0x20 - uVar30)]]) >> 3))
          ;
          uVar10 = uVar10 + (byte)puVar14[(byte)puVar15[(uint)(byte)(&DAT_8030d9a0)[uVar26 & 0xff]
                                                        << uVar24 & 0xffff |
                                                        (uint)((byte)(&DAT_8030d9a0)[uVar26 & 0xff]
                                                              >> 0x20 - uVar24) |
                                                        (uint)(byte)(&DAT_8030d9a0)[uVar26 >> 8] <<
                                                        uVar30 & 0xff |
                                                        (uint)((byte)(&DAT_8030d9a0)[uVar26 >> 8] >>
                                                              0x20 - uVar30)]] & 7;
          uVar17 = 0x20 - uVar10;
          iVar23 = (uint)(byte)puVar15[(uint)(byte)(&DAT_8030d9a0)[uVar26 & 0xff] << uVar24 & 0xffff
                                       | (uint)((byte)(&DAT_8030d9a0)[uVar26 & 0xff] >>
                                               0x20 - uVar24) |
                                       (uint)(byte)(&DAT_8030d9a0)[uVar26 >> 8] << uVar30 & 0xff |
                                       (uint)((byte)(&DAT_8030d9a0)[uVar26 >> 8] >> 0x20 - uVar30)]
                   * 4;
          uVar30 = (uint)*(ushort *)(&DAT_802c2458 + iVar23);
          uVar24 = (uint)*(ushort *)(&DAT_802c245a + iVar23);
          if (uVar24 != 0) {
            uVar30 = uVar30 + (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                                (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                                (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10 |
                               (uint)*(byte *)(puVar6 + 1) << 0x10 - uVar10) & (1 << uVar24) - 1U);
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + uVar24) >> 3));
            uVar10 = uVar10 + uVar24 & 7;
            uVar17 = 0x20 - uVar10;
          }
          pbVar7 = pbVar9 + -uVar30;
          do {
            pbVar7 = pbVar7 + 1;
            pbVar9 = pbVar9 + 1;
            *pbVar9 = *pbVar7;
            uVar29 = uVar29 - 1;
          } while (uVar29 != 0);
        }
      } while (uVar18 != 0x100);
    }
    if ((((uint)bVar1 << uVar5 | (uint)(bVar1 >> 0x20 - uVar5)) & 1) != 0) {
      return 0;
    }
  } while( true );
}

