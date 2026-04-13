// Function: FUN_8006a1a4
// Entry: 8006a1a4
// Size: 5424 bytes

void FUN_8006a1a4(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  undefined *puVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  undefined2 *puVar8;
  uint uVar9;
  byte *pbVar10;
  int iVar11;
  undefined4 *puVar12;
  byte *pbVar13;
  byte *pbVar14;
  undefined2 *puVar15;
  uint uVar16;
  undefined4 *puVar17;
  byte *pbVar18;
  byte *pbVar19;
  byte *pbVar20;
  uint uVar21;
  uint uVar22;
  undefined8 uVar23;
  byte local_138 [2];
  undefined2 uStack_136;
  byte local_134 [2];
  undefined2 uStack_132;
  byte local_130 [2];
  undefined2 uStack_12e;
  byte local_12c [2];
  undefined2 uStack_12a;
  undefined2 local_128 [56];
  byte local_b8 [2];
  undefined2 uStack_b6;
  byte local_b4 [2];
  undefined2 uStack_b2;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8 [42];
  
  uVar23 = FUN_80286834();
  uVar6 = (uint)uVar23;
  uVar5 = (int)((ulonglong)uVar23 >> 0x20) + 0x60;
  uVar16 = (int)param_3 >> 0x1f;
  iVar7 = (int)param_3 >> 1;
  if ((uVar16 * 8 | param_3 * 0x20000000 + uVar16 >> 0x1d) == uVar16) {
    uVar21 = (int)param_3 >> 3;
    pbVar20 = local_b8 + param_3;
    for (uVar16 = 0; uVar16 < uVar6; uVar16 = uVar16 + 1) {
      puVar17 = (undefined4 *)(uVar5 + (uVar16 & 3) * 8 + uVar6 * (uVar16 & 0xfffffffc));
      pbVar14 = local_b8;
      uVar9 = 0;
      if (uVar21 != 0) {
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *(undefined4 *)pbVar14 = param_4;
            *(undefined4 *)(pbVar14 + 4) = param_4;
            *(undefined4 *)(pbVar14 + 8) = param_4;
            *(undefined4 *)(pbVar14 + 0xc) = param_4;
            *(undefined4 *)(pbVar14 + 0x10) = param_4;
            *(undefined4 *)(pbVar14 + 0x14) = param_4;
            *(undefined4 *)(pbVar14 + 0x18) = param_4;
            *(undefined4 *)(pbVar14 + 0x1c) = param_4;
            pbVar14 = pbVar14 + 0x20;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar3 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *(undefined4 *)pbVar14 = param_4;
            pbVar14 = pbVar14 + 4;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      uVar9 = uVar6 + 7 >> 3;
      if (uVar6 != 0) {
        uVar22 = uVar6 + 7 >> 6;
        puVar12 = puVar17;
        if (uVar22 != 0) {
          do {
            *(undefined4 *)pbVar14 = *puVar12;
            *(undefined4 *)(pbVar14 + 4) = puVar12[1];
            *(undefined4 *)(pbVar14 + 8) = puVar12[8];
            *(undefined4 *)(pbVar14 + 0xc) = puVar12[9];
            *(undefined4 *)(pbVar14 + 0x10) = puVar12[0x10];
            *(undefined4 *)(pbVar14 + 0x14) = puVar12[0x11];
            *(undefined4 *)(pbVar14 + 0x18) = puVar12[0x18];
            *(undefined4 *)(pbVar14 + 0x1c) = puVar12[0x19];
            *(undefined4 *)(pbVar14 + 0x20) = puVar12[0x20];
            *(undefined4 *)(pbVar14 + 0x24) = puVar12[0x21];
            *(undefined4 *)(pbVar14 + 0x28) = puVar12[0x28];
            *(undefined4 *)(pbVar14 + 0x2c) = puVar12[0x29];
            *(undefined4 *)(pbVar14 + 0x30) = puVar12[0x30];
            *(undefined4 *)(pbVar14 + 0x34) = puVar12[0x31];
            *(undefined4 *)(pbVar14 + 0x38) = puVar12[0x38];
            *(undefined4 *)(pbVar14 + 0x3c) = puVar12[0x39];
            pbVar14 = pbVar14 + 0x40;
            puVar12 = puVar12 + 0x40;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 7;
          if (uVar9 == 0) goto LAB_8006a35c;
        }
        do {
          *(undefined4 *)pbVar14 = *puVar12;
          *(undefined4 *)(pbVar14 + 4) = puVar12[1];
          pbVar14 = pbVar14 + 8;
          uVar9 = uVar9 - 1;
          puVar12 = puVar12 + 8;
        } while (uVar9 != 0);
      }
LAB_8006a35c:
      uVar9 = 0;
      if (uVar21 != 0) {
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *(undefined4 *)pbVar14 = param_4;
            *(undefined4 *)(pbVar14 + 4) = param_4;
            *(undefined4 *)(pbVar14 + 8) = param_4;
            *(undefined4 *)(pbVar14 + 0xc) = param_4;
            *(undefined4 *)(pbVar14 + 0x10) = param_4;
            *(undefined4 *)(pbVar14 + 0x14) = param_4;
            *(undefined4 *)(pbVar14 + 0x18) = param_4;
            *(undefined4 *)(pbVar14 + 0x1c) = param_4;
            pbVar14 = pbVar14 + 0x20;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar3 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *(undefined4 *)pbVar14 = param_4;
            pbVar14 = pbVar14 + 4;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      uVar9 = 0;
      iVar3 = 0;
      if (0 < (int)param_3) {
        if (8 < (int)param_3) {
          pbVar14 = local_b8;
          uVar22 = param_3 - 1 >> 3;
          if (0 < (int)(param_3 - 8)) {
            do {
              uVar9 = uVar9 + *pbVar14 + (uint)pbVar14[1] + (uint)pbVar14[2] + (uint)pbVar14[3] +
                      (uint)pbVar14[4] + (uint)pbVar14[5] + (uint)pbVar14[6] + (uint)pbVar14[7];
              pbVar14 = pbVar14 + 8;
              iVar3 = iVar3 + 8;
              uVar22 = uVar22 - 1;
            } while (uVar22 != 0);
          }
        }
        pbVar14 = local_b8 + iVar3;
        iVar4 = param_3 - iVar3;
        if (iVar3 < (int)param_3) {
          do {
            uVar9 = uVar9 + *pbVar14;
            pbVar14 = pbVar14 + 1;
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
      iVar3 = 0;
      if (0 < (int)uVar6) {
        if (8 < (int)uVar6) {
          pbVar10 = local_b8;
          uVar22 = uVar6 - 1 >> 3;
          pbVar14 = pbVar20;
          puVar1 = &stack0xfffffec0;
          if (0 < (int)(uVar6 - 8)) {
            do {
              puVar1[8] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *pbVar10) + (uint)*pbVar14;
              puVar1[9] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[1]) + (uint)pbVar14[1];
              puVar1[10] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[2]) + (uint)pbVar14[2];
              puVar1[0xb] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[3]) + (uint)pbVar14[3];
              puVar1[0xc] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[4]) + (uint)pbVar14[4];
              puVar1[0xd] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[5]) + (uint)pbVar14[5];
              puVar1[0xe] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[6]) + (uint)pbVar14[6];
              puVar1[0xf] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[7]) + (uint)pbVar14[7];
              pbVar10 = pbVar10 + 8;
              pbVar14 = pbVar14 + 8;
              iVar3 = iVar3 + 8;
              uVar22 = uVar22 - 1;
              puVar1 = puVar1 + 8;
            } while (uVar22 != 0);
          }
        }
        pbVar14 = local_138 + iVar3;
        pbVar10 = local_b8 + iVar3;
        pbVar19 = pbVar20 + iVar3;
        iVar4 = uVar6 - iVar3;
        if (iVar3 < (int)uVar6) {
          do {
            *pbVar14 = (byte)(uVar9 / param_3);
            uVar9 = (uVar9 - *pbVar10) + (uint)*pbVar19;
            pbVar14 = pbVar14 + 1;
            pbVar10 = pbVar10 + 1;
            pbVar19 = pbVar19 + 1;
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
      pbVar14 = local_138;
      uVar9 = uVar6 + 7 >> 3;
      if (uVar6 != 0) {
        uVar22 = uVar6 + 7 >> 6;
        if (uVar22 != 0) {
          do {
            *puVar17 = *(undefined4 *)pbVar14;
            puVar17[1] = *(undefined4 *)(pbVar14 + 4);
            puVar17[8] = *(undefined4 *)(pbVar14 + 8);
            puVar17[9] = *(undefined4 *)(pbVar14 + 0xc);
            puVar17[0x10] = *(undefined4 *)(pbVar14 + 0x10);
            puVar17[0x11] = *(undefined4 *)(pbVar14 + 0x14);
            puVar17[0x18] = *(undefined4 *)(pbVar14 + 0x18);
            puVar17[0x19] = *(undefined4 *)(pbVar14 + 0x1c);
            puVar17[0x20] = *(undefined4 *)(pbVar14 + 0x20);
            puVar17[0x21] = *(undefined4 *)(pbVar14 + 0x24);
            puVar17[0x28] = *(undefined4 *)(pbVar14 + 0x28);
            puVar17[0x29] = *(undefined4 *)(pbVar14 + 0x2c);
            puVar17[0x30] = *(undefined4 *)(pbVar14 + 0x30);
            puVar17[0x31] = *(undefined4 *)(pbVar14 + 0x34);
            puVar17[0x38] = *(undefined4 *)(pbVar14 + 0x38);
            puVar17[0x39] = *(undefined4 *)(pbVar14 + 0x3c);
            pbVar14 = pbVar14 + 0x40;
            puVar17 = puVar17 + 0x40;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 7;
          if (uVar9 == 0) goto LAB_8006a6d8;
        }
        do {
          *puVar17 = *(undefined4 *)pbVar14;
          puVar17[1] = *(undefined4 *)(pbVar14 + 4);
          pbVar14 = pbVar14 + 8;
          puVar17 = puVar17 + 8;
          uVar9 = uVar9 - 1;
        } while (uVar9 != 0);
      }
LAB_8006a6d8:
    }
    iVar3 = ((int)uVar6 >> 3) * 0x20;
    pbVar14 = local_b8 + uVar6 + iVar7;
    for (uVar16 = 0; uVar16 < uVar6; uVar16 = uVar16 + 1) {
      pbVar19 = (byte *)(uVar5 + (uVar16 & 7) + (uVar16 >> 3) * 0x20);
      pbVar10 = local_b8;
      uVar9 = 0;
      if (uVar21 != 0) {
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *(undefined4 *)pbVar10 = param_4;
            *(undefined4 *)(pbVar10 + 4) = param_4;
            *(undefined4 *)(pbVar10 + 8) = param_4;
            *(undefined4 *)(pbVar10 + 0xc) = param_4;
            *(undefined4 *)(pbVar10 + 0x10) = param_4;
            *(undefined4 *)(pbVar10 + 0x14) = param_4;
            *(undefined4 *)(pbVar10 + 0x18) = param_4;
            *(undefined4 *)(pbVar10 + 0x1c) = param_4;
            pbVar10 = pbVar10 + 0x20;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar4 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *(undefined4 *)pbVar10 = param_4;
            pbVar10 = pbVar10 + 4;
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
      uVar9 = uVar6 + 3 >> 2;
      if (uVar6 != 0) {
        uVar22 = uVar6 + 3 >> 4;
        pbVar10 = pbVar19;
        pbVar13 = local_b8 + iVar7;
        if (uVar22 != 0) {
          do {
            *pbVar13 = *pbVar10;
            pbVar13[1] = pbVar10[8];
            pbVar13[2] = pbVar10[0x10];
            pbVar13[3] = pbVar10[0x18];
            pbVar10 = pbVar10 + iVar3;
            pbVar13[4] = *pbVar10;
            pbVar13[5] = pbVar10[8];
            pbVar13[6] = pbVar10[0x10];
            pbVar13[7] = pbVar10[0x18];
            pbVar10 = pbVar10 + iVar3;
            pbVar13[8] = *pbVar10;
            pbVar13[9] = pbVar10[8];
            pbVar13[10] = pbVar10[0x10];
            pbVar13[0xb] = pbVar10[0x18];
            pbVar10 = pbVar10 + iVar3;
            pbVar13[0xc] = *pbVar10;
            pbVar13[0xd] = pbVar10[8];
            pbVar13[0xe] = pbVar10[0x10];
            pbVar13[0xf] = pbVar10[0x18];
            pbVar13 = pbVar13 + 0x10;
            pbVar10 = pbVar10 + iVar3;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 3;
          if (uVar9 == 0) goto LAB_8006a890;
        }
        do {
          *pbVar13 = *pbVar10;
          pbVar13[1] = pbVar10[8];
          pbVar13[2] = pbVar10[0x10];
          pbVar13[3] = pbVar10[0x18];
          uVar9 = uVar9 - 1;
          pbVar10 = pbVar10 + iVar3;
          pbVar13 = pbVar13 + 4;
        } while (uVar9 != 0);
      }
LAB_8006a890:
      uVar9 = 0;
      if (uVar21 != 0) {
        pbVar10 = pbVar14;
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *(undefined4 *)pbVar10 = param_4;
            *(undefined4 *)(pbVar10 + 4) = param_4;
            *(undefined4 *)(pbVar10 + 8) = param_4;
            *(undefined4 *)(pbVar10 + 0xc) = param_4;
            *(undefined4 *)(pbVar10 + 0x10) = param_4;
            *(undefined4 *)(pbVar10 + 0x14) = param_4;
            *(undefined4 *)(pbVar10 + 0x18) = param_4;
            *(undefined4 *)(pbVar10 + 0x1c) = param_4;
            pbVar10 = pbVar10 + 0x20;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar4 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *(undefined4 *)pbVar10 = param_4;
            pbVar10 = pbVar10 + 4;
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
      uVar9 = 0;
      iVar4 = 0;
      if (0 < (int)param_3) {
        if (8 < (int)param_3) {
          pbVar10 = local_b8;
          uVar22 = param_3 - 1 >> 3;
          if (0 < (int)(param_3 - 8)) {
            do {
              uVar9 = uVar9 + *pbVar10 + (uint)pbVar10[1] + (uint)pbVar10[2] + (uint)pbVar10[3] +
                      (uint)pbVar10[4] + (uint)pbVar10[5] + (uint)pbVar10[6] + (uint)pbVar10[7];
              pbVar10 = pbVar10 + 8;
              iVar4 = iVar4 + 8;
              uVar22 = uVar22 - 1;
            } while (uVar22 != 0);
          }
        }
        pbVar10 = local_b8 + iVar4;
        iVar11 = param_3 - iVar4;
        if (iVar4 < (int)param_3) {
          do {
            uVar9 = uVar9 + *pbVar10;
            pbVar10 = pbVar10 + 1;
            iVar11 = iVar11 + -1;
          } while (iVar11 != 0);
        }
      }
      iVar4 = 0;
      if (0 < (int)uVar6) {
        if (8 < (int)uVar6) {
          pbVar13 = local_b8;
          uVar22 = uVar6 - 1 >> 3;
          pbVar10 = pbVar20;
          puVar1 = &stack0xfffffec0;
          if (0 < (int)(uVar6 - 8)) {
            do {
              puVar1[8] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *pbVar13) + (uint)*pbVar10;
              puVar1[9] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[1]) + (uint)pbVar10[1];
              puVar1[10] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[2]) + (uint)pbVar10[2];
              puVar1[0xb] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[3]) + (uint)pbVar10[3];
              puVar1[0xc] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[4]) + (uint)pbVar10[4];
              puVar1[0xd] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[5]) + (uint)pbVar10[5];
              puVar1[0xe] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[6]) + (uint)pbVar10[6];
              puVar1[0xf] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[7]) + (uint)pbVar10[7];
              pbVar13 = pbVar13 + 8;
              pbVar10 = pbVar10 + 8;
              iVar4 = iVar4 + 8;
              uVar22 = uVar22 - 1;
              puVar1 = puVar1 + 8;
            } while (uVar22 != 0);
          }
        }
        pbVar10 = local_138 + iVar4;
        pbVar13 = local_b8 + iVar4;
        pbVar18 = pbVar20 + iVar4;
        iVar11 = uVar6 - iVar4;
        if (iVar4 < (int)uVar6) {
          do {
            *pbVar10 = (byte)(uVar9 / param_3);
            uVar9 = (uVar9 - *pbVar13) + (uint)*pbVar18;
            pbVar10 = pbVar10 + 1;
            pbVar13 = pbVar13 + 1;
            pbVar18 = pbVar18 + 1;
            iVar11 = iVar11 + -1;
          } while (iVar11 != 0);
        }
      }
      pbVar10 = local_138;
      uVar9 = uVar6 + 3 >> 2;
      if (uVar6 != 0) {
        uVar22 = uVar6 + 3 >> 4;
        if (uVar22 != 0) {
          do {
            *pbVar19 = *pbVar10;
            pbVar19[8] = pbVar10[1];
            pbVar19[0x10] = pbVar10[2];
            pbVar19[0x18] = pbVar10[3];
            pbVar19 = pbVar19 + iVar3;
            *pbVar19 = pbVar10[4];
            pbVar19[8] = pbVar10[5];
            pbVar19[0x10] = pbVar10[6];
            pbVar19[0x18] = pbVar10[7];
            pbVar19 = pbVar19 + iVar3;
            *pbVar19 = pbVar10[8];
            pbVar19[8] = pbVar10[9];
            pbVar19[0x10] = pbVar10[10];
            pbVar19[0x18] = pbVar10[0xb];
            pbVar19 = pbVar19 + iVar3;
            *pbVar19 = pbVar10[0xc];
            pbVar19[8] = pbVar10[0xd];
            pbVar19[0x10] = pbVar10[0xe];
            pbVar19[0x18] = pbVar10[0xf];
            pbVar10 = pbVar10 + 0x10;
            pbVar19 = pbVar19 + iVar3;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 3;
          if (uVar9 == 0) goto LAB_8006ac28;
        }
        do {
          *pbVar19 = *pbVar10;
          pbVar19[8] = pbVar10[1];
          pbVar19[0x10] = pbVar10[2];
          pbVar19[0x18] = pbVar10[3];
          pbVar10 = pbVar10 + 4;
          pbVar19 = pbVar19 + iVar3;
          uVar9 = uVar9 - 1;
        } while (uVar9 != 0);
      }
LAB_8006ac28:
    }
  }
  else {
    uVar21 = (int)param_3 >> 2;
    uVar2 = (undefined2)param_4;
    pbVar20 = local_b8 + param_3;
    for (uVar16 = 0; uVar16 < uVar6; uVar16 = uVar16 + 1) {
      puVar15 = (undefined2 *)(uVar5 + (uVar16 & 3) * 8 + uVar6 * (uVar16 & 0xfffffffc));
      pbVar14 = local_b8;
      uVar9 = 0;
      if (uVar21 != 0) {
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *(undefined2 *)pbVar14 = uVar2;
            *(undefined2 *)(pbVar14 + 2) = uVar2;
            *(undefined2 *)(pbVar14 + 4) = uVar2;
            *(undefined2 *)(pbVar14 + 6) = uVar2;
            *(undefined2 *)(pbVar14 + 8) = uVar2;
            *(undefined2 *)(pbVar14 + 10) = uVar2;
            *(undefined2 *)(pbVar14 + 0xc) = uVar2;
            *(undefined2 *)(pbVar14 + 0xe) = uVar2;
            pbVar14 = pbVar14 + 0x10;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar3 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *(undefined2 *)pbVar14 = uVar2;
            pbVar14 = pbVar14 + 2;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      uVar9 = uVar6 + 7 >> 3;
      if (uVar6 != 0) {
        uVar22 = uVar6 + 7 >> 5;
        puVar8 = puVar15;
        if (uVar22 != 0) {
          do {
            *(undefined2 *)pbVar14 = *puVar8;
            *(undefined2 *)(pbVar14 + 2) = puVar8[1];
            *(undefined2 *)(pbVar14 + 4) = puVar8[2];
            *(undefined2 *)(pbVar14 + 6) = puVar8[3];
            *(undefined2 *)(pbVar14 + 8) = puVar8[0x10];
            *(undefined2 *)(pbVar14 + 10) = puVar8[0x11];
            *(undefined2 *)(pbVar14 + 0xc) = puVar8[0x12];
            *(undefined2 *)(pbVar14 + 0xe) = puVar8[0x13];
            *(undefined2 *)(pbVar14 + 0x10) = puVar8[0x20];
            *(undefined2 *)(pbVar14 + 0x12) = puVar8[0x21];
            *(undefined2 *)(pbVar14 + 0x14) = puVar8[0x22];
            *(undefined2 *)(pbVar14 + 0x16) = puVar8[0x23];
            *(undefined2 *)(pbVar14 + 0x18) = puVar8[0x30];
            *(undefined2 *)(pbVar14 + 0x1a) = puVar8[0x31];
            *(undefined2 *)(pbVar14 + 0x1c) = puVar8[0x32];
            *(undefined2 *)(pbVar14 + 0x1e) = puVar8[0x33];
            pbVar14 = pbVar14 + 0x20;
            puVar8 = puVar8 + 0x40;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 3;
          if (uVar9 == 0) goto LAB_8006add0;
        }
        do {
          *(undefined2 *)pbVar14 = *puVar8;
          *(undefined2 *)(pbVar14 + 2) = puVar8[1];
          *(undefined2 *)(pbVar14 + 4) = puVar8[2];
          *(undefined2 *)(pbVar14 + 6) = puVar8[3];
          pbVar14 = pbVar14 + 8;
          uVar9 = uVar9 - 1;
          puVar8 = puVar8 + 0x10;
        } while (uVar9 != 0);
      }
LAB_8006add0:
      uVar9 = 0;
      if (uVar21 != 0) {
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *(undefined2 *)pbVar14 = uVar2;
            *(undefined2 *)(pbVar14 + 2) = uVar2;
            *(undefined2 *)(pbVar14 + 4) = uVar2;
            *(undefined2 *)(pbVar14 + 6) = uVar2;
            *(undefined2 *)(pbVar14 + 8) = uVar2;
            *(undefined2 *)(pbVar14 + 10) = uVar2;
            *(undefined2 *)(pbVar14 + 0xc) = uVar2;
            *(undefined2 *)(pbVar14 + 0xe) = uVar2;
            pbVar14 = pbVar14 + 0x10;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar3 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *(undefined2 *)pbVar14 = uVar2;
            pbVar14 = pbVar14 + 2;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      uVar9 = 0;
      iVar3 = 0;
      if (0 < (int)param_3) {
        if (8 < (int)param_3) {
          pbVar14 = local_b8;
          uVar22 = param_3 - 1 >> 3;
          if (0 < (int)(param_3 - 8)) {
            do {
              uVar9 = uVar9 + *pbVar14 + (uint)pbVar14[1] + (uint)pbVar14[2] + (uint)pbVar14[3] +
                      (uint)pbVar14[4] + (uint)pbVar14[5] + (uint)pbVar14[6] + (uint)pbVar14[7];
              pbVar14 = pbVar14 + 8;
              iVar3 = iVar3 + 8;
              uVar22 = uVar22 - 1;
            } while (uVar22 != 0);
          }
        }
        pbVar14 = local_b8 + iVar3;
        iVar4 = param_3 - iVar3;
        if (iVar3 < (int)param_3) {
          do {
            uVar9 = uVar9 + *pbVar14;
            pbVar14 = pbVar14 + 1;
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
      iVar3 = 0;
      if (0 < (int)uVar6) {
        if (8 < (int)uVar6) {
          pbVar10 = local_b8;
          uVar22 = uVar6 - 1 >> 3;
          pbVar14 = pbVar20;
          puVar1 = &stack0xfffffec0;
          if (0 < (int)(uVar6 - 8)) {
            do {
              puVar1[8] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *pbVar10) + (uint)*pbVar14;
              puVar1[9] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[1]) + (uint)pbVar14[1];
              puVar1[10] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[2]) + (uint)pbVar14[2];
              puVar1[0xb] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[3]) + (uint)pbVar14[3];
              puVar1[0xc] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[4]) + (uint)pbVar14[4];
              puVar1[0xd] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[5]) + (uint)pbVar14[5];
              puVar1[0xe] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[6]) + (uint)pbVar14[6];
              puVar1[0xf] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar10[7]) + (uint)pbVar14[7];
              pbVar10 = pbVar10 + 8;
              pbVar14 = pbVar14 + 8;
              iVar3 = iVar3 + 8;
              uVar22 = uVar22 - 1;
              puVar1 = puVar1 + 8;
            } while (uVar22 != 0);
          }
        }
        pbVar14 = local_138 + iVar3;
        pbVar10 = local_b8 + iVar3;
        pbVar19 = pbVar20 + iVar3;
        iVar4 = uVar6 - iVar3;
        if (iVar3 < (int)uVar6) {
          do {
            *pbVar14 = (byte)(uVar9 / param_3);
            uVar9 = (uVar9 - *pbVar10) + (uint)*pbVar19;
            pbVar14 = pbVar14 + 1;
            pbVar10 = pbVar10 + 1;
            pbVar19 = pbVar19 + 1;
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
      pbVar14 = local_138;
      uVar9 = uVar6 + 7 >> 3;
      if (uVar6 != 0) {
        uVar22 = uVar6 + 7 >> 5;
        if (uVar22 != 0) {
          do {
            *puVar15 = *(undefined2 *)pbVar14;
            puVar15[1] = *(undefined2 *)(pbVar14 + 2);
            puVar15[2] = *(undefined2 *)(pbVar14 + 4);
            puVar15[3] = *(undefined2 *)(pbVar14 + 6);
            puVar15[0x10] = *(undefined2 *)(pbVar14 + 8);
            puVar15[0x11] = *(undefined2 *)(pbVar14 + 10);
            puVar15[0x12] = *(undefined2 *)(pbVar14 + 0xc);
            puVar15[0x13] = *(undefined2 *)(pbVar14 + 0xe);
            puVar15[0x20] = *(undefined2 *)(pbVar14 + 0x10);
            puVar15[0x21] = *(undefined2 *)(pbVar14 + 0x12);
            puVar15[0x22] = *(undefined2 *)(pbVar14 + 0x14);
            puVar15[0x23] = *(undefined2 *)(pbVar14 + 0x16);
            puVar15[0x30] = *(undefined2 *)(pbVar14 + 0x18);
            puVar15[0x31] = *(undefined2 *)(pbVar14 + 0x1a);
            puVar15[0x32] = *(undefined2 *)(pbVar14 + 0x1c);
            puVar15[0x33] = *(undefined2 *)(pbVar14 + 0x1e);
            pbVar14 = pbVar14 + 0x20;
            puVar15 = puVar15 + 0x40;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 3;
          if (uVar9 == 0) goto LAB_8006b158;
        }
        do {
          *puVar15 = *(undefined2 *)pbVar14;
          puVar15[1] = *(undefined2 *)(pbVar14 + 2);
          puVar15[2] = *(undefined2 *)(pbVar14 + 4);
          puVar15[3] = *(undefined2 *)(pbVar14 + 6);
          pbVar14 = pbVar14 + 8;
          puVar15 = puVar15 + 0x10;
          uVar9 = uVar9 - 1;
        } while (uVar9 != 0);
      }
LAB_8006b158:
    }
    iVar3 = ((int)uVar6 >> 3) * 0x20;
    pbVar14 = local_b8 + uVar6 + iVar7;
    for (uVar16 = 0; uVar16 < uVar6; uVar16 = uVar16 + 1) {
      pbVar19 = (byte *)(uVar5 + (uVar16 & 7) + (uVar16 >> 3) * 0x20);
      pbVar10 = local_b8;
      uVar9 = 0;
      if (uVar21 != 0) {
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *(undefined2 *)pbVar10 = uVar2;
            *(undefined2 *)(pbVar10 + 2) = uVar2;
            *(undefined2 *)(pbVar10 + 4) = uVar2;
            *(undefined2 *)(pbVar10 + 6) = uVar2;
            *(undefined2 *)(pbVar10 + 8) = uVar2;
            *(undefined2 *)(pbVar10 + 10) = uVar2;
            *(undefined2 *)(pbVar10 + 0xc) = uVar2;
            *(undefined2 *)(pbVar10 + 0xe) = uVar2;
            pbVar10 = pbVar10 + 0x10;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar4 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *(undefined2 *)pbVar10 = uVar2;
            pbVar10 = pbVar10 + 2;
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
      uVar9 = uVar6 + 3 >> 2;
      if (uVar6 != 0) {
        uVar22 = uVar6 + 3 >> 4;
        pbVar10 = pbVar19;
        pbVar13 = local_b8 + iVar7;
        if (uVar22 != 0) {
          do {
            *pbVar13 = *pbVar10;
            pbVar13[1] = pbVar10[8];
            pbVar13[2] = pbVar10[0x10];
            pbVar13[3] = pbVar10[0x18];
            pbVar10 = pbVar10 + iVar3;
            pbVar13[4] = *pbVar10;
            pbVar13[5] = pbVar10[8];
            pbVar13[6] = pbVar10[0x10];
            pbVar13[7] = pbVar10[0x18];
            pbVar10 = pbVar10 + iVar3;
            pbVar13[8] = *pbVar10;
            pbVar13[9] = pbVar10[8];
            pbVar13[10] = pbVar10[0x10];
            pbVar13[0xb] = pbVar10[0x18];
            pbVar10 = pbVar10 + iVar3;
            pbVar13[0xc] = *pbVar10;
            pbVar13[0xd] = pbVar10[8];
            pbVar13[0xe] = pbVar10[0x10];
            pbVar13[0xf] = pbVar10[0x18];
            pbVar13 = pbVar13 + 0x10;
            pbVar10 = pbVar10 + iVar3;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 3;
          if (uVar9 == 0) goto LAB_8006b310;
        }
        do {
          *pbVar13 = *pbVar10;
          pbVar13[1] = pbVar10[8];
          pbVar13[2] = pbVar10[0x10];
          pbVar13[3] = pbVar10[0x18];
          uVar9 = uVar9 - 1;
          pbVar10 = pbVar10 + iVar3;
          pbVar13 = pbVar13 + 4;
        } while (uVar9 != 0);
      }
LAB_8006b310:
      uVar9 = 0;
      if (uVar21 != 0) {
        pbVar10 = pbVar14;
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *(undefined2 *)pbVar10 = uVar2;
            *(undefined2 *)(pbVar10 + 2) = uVar2;
            *(undefined2 *)(pbVar10 + 4) = uVar2;
            *(undefined2 *)(pbVar10 + 6) = uVar2;
            *(undefined2 *)(pbVar10 + 8) = uVar2;
            *(undefined2 *)(pbVar10 + 10) = uVar2;
            *(undefined2 *)(pbVar10 + 0xc) = uVar2;
            *(undefined2 *)(pbVar10 + 0xe) = uVar2;
            pbVar10 = pbVar10 + 0x10;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar4 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *(undefined2 *)pbVar10 = uVar2;
            pbVar10 = pbVar10 + 2;
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
      uVar9 = 0;
      iVar4 = 0;
      if (0 < (int)param_3) {
        if (8 < (int)param_3) {
          pbVar10 = local_b8;
          uVar22 = param_3 - 1 >> 3;
          if (0 < (int)(param_3 - 8)) {
            do {
              uVar9 = uVar9 + *pbVar10 + (uint)pbVar10[1] + (uint)pbVar10[2] + (uint)pbVar10[3] +
                      (uint)pbVar10[4] + (uint)pbVar10[5] + (uint)pbVar10[6] + (uint)pbVar10[7];
              pbVar10 = pbVar10 + 8;
              iVar4 = iVar4 + 8;
              uVar22 = uVar22 - 1;
            } while (uVar22 != 0);
          }
        }
        pbVar10 = local_b8 + iVar4;
        iVar11 = param_3 - iVar4;
        if (iVar4 < (int)param_3) {
          do {
            uVar9 = uVar9 + *pbVar10;
            pbVar10 = pbVar10 + 1;
            iVar11 = iVar11 + -1;
          } while (iVar11 != 0);
        }
      }
      iVar4 = 0;
      if (0 < (int)uVar6) {
        if (8 < (int)uVar6) {
          pbVar13 = local_b8;
          uVar22 = uVar6 - 1 >> 3;
          pbVar10 = pbVar20;
          puVar1 = &stack0xfffffec0;
          if (0 < (int)(uVar6 - 8)) {
            do {
              puVar1[8] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *pbVar13) + (uint)*pbVar10;
              puVar1[9] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[1]) + (uint)pbVar10[1];
              puVar1[10] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[2]) + (uint)pbVar10[2];
              puVar1[0xb] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[3]) + (uint)pbVar10[3];
              puVar1[0xc] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[4]) + (uint)pbVar10[4];
              puVar1[0xd] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[5]) + (uint)pbVar10[5];
              puVar1[0xe] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[6]) + (uint)pbVar10[6];
              puVar1[0xf] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - pbVar13[7]) + (uint)pbVar10[7];
              pbVar13 = pbVar13 + 8;
              pbVar10 = pbVar10 + 8;
              iVar4 = iVar4 + 8;
              uVar22 = uVar22 - 1;
              puVar1 = puVar1 + 8;
            } while (uVar22 != 0);
          }
        }
        pbVar10 = local_138 + iVar4;
        pbVar13 = local_b8 + iVar4;
        pbVar18 = pbVar20 + iVar4;
        iVar11 = uVar6 - iVar4;
        if (iVar4 < (int)uVar6) {
          do {
            *pbVar10 = (byte)(uVar9 / param_3);
            uVar9 = (uVar9 - *pbVar13) + (uint)*pbVar18;
            pbVar10 = pbVar10 + 1;
            pbVar13 = pbVar13 + 1;
            pbVar18 = pbVar18 + 1;
            iVar11 = iVar11 + -1;
          } while (iVar11 != 0);
        }
      }
      pbVar10 = local_138;
      uVar9 = uVar6 + 3 >> 2;
      if (uVar6 != 0) {
        uVar22 = uVar6 + 3 >> 4;
        if (uVar22 != 0) {
          do {
            *pbVar19 = *pbVar10;
            pbVar19[8] = pbVar10[1];
            pbVar19[0x10] = pbVar10[2];
            pbVar19[0x18] = pbVar10[3];
            pbVar19 = pbVar19 + iVar3;
            *pbVar19 = pbVar10[4];
            pbVar19[8] = pbVar10[5];
            pbVar19[0x10] = pbVar10[6];
            pbVar19[0x18] = pbVar10[7];
            pbVar19 = pbVar19 + iVar3;
            *pbVar19 = pbVar10[8];
            pbVar19[8] = pbVar10[9];
            pbVar19[0x10] = pbVar10[10];
            pbVar19[0x18] = pbVar10[0xb];
            pbVar19 = pbVar19 + iVar3;
            *pbVar19 = pbVar10[0xc];
            pbVar19[8] = pbVar10[0xd];
            pbVar19[0x10] = pbVar10[0xe];
            pbVar19[0x18] = pbVar10[0xf];
            pbVar10 = pbVar10 + 0x10;
            pbVar19 = pbVar19 + iVar3;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 3;
          if (uVar9 == 0) goto LAB_8006b6a8;
        }
        do {
          *pbVar19 = *pbVar10;
          pbVar19[8] = pbVar10[1];
          pbVar19[0x10] = pbVar10[2];
          pbVar19[0x18] = pbVar10[3];
          pbVar10 = pbVar10 + 4;
          pbVar19 = pbVar19 + iVar3;
          uVar9 = uVar9 - 1;
        } while (uVar9 != 0);
      }
LAB_8006b6a8:
    }
  }
  FUN_802420e0(uVar5,uVar6 * uVar6);
  FUN_80286880();
  return;
}

