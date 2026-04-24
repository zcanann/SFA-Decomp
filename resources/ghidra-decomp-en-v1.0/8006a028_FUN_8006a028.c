// Function: FUN_8006a028
// Entry: 8006a028
// Size: 5424 bytes

void FUN_8006a028(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined4 *puVar7;
  undefined2 *puVar8;
  uint uVar9;
  undefined *puVar10;
  int iVar11;
  undefined4 *puVar12;
  undefined *puVar13;
  byte *pbVar14;
  undefined2 *puVar15;
  uint uVar16;
  undefined4 *puVar17;
  byte *pbVar18;
  undefined *puVar19;
  byte *pbVar20;
  uint uVar21;
  uint uVar22;
  undefined8 uVar23;
  undefined4 local_138;
  undefined2 local_134;
  undefined2 uStack306;
  undefined2 local_130;
  undefined2 uStack302;
  undefined2 local_12c;
  undefined2 uStack298;
  undefined2 local_128 [56];
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8 [42];
  
  uVar23 = FUN_802860d0();
  uVar5 = (uint)uVar23;
  iVar4 = (int)((ulonglong)uVar23 >> 0x20) + 0x60;
  uVar16 = (int)param_3 >> 0x1f;
  iVar6 = (int)param_3 >> 1;
  if ((uVar16 * 8 | param_3 * 0x20000000 + uVar16 >> 0x1d) == uVar16) {
    uVar21 = (int)param_3 >> 3;
    pbVar20 = (byte *)((int)&local_b8 + param_3);
    for (uVar16 = 0; uVar16 < uVar5; uVar16 = uVar16 + 1) {
      puVar17 = (undefined4 *)(iVar4 + (uVar16 & 3) * 8 + uVar5 * (uVar16 & 0xfffffffc));
      puVar7 = &local_b8;
      uVar9 = 0;
      if (uVar21 != 0) {
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *puVar7 = param_4;
            puVar7[1] = param_4;
            puVar7[2] = param_4;
            puVar7[3] = param_4;
            puVar7[4] = param_4;
            puVar7[5] = param_4;
            puVar7[6] = param_4;
            puVar7[7] = param_4;
            puVar7 = puVar7 + 8;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar2 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *puVar7 = param_4;
            puVar7 = puVar7 + 1;
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
        }
      }
      uVar9 = uVar5 + 7 >> 3;
      if (uVar5 != 0) {
        uVar22 = uVar5 + 7 >> 6;
        puVar12 = puVar17;
        if (uVar22 != 0) {
          do {
            *puVar7 = *puVar12;
            puVar7[1] = puVar12[1];
            puVar7[2] = puVar12[8];
            puVar7[3] = puVar12[9];
            puVar7[4] = puVar12[0x10];
            puVar7[5] = puVar12[0x11];
            puVar7[6] = puVar12[0x18];
            puVar7[7] = puVar12[0x19];
            puVar7[8] = puVar12[0x20];
            puVar7[9] = puVar12[0x21];
            puVar7[10] = puVar12[0x28];
            puVar7[0xb] = puVar12[0x29];
            puVar7[0xc] = puVar12[0x30];
            puVar7[0xd] = puVar12[0x31];
            puVar7[0xe] = puVar12[0x38];
            puVar7[0xf] = puVar12[0x39];
            puVar7 = puVar7 + 0x10;
            puVar12 = puVar12 + 0x40;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 7;
          if (uVar9 == 0) goto LAB_8006a1e0;
        }
        do {
          *puVar7 = *puVar12;
          puVar7[1] = puVar12[1];
          puVar7 = puVar7 + 2;
          uVar9 = uVar9 - 1;
          puVar12 = puVar12 + 8;
        } while (uVar9 != 0);
      }
LAB_8006a1e0:
      uVar9 = 0;
      if (uVar21 != 0) {
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *puVar7 = param_4;
            puVar7[1] = param_4;
            puVar7[2] = param_4;
            puVar7[3] = param_4;
            puVar7[4] = param_4;
            puVar7[5] = param_4;
            puVar7[6] = param_4;
            puVar7[7] = param_4;
            puVar7 = puVar7 + 8;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar2 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *puVar7 = param_4;
            puVar7 = puVar7 + 1;
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
        }
      }
      uVar9 = 0;
      iVar2 = 0;
      if (0 < (int)param_3) {
        if (8 < (int)param_3) {
          puVar7 = &local_b8;
          uVar22 = param_3 - 1 >> 3;
          if (0 < (int)(param_3 - 8)) {
            do {
              uVar9 = uVar9 + *(byte *)puVar7 + (uint)*(byte *)((int)puVar7 + 1) +
                      (uint)*(byte *)((int)puVar7 + 2) + (uint)*(byte *)((int)puVar7 + 3) +
                      (uint)*(byte *)(puVar7 + 1) + (uint)*(byte *)((int)puVar7 + 5) +
                      (uint)*(byte *)((int)puVar7 + 6) + (uint)*(byte *)((int)puVar7 + 7);
              puVar7 = puVar7 + 2;
              iVar2 = iVar2 + 8;
              uVar22 = uVar22 - 1;
            } while (uVar22 != 0);
          }
        }
        pbVar14 = (byte *)((int)&local_b8 + iVar2);
        iVar3 = param_3 - iVar2;
        if (iVar2 < (int)param_3) {
          do {
            uVar9 = uVar9 + *pbVar14;
            pbVar14 = pbVar14 + 1;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      iVar2 = 0;
      if (0 < (int)uVar5) {
        if (8 < (int)uVar5) {
          puVar7 = &local_b8;
          uVar22 = uVar5 - 1 >> 3;
          pbVar14 = pbVar20;
          puVar19 = &stack0xfffffec0;
          if (0 < (int)(uVar5 - 8)) {
            do {
              puVar19[8] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)puVar7) + (uint)*pbVar14;
              puVar19[9] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 1)) + (uint)pbVar14[1];
              puVar19[10] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 2)) + (uint)pbVar14[2];
              puVar19[0xb] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 3)) + (uint)pbVar14[3];
              puVar19[0xc] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)(puVar7 + 1)) + (uint)pbVar14[4];
              puVar19[0xd] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 5)) + (uint)pbVar14[5];
              puVar19[0xe] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 6)) + (uint)pbVar14[6];
              puVar19[0xf] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 7)) + (uint)pbVar14[7];
              puVar7 = puVar7 + 2;
              pbVar14 = pbVar14 + 8;
              iVar2 = iVar2 + 8;
              uVar22 = uVar22 - 1;
              puVar19 = puVar19 + 8;
            } while (uVar22 != 0);
          }
        }
        puVar19 = (undefined *)((int)&local_138 + iVar2);
        pbVar14 = (byte *)((int)&local_b8 + iVar2);
        pbVar18 = pbVar20 + iVar2;
        iVar3 = uVar5 - iVar2;
        if (iVar2 < (int)uVar5) {
          do {
            *puVar19 = (char)(uVar9 / param_3);
            uVar9 = (uVar9 - *pbVar14) + (uint)*pbVar18;
            puVar19 = puVar19 + 1;
            pbVar14 = pbVar14 + 1;
            pbVar18 = pbVar18 + 1;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      puVar7 = &local_138;
      uVar9 = uVar5 + 7 >> 3;
      if (uVar5 != 0) {
        uVar22 = uVar5 + 7 >> 6;
        if (uVar22 != 0) {
          do {
            *puVar17 = *puVar7;
            puVar17[1] = puVar7[1];
            puVar17[8] = puVar7[2];
            puVar17[9] = puVar7[3];
            puVar17[0x10] = puVar7[4];
            puVar17[0x11] = puVar7[5];
            puVar17[0x18] = puVar7[6];
            puVar17[0x19] = puVar7[7];
            puVar17[0x20] = puVar7[8];
            puVar17[0x21] = puVar7[9];
            puVar17[0x28] = puVar7[10];
            puVar17[0x29] = puVar7[0xb];
            puVar17[0x30] = puVar7[0xc];
            puVar17[0x31] = puVar7[0xd];
            puVar17[0x38] = puVar7[0xe];
            puVar17[0x39] = puVar7[0xf];
            puVar7 = puVar7 + 0x10;
            puVar17 = puVar17 + 0x40;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 7;
          if (uVar9 == 0) goto LAB_8006a55c;
        }
        do {
          *puVar17 = *puVar7;
          puVar17[1] = puVar7[1];
          puVar7 = puVar7 + 2;
          puVar17 = puVar17 + 8;
          uVar9 = uVar9 - 1;
        } while (uVar9 != 0);
      }
LAB_8006a55c:
    }
    iVar2 = ((int)uVar5 >> 3) * 0x20;
    puVar7 = (undefined4 *)((int)&local_b8 + uVar5 + iVar6);
    for (uVar16 = 0; uVar16 < uVar5; uVar16 = uVar16 + 1) {
      puVar19 = (undefined *)(iVar4 + (uVar16 & 7) + (uVar16 >> 3) * 0x20);
      puVar17 = &local_b8;
      uVar9 = 0;
      if (uVar21 != 0) {
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *puVar17 = param_4;
            puVar17[1] = param_4;
            puVar17[2] = param_4;
            puVar17[3] = param_4;
            puVar17[4] = param_4;
            puVar17[5] = param_4;
            puVar17[6] = param_4;
            puVar17[7] = param_4;
            puVar17 = puVar17 + 8;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar3 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *puVar17 = param_4;
            puVar17 = puVar17 + 1;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      uVar9 = uVar5 + 3 >> 2;
      if (uVar5 != 0) {
        uVar22 = uVar5 + 3 >> 4;
        puVar10 = puVar19;
        puVar13 = (undefined *)((int)&local_b8 + iVar6);
        if (uVar22 != 0) {
          do {
            *puVar13 = *puVar10;
            puVar13[1] = puVar10[8];
            puVar13[2] = puVar10[0x10];
            puVar13[3] = puVar10[0x18];
            puVar10 = puVar10 + iVar2;
            puVar13[4] = *puVar10;
            puVar13[5] = puVar10[8];
            puVar13[6] = puVar10[0x10];
            puVar13[7] = puVar10[0x18];
            puVar10 = puVar10 + iVar2;
            puVar13[8] = *puVar10;
            puVar13[9] = puVar10[8];
            puVar13[10] = puVar10[0x10];
            puVar13[0xb] = puVar10[0x18];
            puVar10 = puVar10 + iVar2;
            puVar13[0xc] = *puVar10;
            puVar13[0xd] = puVar10[8];
            puVar13[0xe] = puVar10[0x10];
            puVar13[0xf] = puVar10[0x18];
            puVar13 = puVar13 + 0x10;
            puVar10 = puVar10 + iVar2;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 3;
          if (uVar9 == 0) goto LAB_8006a714;
        }
        do {
          *puVar13 = *puVar10;
          puVar13[1] = puVar10[8];
          puVar13[2] = puVar10[0x10];
          puVar13[3] = puVar10[0x18];
          uVar9 = uVar9 - 1;
          puVar10 = puVar10 + iVar2;
          puVar13 = puVar13 + 4;
        } while (uVar9 != 0);
      }
LAB_8006a714:
      uVar9 = 0;
      if (uVar21 != 0) {
        puVar17 = puVar7;
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *puVar17 = param_4;
            puVar17[1] = param_4;
            puVar17[2] = param_4;
            puVar17[3] = param_4;
            puVar17[4] = param_4;
            puVar17[5] = param_4;
            puVar17[6] = param_4;
            puVar17[7] = param_4;
            puVar17 = puVar17 + 8;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar3 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *puVar17 = param_4;
            puVar17 = puVar17 + 1;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      uVar9 = 0;
      iVar3 = 0;
      if (0 < (int)param_3) {
        if (8 < (int)param_3) {
          puVar17 = &local_b8;
          uVar22 = param_3 - 1 >> 3;
          if (0 < (int)(param_3 - 8)) {
            do {
              uVar9 = uVar9 + *(byte *)puVar17 + (uint)*(byte *)((int)puVar17 + 1) +
                      (uint)*(byte *)((int)puVar17 + 2) + (uint)*(byte *)((int)puVar17 + 3) +
                      (uint)*(byte *)(puVar17 + 1) + (uint)*(byte *)((int)puVar17 + 5) +
                      (uint)*(byte *)((int)puVar17 + 6) + (uint)*(byte *)((int)puVar17 + 7);
              puVar17 = puVar17 + 2;
              iVar3 = iVar3 + 8;
              uVar22 = uVar22 - 1;
            } while (uVar22 != 0);
          }
        }
        pbVar14 = (byte *)((int)&local_b8 + iVar3);
        iVar11 = param_3 - iVar3;
        if (iVar3 < (int)param_3) {
          do {
            uVar9 = uVar9 + *pbVar14;
            pbVar14 = pbVar14 + 1;
            iVar11 = iVar11 + -1;
          } while (iVar11 != 0);
        }
      }
      iVar3 = 0;
      if (0 < (int)uVar5) {
        if (8 < (int)uVar5) {
          puVar17 = &local_b8;
          uVar22 = uVar5 - 1 >> 3;
          pbVar14 = pbVar20;
          puVar10 = &stack0xfffffec0;
          if (0 < (int)(uVar5 - 8)) {
            do {
              puVar10[8] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)puVar17) + (uint)*pbVar14;
              puVar10[9] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar17 + 1)) + (uint)pbVar14[1];
              puVar10[10] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar17 + 2)) + (uint)pbVar14[2];
              puVar10[0xb] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar17 + 3)) + (uint)pbVar14[3];
              puVar10[0xc] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)(puVar17 + 1)) + (uint)pbVar14[4];
              puVar10[0xd] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar17 + 5)) + (uint)pbVar14[5];
              puVar10[0xe] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar17 + 6)) + (uint)pbVar14[6];
              puVar10[0xf] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar17 + 7)) + (uint)pbVar14[7];
              puVar17 = puVar17 + 2;
              pbVar14 = pbVar14 + 8;
              iVar3 = iVar3 + 8;
              uVar22 = uVar22 - 1;
              puVar10 = puVar10 + 8;
            } while (uVar22 != 0);
          }
        }
        puVar10 = (undefined *)((int)&local_138 + iVar3);
        pbVar14 = (byte *)((int)&local_b8 + iVar3);
        pbVar18 = pbVar20 + iVar3;
        iVar11 = uVar5 - iVar3;
        if (iVar3 < (int)uVar5) {
          do {
            *puVar10 = (char)(uVar9 / param_3);
            uVar9 = (uVar9 - *pbVar14) + (uint)*pbVar18;
            puVar10 = puVar10 + 1;
            pbVar14 = pbVar14 + 1;
            pbVar18 = pbVar18 + 1;
            iVar11 = iVar11 + -1;
          } while (iVar11 != 0);
        }
      }
      puVar17 = &local_138;
      uVar9 = uVar5 + 3 >> 2;
      if (uVar5 != 0) {
        uVar22 = uVar5 + 3 >> 4;
        if (uVar22 != 0) {
          do {
            *puVar19 = *(undefined *)puVar17;
            puVar19[8] = *(undefined *)((int)puVar17 + 1);
            puVar19[0x10] = *(undefined *)((int)puVar17 + 2);
            puVar19[0x18] = *(undefined *)((int)puVar17 + 3);
            puVar19 = puVar19 + iVar2;
            *puVar19 = *(undefined *)(puVar17 + 1);
            puVar19[8] = *(undefined *)((int)puVar17 + 5);
            puVar19[0x10] = *(undefined *)((int)puVar17 + 6);
            puVar19[0x18] = *(undefined *)((int)puVar17 + 7);
            puVar19 = puVar19 + iVar2;
            *puVar19 = *(undefined *)(puVar17 + 2);
            puVar19[8] = *(undefined *)((int)puVar17 + 9);
            puVar19[0x10] = *(undefined *)((int)puVar17 + 10);
            puVar19[0x18] = *(undefined *)((int)puVar17 + 0xb);
            puVar19 = puVar19 + iVar2;
            *puVar19 = *(undefined *)(puVar17 + 3);
            puVar19[8] = *(undefined *)((int)puVar17 + 0xd);
            puVar19[0x10] = *(undefined *)((int)puVar17 + 0xe);
            puVar19[0x18] = *(undefined *)((int)puVar17 + 0xf);
            puVar17 = puVar17 + 4;
            puVar19 = puVar19 + iVar2;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 3;
          if (uVar9 == 0) goto LAB_8006aaac;
        }
        do {
          *puVar19 = *(undefined *)puVar17;
          puVar19[8] = *(undefined *)((int)puVar17 + 1);
          puVar19[0x10] = *(undefined *)((int)puVar17 + 2);
          puVar19[0x18] = *(undefined *)((int)puVar17 + 3);
          puVar17 = puVar17 + 1;
          puVar19 = puVar19 + iVar2;
          uVar9 = uVar9 - 1;
        } while (uVar9 != 0);
      }
LAB_8006aaac:
    }
  }
  else {
    uVar21 = (int)param_3 >> 2;
    uVar1 = (undefined2)param_4;
    pbVar20 = (byte *)((int)&local_b8 + param_3);
    for (uVar16 = 0; uVar16 < uVar5; uVar16 = uVar16 + 1) {
      puVar15 = (undefined2 *)(iVar4 + (uVar16 & 3) * 8 + uVar5 * (uVar16 & 0xfffffffc));
      puVar7 = &local_b8;
      uVar9 = 0;
      if (uVar21 != 0) {
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *(undefined2 *)puVar7 = uVar1;
            *(undefined2 *)((int)puVar7 + 2) = uVar1;
            *(undefined2 *)(puVar7 + 1) = uVar1;
            *(undefined2 *)((int)puVar7 + 6) = uVar1;
            *(undefined2 *)(puVar7 + 2) = uVar1;
            *(undefined2 *)((int)puVar7 + 10) = uVar1;
            *(undefined2 *)(puVar7 + 3) = uVar1;
            *(undefined2 *)((int)puVar7 + 0xe) = uVar1;
            puVar7 = puVar7 + 4;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar2 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *(undefined2 *)puVar7 = uVar1;
            puVar7 = (undefined4 *)((int)puVar7 + 2);
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
        }
      }
      uVar9 = uVar5 + 7 >> 3;
      if (uVar5 != 0) {
        uVar22 = uVar5 + 7 >> 5;
        puVar8 = puVar15;
        if (uVar22 != 0) {
          do {
            *(undefined2 *)puVar7 = *puVar8;
            *(undefined2 *)((int)puVar7 + 2) = puVar8[1];
            *(undefined2 *)(puVar7 + 1) = puVar8[2];
            *(undefined2 *)((int)puVar7 + 6) = puVar8[3];
            *(undefined2 *)(puVar7 + 2) = puVar8[0x10];
            *(undefined2 *)((int)puVar7 + 10) = puVar8[0x11];
            *(undefined2 *)(puVar7 + 3) = puVar8[0x12];
            *(undefined2 *)((int)puVar7 + 0xe) = puVar8[0x13];
            *(undefined2 *)(puVar7 + 4) = puVar8[0x20];
            *(undefined2 *)((int)puVar7 + 0x12) = puVar8[0x21];
            *(undefined2 *)(puVar7 + 5) = puVar8[0x22];
            *(undefined2 *)((int)puVar7 + 0x16) = puVar8[0x23];
            *(undefined2 *)(puVar7 + 6) = puVar8[0x30];
            *(undefined2 *)((int)puVar7 + 0x1a) = puVar8[0x31];
            *(undefined2 *)(puVar7 + 7) = puVar8[0x32];
            *(undefined2 *)((int)puVar7 + 0x1e) = puVar8[0x33];
            puVar7 = puVar7 + 8;
            puVar8 = puVar8 + 0x40;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 3;
          if (uVar9 == 0) goto LAB_8006ac54;
        }
        do {
          *(undefined2 *)puVar7 = *puVar8;
          *(undefined2 *)((int)puVar7 + 2) = puVar8[1];
          *(undefined2 *)(puVar7 + 1) = puVar8[2];
          *(undefined2 *)((int)puVar7 + 6) = puVar8[3];
          puVar7 = puVar7 + 2;
          uVar9 = uVar9 - 1;
          puVar8 = puVar8 + 0x10;
        } while (uVar9 != 0);
      }
LAB_8006ac54:
      uVar9 = 0;
      if (uVar21 != 0) {
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *(undefined2 *)puVar7 = uVar1;
            *(undefined2 *)((int)puVar7 + 2) = uVar1;
            *(undefined2 *)(puVar7 + 1) = uVar1;
            *(undefined2 *)((int)puVar7 + 6) = uVar1;
            *(undefined2 *)(puVar7 + 2) = uVar1;
            *(undefined2 *)((int)puVar7 + 10) = uVar1;
            *(undefined2 *)(puVar7 + 3) = uVar1;
            *(undefined2 *)((int)puVar7 + 0xe) = uVar1;
            puVar7 = puVar7 + 4;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar2 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *(undefined2 *)puVar7 = uVar1;
            puVar7 = (undefined4 *)((int)puVar7 + 2);
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
        }
      }
      uVar9 = 0;
      iVar2 = 0;
      if (0 < (int)param_3) {
        if (8 < (int)param_3) {
          puVar7 = &local_b8;
          uVar22 = param_3 - 1 >> 3;
          if (0 < (int)(param_3 - 8)) {
            do {
              uVar9 = uVar9 + *(byte *)puVar7 + (uint)*(byte *)((int)puVar7 + 1) +
                      (uint)*(byte *)((int)puVar7 + 2) + (uint)*(byte *)((int)puVar7 + 3) +
                      (uint)*(byte *)(puVar7 + 1) + (uint)*(byte *)((int)puVar7 + 5) +
                      (uint)*(byte *)((int)puVar7 + 6) + (uint)*(byte *)((int)puVar7 + 7);
              puVar7 = puVar7 + 2;
              iVar2 = iVar2 + 8;
              uVar22 = uVar22 - 1;
            } while (uVar22 != 0);
          }
        }
        pbVar14 = (byte *)((int)&local_b8 + iVar2);
        iVar3 = param_3 - iVar2;
        if (iVar2 < (int)param_3) {
          do {
            uVar9 = uVar9 + *pbVar14;
            pbVar14 = pbVar14 + 1;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      iVar2 = 0;
      if (0 < (int)uVar5) {
        if (8 < (int)uVar5) {
          puVar7 = &local_b8;
          uVar22 = uVar5 - 1 >> 3;
          pbVar14 = pbVar20;
          puVar19 = &stack0xfffffec0;
          if (0 < (int)(uVar5 - 8)) {
            do {
              puVar19[8] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)puVar7) + (uint)*pbVar14;
              puVar19[9] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 1)) + (uint)pbVar14[1];
              puVar19[10] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 2)) + (uint)pbVar14[2];
              puVar19[0xb] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 3)) + (uint)pbVar14[3];
              puVar19[0xc] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)(puVar7 + 1)) + (uint)pbVar14[4];
              puVar19[0xd] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 5)) + (uint)pbVar14[5];
              puVar19[0xe] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 6)) + (uint)pbVar14[6];
              puVar19[0xf] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 7)) + (uint)pbVar14[7];
              puVar7 = puVar7 + 2;
              pbVar14 = pbVar14 + 8;
              iVar2 = iVar2 + 8;
              uVar22 = uVar22 - 1;
              puVar19 = puVar19 + 8;
            } while (uVar22 != 0);
          }
        }
        puVar19 = (undefined *)((int)&local_138 + iVar2);
        pbVar14 = (byte *)((int)&local_b8 + iVar2);
        pbVar18 = pbVar20 + iVar2;
        iVar3 = uVar5 - iVar2;
        if (iVar2 < (int)uVar5) {
          do {
            *puVar19 = (char)(uVar9 / param_3);
            uVar9 = (uVar9 - *pbVar14) + (uint)*pbVar18;
            puVar19 = puVar19 + 1;
            pbVar14 = pbVar14 + 1;
            pbVar18 = pbVar18 + 1;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      puVar7 = &local_138;
      uVar9 = uVar5 + 7 >> 3;
      if (uVar5 != 0) {
        uVar22 = uVar5 + 7 >> 5;
        if (uVar22 != 0) {
          do {
            *puVar15 = *(undefined2 *)puVar7;
            puVar15[1] = *(undefined2 *)((int)puVar7 + 2);
            puVar15[2] = *(undefined2 *)(puVar7 + 1);
            puVar15[3] = *(undefined2 *)((int)puVar7 + 6);
            puVar15[0x10] = *(undefined2 *)(puVar7 + 2);
            puVar15[0x11] = *(undefined2 *)((int)puVar7 + 10);
            puVar15[0x12] = *(undefined2 *)(puVar7 + 3);
            puVar15[0x13] = *(undefined2 *)((int)puVar7 + 0xe);
            puVar15[0x20] = *(undefined2 *)(puVar7 + 4);
            puVar15[0x21] = *(undefined2 *)((int)puVar7 + 0x12);
            puVar15[0x22] = *(undefined2 *)(puVar7 + 5);
            puVar15[0x23] = *(undefined2 *)((int)puVar7 + 0x16);
            puVar15[0x30] = *(undefined2 *)(puVar7 + 6);
            puVar15[0x31] = *(undefined2 *)((int)puVar7 + 0x1a);
            puVar15[0x32] = *(undefined2 *)(puVar7 + 7);
            puVar15[0x33] = *(undefined2 *)((int)puVar7 + 0x1e);
            puVar7 = puVar7 + 8;
            puVar15 = puVar15 + 0x40;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 3;
          if (uVar9 == 0) goto LAB_8006afdc;
        }
        do {
          *puVar15 = *(undefined2 *)puVar7;
          puVar15[1] = *(undefined2 *)((int)puVar7 + 2);
          puVar15[2] = *(undefined2 *)(puVar7 + 1);
          puVar15[3] = *(undefined2 *)((int)puVar7 + 6);
          puVar7 = puVar7 + 2;
          puVar15 = puVar15 + 0x10;
          uVar9 = uVar9 - 1;
        } while (uVar9 != 0);
      }
LAB_8006afdc:
    }
    iVar2 = ((int)uVar5 >> 3) * 0x20;
    puVar15 = (undefined2 *)((int)&local_b8 + uVar5 + iVar6);
    for (uVar16 = 0; uVar16 < uVar5; uVar16 = uVar16 + 1) {
      puVar19 = (undefined *)(iVar4 + (uVar16 & 7) + (uVar16 >> 3) * 0x20);
      puVar7 = &local_b8;
      uVar9 = 0;
      if (uVar21 != 0) {
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *(undefined2 *)puVar7 = uVar1;
            *(undefined2 *)((int)puVar7 + 2) = uVar1;
            *(undefined2 *)(puVar7 + 1) = uVar1;
            *(undefined2 *)((int)puVar7 + 6) = uVar1;
            *(undefined2 *)(puVar7 + 2) = uVar1;
            *(undefined2 *)((int)puVar7 + 10) = uVar1;
            *(undefined2 *)(puVar7 + 3) = uVar1;
            *(undefined2 *)((int)puVar7 + 0xe) = uVar1;
            puVar7 = puVar7 + 4;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar3 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *(undefined2 *)puVar7 = uVar1;
            puVar7 = (undefined4 *)((int)puVar7 + 2);
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      uVar9 = uVar5 + 3 >> 2;
      if (uVar5 != 0) {
        uVar22 = uVar5 + 3 >> 4;
        puVar10 = puVar19;
        puVar13 = (undefined *)((int)&local_b8 + iVar6);
        if (uVar22 != 0) {
          do {
            *puVar13 = *puVar10;
            puVar13[1] = puVar10[8];
            puVar13[2] = puVar10[0x10];
            puVar13[3] = puVar10[0x18];
            puVar10 = puVar10 + iVar2;
            puVar13[4] = *puVar10;
            puVar13[5] = puVar10[8];
            puVar13[6] = puVar10[0x10];
            puVar13[7] = puVar10[0x18];
            puVar10 = puVar10 + iVar2;
            puVar13[8] = *puVar10;
            puVar13[9] = puVar10[8];
            puVar13[10] = puVar10[0x10];
            puVar13[0xb] = puVar10[0x18];
            puVar10 = puVar10 + iVar2;
            puVar13[0xc] = *puVar10;
            puVar13[0xd] = puVar10[8];
            puVar13[0xe] = puVar10[0x10];
            puVar13[0xf] = puVar10[0x18];
            puVar13 = puVar13 + 0x10;
            puVar10 = puVar10 + iVar2;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 3;
          if (uVar9 == 0) goto LAB_8006b194;
        }
        do {
          *puVar13 = *puVar10;
          puVar13[1] = puVar10[8];
          puVar13[2] = puVar10[0x10];
          puVar13[3] = puVar10[0x18];
          uVar9 = uVar9 - 1;
          puVar10 = puVar10 + iVar2;
          puVar13 = puVar13 + 4;
        } while (uVar9 != 0);
      }
LAB_8006b194:
      uVar9 = 0;
      if (uVar21 != 0) {
        puVar8 = puVar15;
        if ((8 < uVar21) && (uVar22 = uVar21 - 1 >> 3, uVar21 != 8)) {
          do {
            *puVar8 = uVar1;
            puVar8[1] = uVar1;
            puVar8[2] = uVar1;
            puVar8[3] = uVar1;
            puVar8[4] = uVar1;
            puVar8[5] = uVar1;
            puVar8[6] = uVar1;
            puVar8[7] = uVar1;
            puVar8 = puVar8 + 8;
            uVar9 = uVar9 + 8;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
        }
        iVar3 = uVar21 - uVar9;
        if (uVar9 < uVar21) {
          do {
            *puVar8 = uVar1;
            puVar8 = puVar8 + 1;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
      }
      uVar9 = 0;
      iVar3 = 0;
      if (0 < (int)param_3) {
        if (8 < (int)param_3) {
          puVar7 = &local_b8;
          uVar22 = param_3 - 1 >> 3;
          if (0 < (int)(param_3 - 8)) {
            do {
              uVar9 = uVar9 + *(byte *)puVar7 + (uint)*(byte *)((int)puVar7 + 1) +
                      (uint)*(byte *)((int)puVar7 + 2) + (uint)*(byte *)((int)puVar7 + 3) +
                      (uint)*(byte *)(puVar7 + 1) + (uint)*(byte *)((int)puVar7 + 5) +
                      (uint)*(byte *)((int)puVar7 + 6) + (uint)*(byte *)((int)puVar7 + 7);
              puVar7 = puVar7 + 2;
              iVar3 = iVar3 + 8;
              uVar22 = uVar22 - 1;
            } while (uVar22 != 0);
          }
        }
        pbVar14 = (byte *)((int)&local_b8 + iVar3);
        iVar11 = param_3 - iVar3;
        if (iVar3 < (int)param_3) {
          do {
            uVar9 = uVar9 + *pbVar14;
            pbVar14 = pbVar14 + 1;
            iVar11 = iVar11 + -1;
          } while (iVar11 != 0);
        }
      }
      iVar3 = 0;
      if (0 < (int)uVar5) {
        if (8 < (int)uVar5) {
          puVar7 = &local_b8;
          uVar22 = uVar5 - 1 >> 3;
          pbVar14 = pbVar20;
          puVar10 = &stack0xfffffec0;
          if (0 < (int)(uVar5 - 8)) {
            do {
              puVar10[8] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)puVar7) + (uint)*pbVar14;
              puVar10[9] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 1)) + (uint)pbVar14[1];
              puVar10[10] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 2)) + (uint)pbVar14[2];
              puVar10[0xb] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 3)) + (uint)pbVar14[3];
              puVar10[0xc] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)(puVar7 + 1)) + (uint)pbVar14[4];
              puVar10[0xd] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 5)) + (uint)pbVar14[5];
              puVar10[0xe] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 6)) + (uint)pbVar14[6];
              puVar10[0xf] = (char)(uVar9 / param_3);
              uVar9 = (uVar9 - *(byte *)((int)puVar7 + 7)) + (uint)pbVar14[7];
              puVar7 = puVar7 + 2;
              pbVar14 = pbVar14 + 8;
              iVar3 = iVar3 + 8;
              uVar22 = uVar22 - 1;
              puVar10 = puVar10 + 8;
            } while (uVar22 != 0);
          }
        }
        puVar10 = (undefined *)((int)&local_138 + iVar3);
        pbVar14 = (byte *)((int)&local_b8 + iVar3);
        pbVar18 = pbVar20 + iVar3;
        iVar11 = uVar5 - iVar3;
        if (iVar3 < (int)uVar5) {
          do {
            *puVar10 = (char)(uVar9 / param_3);
            uVar9 = (uVar9 - *pbVar14) + (uint)*pbVar18;
            puVar10 = puVar10 + 1;
            pbVar14 = pbVar14 + 1;
            pbVar18 = pbVar18 + 1;
            iVar11 = iVar11 + -1;
          } while (iVar11 != 0);
        }
      }
      puVar7 = &local_138;
      uVar9 = uVar5 + 3 >> 2;
      if (uVar5 != 0) {
        uVar22 = uVar5 + 3 >> 4;
        if (uVar22 != 0) {
          do {
            *puVar19 = *(undefined *)puVar7;
            puVar19[8] = *(undefined *)((int)puVar7 + 1);
            puVar19[0x10] = *(undefined *)((int)puVar7 + 2);
            puVar19[0x18] = *(undefined *)((int)puVar7 + 3);
            puVar19 = puVar19 + iVar2;
            *puVar19 = *(undefined *)(puVar7 + 1);
            puVar19[8] = *(undefined *)((int)puVar7 + 5);
            puVar19[0x10] = *(undefined *)((int)puVar7 + 6);
            puVar19[0x18] = *(undefined *)((int)puVar7 + 7);
            puVar19 = puVar19 + iVar2;
            *puVar19 = *(undefined *)(puVar7 + 2);
            puVar19[8] = *(undefined *)((int)puVar7 + 9);
            puVar19[0x10] = *(undefined *)((int)puVar7 + 10);
            puVar19[0x18] = *(undefined *)((int)puVar7 + 0xb);
            puVar19 = puVar19 + iVar2;
            *puVar19 = *(undefined *)(puVar7 + 3);
            puVar19[8] = *(undefined *)((int)puVar7 + 0xd);
            puVar19[0x10] = *(undefined *)((int)puVar7 + 0xe);
            puVar19[0x18] = *(undefined *)((int)puVar7 + 0xf);
            puVar7 = puVar7 + 4;
            puVar19 = puVar19 + iVar2;
            uVar22 = uVar22 - 1;
          } while (uVar22 != 0);
          uVar9 = uVar9 & 3;
          if (uVar9 == 0) goto LAB_8006b52c;
        }
        do {
          *puVar19 = *(undefined *)puVar7;
          puVar19[8] = *(undefined *)((int)puVar7 + 1);
          puVar19[0x10] = *(undefined *)((int)puVar7 + 2);
          puVar19[0x18] = *(undefined *)((int)puVar7 + 3);
          puVar7 = puVar7 + 1;
          puVar19 = puVar19 + iVar2;
          uVar9 = uVar9 - 1;
        } while (uVar9 != 0);
      }
LAB_8006b52c:
    }
  }
  FUN_802419e8(iVar4,uVar5 * uVar5);
  FUN_8028611c();
  return;
}

