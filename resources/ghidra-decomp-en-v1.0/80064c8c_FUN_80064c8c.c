// Function: FUN_80064c8c
// Entry: 80064c8c
// Size: 2280 bytes

/* WARNING: Removing unreachable block (ram,0x80065548) */
/* WARNING: Removing unreachable block (ram,0x80065530) */
/* WARNING: Removing unreachable block (ram,0x80065518) */
/* WARNING: Removing unreachable block (ram,0x80064ce8) */
/* WARNING: Removing unreachable block (ram,0x80064cdc) */
/* WARNING: Removing unreachable block (ram,0x80064cd0) */
/* WARNING: Removing unreachable block (ram,0x80064cc4) */
/* WARNING: Removing unreachable block (ram,0x80064cb8) */
/* WARNING: Removing unreachable block (ram,0x80064cac) */
/* WARNING: Removing unreachable block (ram,0x80064ca0) */
/* WARNING: Removing unreachable block (ram,0x8006550c) */
/* WARNING: Removing unreachable block (ram,0x80065524) */
/* WARNING: Removing unreachable block (ram,0x8006553c) */
/* WARNING: Removing unreachable block (ram,0x80065554) */

void FUN_80064c8c(void)

{
  short sVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  bool bVar6;
  int iVar7;
  int iVar8;
  undefined2 uVar9;
  short *psVar10;
  undefined *puVar11;
  ushort uVar12;
  ushort uVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  int iVar19;
  undefined *puVar20;
  char *pcVar21;
  int iVar22;
  undefined4 uVar23;
  undefined8 in_f25;
  double dVar24;
  undefined8 in_f26;
  double dVar25;
  undefined8 in_f27;
  double dVar26;
  undefined8 in_f28;
  double dVar27;
  undefined8 in_f29;
  double dVar28;
  undefined8 in_f30;
  double dVar29;
  undefined8 in_f31;
  double dVar30;
  short local_1be8 [70];
  short local_1b5c [2];
  short asStack7000 [3400];
  undefined4 local_c8;
  uint uStack196;
  undefined4 local_c0;
  uint uStack188;
  undefined4 local_b8;
  uint uStack180;
  undefined4 uStack104;
  undefined4 uStack100;
  undefined4 uStack88;
  undefined4 uStack84;
  undefined4 uStack72;
  undefined4 uStack68;
  undefined4 uStack56;
  undefined4 uStack52;
  undefined4 uStack40;
  undefined4 uStack36;
  undefined4 uStack24;
  undefined4 uStack20;
  undefined4 uStack8;
  undefined4 uStack4;
  
  uVar23 = 0;
  uStack4 = (undefined4)in_f31;
  uStack8 = (undefined4)((ulonglong)in_f31 >> 0x20);
  uStack20 = (undefined4)in_f30;
  uStack24 = (undefined4)((ulonglong)in_f30 >> 0x20);
  uStack36 = (undefined4)in_f29;
  uStack40 = (undefined4)((ulonglong)in_f29 >> 0x20);
  uStack52 = (undefined4)in_f28;
  uStack56 = (undefined4)((ulonglong)in_f28 >> 0x20);
  uStack68 = (undefined4)in_f27;
  uStack72 = (undefined4)((ulonglong)in_f27 >> 0x20);
  uStack84 = (undefined4)in_f26;
  uStack88 = (undefined4)((ulonglong)in_f26 >> 0x20);
  uStack100 = (undefined4)in_f25;
  uStack104 = (undefined4)((ulonglong)in_f25 >> 0x20);
  FUN_802860b0();
  DAT_803dcf44 = 0;
  if ((DAT_803dcf4d != '\0') && (iVar7 = FUN_8002073c(), iVar7 == 0)) {
    DAT_803dcf4d = DAT_803dcf4d + -1;
  }
  uVar9 = (undefined2)((uint)uVar23 >> 0x10);
  if (DAT_803dcf4e == '\x01') {
    DAT_803dcf4f = '\x01';
    DAT_803dcf4e = '\0';
  }
  else if (DAT_803dcf4f != '\0') {
    DAT_803dcf4f = '\0';
    iVar7 = FUN_8002073c();
    if (iVar7 != 0) {
      DAT_803dcf4d = '\x02';
    }
    iVar7 = 0;
    psVar10 = local_1be8;
    iVar22 = 2;
    do {
      *psVar10 = 0;
      psVar10[1] = 0;
      psVar10[2] = 0;
      psVar10[3] = 0;
      psVar10[4] = 0;
      psVar10[5] = 0;
      psVar10[6] = 0;
      psVar10[7] = 0;
      psVar10[8] = 0;
      psVar10[9] = 0;
      psVar10[10] = 0;
      psVar10[0xb] = 0;
      psVar10[0xc] = 0;
      psVar10[0xd] = 0;
      psVar10[0xe] = 0;
      psVar10[0xf] = 0;
      psVar10[0x10] = 0;
      psVar10[0x11] = 0;
      psVar10[0x12] = 0;
      psVar10[0x13] = 0;
      psVar10[0x14] = 0;
      psVar10[0x15] = 0;
      psVar10[0x16] = 0;
      psVar10[0x17] = 0;
      psVar10[0x18] = 0;
      psVar10[0x19] = 0;
      psVar10[0x1a] = 0;
      psVar10[0x1b] = 0;
      psVar10[0x1c] = 0;
      psVar10[0x1d] = 0;
      psVar10[0x1e] = 0;
      psVar10[0x1f] = 0;
      psVar10 = psVar10 + 0x20;
      iVar7 = iVar7 + 0x20;
      iVar22 = iVar22 + -1;
    } while (iVar22 != 0);
    psVar10 = local_1be8 + iVar7;
    iVar22 = 0x47 - iVar7;
    if (iVar7 < 0x47) {
      do {
        *psVar10 = 0;
        psVar10 = psVar10 + 1;
        iVar22 = iVar22 + -1;
      } while (iVar22 != 0);
    }
    DAT_803dcf5e = 0;
    DAT_803dcf5c = 0;
    iVar7 = 0;
    dVar29 = (double)FLOAT_803dece0;
    dVar30 = DOUBLE_803decd8;
    do {
      iVar22 = FUN_8005af18(iVar7);
      uVar14 = 0;
      iVar18 = 0;
      do {
        uVar15 = 0;
        uStack196 = uVar14 ^ 0x80000000;
        local_c8 = 0x43300000;
        dVar28 = (double)(float)(dVar29 * (double)(float)((double)CONCAT44(0x43300000,uStack196) -
                                                         dVar30));
        pcVar21 = (char *)(iVar22 + iVar18);
        do {
          if (-1 < *pcVar21) {
            iVar8 = FUN_8005aeec();
            iVar19 = 0;
            uStack196 = uVar15 ^ 0x80000000;
            local_c8 = 0x43300000;
            dVar26 = (double)(FLOAT_803dece0 *
                             (float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803decd8));
            for (iVar17 = 0; iVar17 < (int)(uint)*(ushort *)(iVar8 + 0x9c); iVar17 = iVar17 + 1) {
              if (DAT_803dcf5e < 0x5dc) {
                psVar10 = (short *)(*(int *)(iVar8 + 0x70) + iVar19);
                puVar11 = (undefined *)(DAT_803dcf34 + DAT_803dcf5e * 0x10);
                *puVar11 = *(undefined *)(psVar10 + 6);
                puVar11[1] = *(undefined *)((int)psVar10 + 0xd);
                puVar11[3] = *(undefined *)((int)psVar10 + 0xf);
                if ((puVar11[3] & 0x3f) == 0x11) {
                  puVar11[3] = puVar11[3] & 0xc0;
                  puVar11[3] = puVar11[3] | 2;
                }
                puVar11[2] = *(undefined *)(psVar10 + 7);
                puVar11[2] = puVar11[2] ^ 0x10;
                *(short *)(puVar11 + 0xc) = psVar10[8];
                dVar25 = (double)(float)(dVar26 + (double)FLOAT_803dcdd8);
                dVar24 = (double)(float)(dVar28 + (double)FLOAT_803dcddc);
                iVar16 = 0;
                puVar20 = puVar11;
                dVar27 = DOUBLE_803decd8;
                do {
                  uStack196 = (int)*psVar10 ^ 0x80000000;
                  local_c8 = 0x43300000;
                  uStack188 = (int)psVar10[2] ^ 0x80000000;
                  local_c0 = 0x43300000;
                  uStack180 = (int)psVar10[4] ^ 0x80000000;
                  local_b8 = 0x43300000;
                  if (DAT_803dcf5c < 0x6a4) {
                    uVar9 = FUN_80063ff0((double)(float)(dVar25 + (double)(float)((double)CONCAT44(
                                                  0x43300000,uStack196) - dVar27)),
                                         (double)(float)((double)CONCAT44(0x43300000,uStack188) -
                                                        dVar27),
                                         (double)(float)((double)(float)((double)CONCAT44(0x43300000
                                                                                          ,uStack180
                                                                                         ) - dVar27)
                                                        + dVar24),(int)DAT_803dcf5e,asStack7000);
                    *(undefined2 *)(puVar20 + 4) = uVar9;
                  }
                  psVar10 = psVar10 + 1;
                  puVar20 = puVar20 + 2;
                  iVar16 = iVar16 + 1;
                } while (iVar16 < 2);
                local_1be8[(int)(char)puVar11[3] & 0x3fU] =
                     local_1be8[(int)(char)puVar11[3] & 0x3fU] + 1;
                DAT_803dcf5e = DAT_803dcf5e + 1;
              }
              iVar19 = iVar19 + 0x14;
            }
          }
          pcVar21 = pcVar21 + 1;
          uVar15 = uVar15 + 1;
        } while ((int)uVar15 < 0x10);
        iVar18 = iVar18 + 0x10;
        uVar14 = uVar14 + 1;
      } while ((int)uVar14 < 0x10);
      iVar7 = iVar7 + 1;
    } while (iVar7 < 5);
    iVar7 = 0;
    for (iVar22 = 0; iVar22 < DAT_803dcf5e; iVar22 = iVar22 + 1) {
      iVar18 = DAT_803dcf34 + iVar7;
      sVar1 = asStack7000[*(short *)(iVar18 + 4) * 2];
      if ((sVar1 < 0) || (sVar1 == iVar22)) {
        sVar1 = asStack7000[*(short *)(iVar18 + 4) * 2 + 1];
        if ((sVar1 < 0) || (sVar1 == iVar22)) {
          *(undefined2 *)(iVar18 + 8) = 0xffff;
        }
        else {
          *(short *)(iVar18 + 8) = sVar1;
        }
      }
      else {
        *(short *)(iVar18 + 8) = sVar1;
      }
      sVar1 = asStack7000[*(short *)(iVar18 + 6) * 2];
      if ((sVar1 < 0) || (sVar1 == iVar22)) {
        sVar1 = asStack7000[*(short *)(iVar18 + 6) * 2 + 1];
        if ((sVar1 < 0) || (sVar1 == iVar22)) {
          *(undefined2 *)(iVar18 + 10) = 0xffff;
        }
        else {
          *(short *)(iVar18 + 10) = sVar1;
        }
      }
      else {
        *(short *)(iVar18 + 10) = sVar1;
      }
      iVar7 = iVar7 + 0x10;
    }
    if (DAT_803dcf40 != 0) {
      iVar7 = 0;
      for (iVar22 = 0; iVar22 < DAT_803dcf5e; iVar22 = iVar22 + 1) {
        *(short *)(DAT_803dcf40 + iVar7) = (short)iVar22;
        iVar7 = iVar7 + 2;
      }
      bVar6 = false;
      while (!bVar6) {
        bVar6 = true;
        iVar7 = 0;
        for (iVar22 = 0; iVar22 < DAT_803dcf5e + -1; iVar22 = iVar22 + 1) {
          psVar10 = (short *)(DAT_803dcf40 + iVar7);
          sVar1 = *psVar10;
          if ((*(byte *)(DAT_803dcf34 + sVar1 * 0x10 + 3) & 0x3f) <
              (*(byte *)(DAT_803dcf34 + psVar10[1] * 0x10 + 3) & 0x3f)) {
            *psVar10 = psVar10[1];
            *(short *)(DAT_803dcf40 + iVar7 + 2) = sVar1;
            bVar6 = false;
          }
          iVar7 = iVar7 + 2;
        }
      }
    }
    psVar10 = local_1b5c;
    iVar7 = 7;
    do {
      psVar10[-1] = psVar10[-1] + *psVar10;
      psVar10[-2] = psVar10[-2] + psVar10[-1];
      psVar10[-3] = psVar10[-3] + psVar10[-2];
      psVar10[-4] = psVar10[-4] + psVar10[-3];
      psVar10[-5] = psVar10[-5] + psVar10[-4];
      psVar10[-6] = psVar10[-6] + psVar10[-5];
      psVar10[-7] = psVar10[-7] + psVar10[-6];
      psVar10[-8] = psVar10[-8] + psVar10[-7];
      psVar10[-9] = psVar10[-9] + psVar10[-8];
      psVar10[-10] = psVar10[-10] + psVar10[-9];
      psVar10 = psVar10 + -10;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    iVar7 = 0;
    for (iVar22 = 0; iVar18 = (int)DAT_803dcf5e, iVar22 < iVar18; iVar22 = iVar22 + 1) {
      iVar18 = ((int)*(char *)(DAT_803dcf34 + iVar7 + 3) & 0x3fU) + 1;
      sVar1 = local_1be8[iVar18];
      local_1be8[iVar18] = sVar1 + 1;
      *(short *)(DAT_803dcf3c + sVar1 * 2) = (short)iVar22;
      iVar7 = iVar7 + 0x10;
    }
    iVar22 = 0;
    iVar7 = iVar18 + -1;
    if (0 < iVar7) {
      if ((8 < iVar7) && (uVar14 = iVar18 - 2U >> 3, 0 < iVar18 + -9)) {
        do {
          iVar22 = iVar22 + 8;
          uVar14 = uVar14 - 1;
        } while (uVar14 != 0);
      }
      iVar18 = iVar7 - iVar22;
      if (iVar22 < iVar7) {
        do {
          iVar18 = iVar18 + -1;
        } while (iVar18 != 0);
      }
    }
    DAT_8038d840 = 0xffff;
    DAT_8038d842 = 0xffff;
    DAT_8038d844 = 0xffff;
    DAT_8038d846 = 0xffff;
    DAT_8038d848 = 0xffff;
    DAT_8038d84a = 0xffff;
    DAT_8038d84c = 0xffff;
    DAT_8038d84e = 0xffff;
    DAT_8038d850 = 0xffff;
    DAT_8038d852 = 0xffff;
    DAT_8038d854 = 0xffff;
    DAT_8038d856 = 0xffff;
    DAT_8038d858 = 0xffff;
    DAT_8038d85a = 0xffff;
    DAT_8038d85c = 0xffff;
    DAT_8038d85e = 0xffff;
    DAT_8038d860 = 0xffff;
    DAT_8038d862 = 0xffff;
    DAT_8038d864 = 0xffff;
    DAT_8038d866 = 0xffff;
    DAT_8038d868 = 0xffff;
    DAT_8038d86a = 0xffff;
    DAT_8038d86c = 0xffff;
    DAT_8038d86e = 0xffff;
    DAT_8038d870 = 0xffff;
    DAT_8038d872 = 0xffff;
    DAT_8038d874 = 0xffff;
    DAT_8038d876 = 0xffff;
    DAT_8038d878 = 0xffff;
    DAT_8038d87a = 0xffff;
    DAT_8038d87c = 0xffff;
    DAT_8038d87e = 0xffff;
    DAT_8038d880 = 0xffff;
    DAT_8038d882 = 0xffff;
    DAT_8038d884 = 0xffff;
    DAT_8038d886 = 0xffff;
    DAT_8038d888 = 0xffff;
    DAT_8038d88a = 0xffff;
    DAT_8038d88c = 0xffff;
    DAT_8038d88e = 0xffff;
    uVar12 = 0xffff;
    iVar7 = 0;
    for (iVar22 = 0; uVar9 = (undefined2)((uint)uVar23 >> 0x10), iVar22 < DAT_803dcf5e;
        iVar22 = iVar22 + 1) {
      uVar13 = (short)*(char *)(DAT_803dcf34 + *(short *)(DAT_803dcf3c + iVar7) * 0x10 + 3) & 0x3f;
      if (0x13 < uVar13) {
        uVar13 = 1;
        FUN_801378a8(s_trackIntersect__FUNC_OVERFLOW__d_8030e87c,1);
      }
      iVar18 = (int)(short)uVar12;
      if (iVar18 != (short)uVar13) {
        (&DAT_8038d840)[(short)uVar13 * 2] = (short)iVar22;
        uVar12 = uVar13;
        if (iVar18 != -1) {
          (&DAT_8038d842)[iVar18 * 2] = (short)iVar22;
        }
      }
      iVar7 = iVar7 + 2;
    }
    if ((short)uVar12 != -1) {
      (&DAT_8038d842)[(short)uVar12 * 2] = DAT_803dcf5e;
    }
    DAT_803dcf44 = 1;
  }
  bVar2 = (byte)uVar9;
  bVar3 = bVar2 & 7;
  bVar4 = (byte)((ushort)uVar9 >> 8);
  bVar5 = bVar4 & 0x3f;
  if (bVar3 == 4 || bVar3 == 6) {
    dequantize(&uStack8,bVar3,bVar5);
    dequantize((int)&uStack8 + 1,bVar3,bVar5);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    dequantize(&uStack8,bVar3,bVar5);
    dequantize((int)&uStack8 + 2,bVar3,bVar5);
  }
  bVar3 = bVar2 & 7;
  bVar5 = bVar4 & 0x3f;
  if (bVar3 == 4 || bVar3 == 6) {
    dequantize(&uStack24,bVar3,bVar5);
    dequantize((int)&uStack24 + 1,bVar3,bVar5);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    dequantize(&uStack24,bVar3,bVar5);
    dequantize((int)&uStack24 + 2,bVar3,bVar5);
  }
  bVar3 = bVar2 & 7;
  bVar5 = bVar4 & 0x3f;
  if (bVar3 == 4 || bVar3 == 6) {
    dequantize(&uStack40,bVar3,bVar5);
    dequantize((int)&uStack40 + 1,bVar3,bVar5);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    dequantize(&uStack40,bVar3,bVar5);
    dequantize((int)&uStack40 + 2,bVar3,bVar5);
  }
  bVar3 = bVar2 & 7;
  bVar5 = bVar4 & 0x3f;
  if (bVar3 == 4 || bVar3 == 6) {
    dequantize(&uStack56,bVar3,bVar5);
    dequantize((int)&uStack56 + 1,bVar3,bVar5);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    dequantize(&uStack56,bVar3,bVar5);
    dequantize((int)&uStack56 + 2,bVar3,bVar5);
  }
  bVar3 = bVar2 & 7;
  bVar5 = bVar4 & 0x3f;
  if (bVar3 == 4 || bVar3 == 6) {
    dequantize(&uStack72,bVar3,bVar5);
    dequantize((int)&uStack72 + 1,bVar3,bVar5);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    dequantize(&uStack72,bVar3,bVar5);
    dequantize((int)&uStack72 + 2,bVar3,bVar5);
  }
  bVar3 = bVar2 & 7;
  bVar5 = bVar4 & 0x3f;
  if (bVar3 == 4 || bVar3 == 6) {
    dequantize(&uStack88,bVar3,bVar5);
    dequantize((int)&uStack88 + 1,bVar3,bVar5);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    dequantize(&uStack88,bVar3,bVar5);
    dequantize((int)&uStack88 + 2,bVar3,bVar5);
  }
  bVar2 = bVar2 & 7;
  bVar4 = bVar4 & 0x3f;
  if (bVar2 == 4 || bVar2 == 6) {
    dequantize(&uStack104,bVar2,bVar4);
    dequantize((int)&uStack104 + 1,bVar2,bVar4);
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    dequantize(&uStack104,bVar2,bVar4);
    dequantize((int)&uStack104 + 2,bVar2,bVar4);
  }
  FUN_802860fc();
  return;
}

