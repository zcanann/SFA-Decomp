// Function: FUN_8002fa48
// Entry: 8002fa48
// Size: 2236 bytes

void FUN_8002fa48(undefined8 param_1,double param_2)

{
  double dVar1;
  char cVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  uint uVar15;
  uint uVar16;
  undefined uVar17;
  int iVar18;
  float *pfVar19;
  int iVar20;
  int *piVar21;
  int iVar22;
  int iVar23;
  int iVar24;
  int iVar25;
  undefined4 uVar26;
  float *pfVar27;
  short *psVar28;
  byte bVar29;
  int iVar30;
  double dVar31;
  double extraout_f1;
  undefined8 uVar32;
  double local_48;
  double local_38;
  double local_30;
  double local_20;
  
  uVar32 = FUN_802860dc();
  iVar18 = (int)((ulonglong)uVar32 >> 0x20);
  pfVar19 = (float *)uVar32;
  uVar26 = 0;
  dVar31 = (double)FLOAT_803de90c;
  if ((dVar31 <= extraout_f1) && (dVar31 = extraout_f1, (double)FLOAT_803de8e0 < extraout_f1)) {
    dVar31 = (double)FLOAT_803de8e0;
  }
  piVar21 = *(int **)(*(int *)(iVar18 + 0x7c) + *(char *)(iVar18 + 0xad) * 4);
  if (*(short *)(*piVar21 + 0xec) == 0) {
    uVar26 = 0;
  }
  else {
    iVar23 = piVar21[0xb];
    if (iVar23 == 0) {
      uVar26 = 0;
    }
    else {
      *(float *)(iVar23 + 0xc) = (float)(dVar31 * (double)*(float *)(iVar23 + 0x14));
      if (*(short *)(iVar23 + 0x58) != 0) {
        if ((*(byte *)(iVar23 + 99) & 8) != 0) {
          *(undefined4 *)(iVar23 + 0x10) = *(undefined4 *)(iVar23 + 0xc);
        }
        *(float *)(iVar23 + 8) =
             (float)((double)*(float *)(iVar23 + 0x10) * param_2 + (double)*(float *)(iVar23 + 8));
        fVar4 = FLOAT_803de8f0;
        fVar3 = *(float *)(iVar23 + 0x18);
        if (*(char *)(iVar23 + 0x61) == '\0') {
          fVar4 = *(float *)(iVar23 + 8);
          fVar5 = FLOAT_803de8f0;
          if ((FLOAT_803de8f0 <= fVar4) && (fVar5 = fVar4, fVar3 < fVar4)) {
            fVar5 = fVar3;
          }
          *(float *)(iVar23 + 8) = fVar5;
        }
        else {
          if (*(float *)(iVar23 + 8) < FLOAT_803de8f0) {
            while (*(float *)(iVar23 + 8) < fVar4) {
              *(float *)(iVar23 + 8) = *(float *)(iVar23 + 8) + fVar3;
            }
          }
          if (fVar3 <= *(float *)(iVar23 + 8)) {
            while (fVar3 <= *(float *)(iVar23 + 8)) {
              *(float *)(iVar23 + 8) = *(float *)(iVar23 + 8) - fVar3;
            }
          }
        }
        if ((*(byte *)(iVar23 + 99) & 2) == 0) {
          uVar15 = (uint)-(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (uint)*(ushort *)(iVar23 + 0x5e))
                                                 - DOUBLE_803de8e8) * param_2 -
                                 (double)(float)((double)CONCAT44(0x43300000,
                                                                  *(ushort *)(iVar23 + 0x58) ^
                                                                  0x80000000) - DOUBLE_803de900));
          fVar3 = FLOAT_803de8f0;
          if ((-1 < (int)uVar15) &&
             (uVar15 = uVar15 ^ 0x80000000, fVar3 = FLOAT_803de8f4,
             (float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803de900) <= FLOAT_803de8f4)) {
            local_38 = (double)CONCAT44(0x43300000,uVar15);
            fVar3 = (float)(local_38 - DOUBLE_803de900);
          }
          *(short *)(iVar23 + 0x58) = (short)(int)fVar3;
        }
        if (*(short *)(iVar23 + 0x58) == 0) {
          *(undefined2 *)(iVar23 + 0x5c) = 0;
        }
      }
      fVar4 = *(float *)(iVar18 + 0x98);
      fVar3 = (float)(dVar31 * param_2);
      *(float *)(iVar18 + 0x98) = fVar4 + fVar3;
      fVar6 = FLOAT_803de8f0;
      fVar5 = FLOAT_803de8e0;
      if (*(float *)(iVar18 + 0x98) < FLOAT_803de8e0) {
        if (*(float *)(iVar18 + 0x98) < FLOAT_803de8f0) {
          if (*(char *)(iVar23 + 0x60) == '\0') {
            *(float *)(iVar18 + 0x98) = FLOAT_803de8f0;
          }
          else {
            while (*(float *)(iVar18 + 0x98) < fVar6) {
              *(float *)(iVar18 + 0x98) = *(float *)(iVar18 + 0x98) + fVar5;
            }
          }
          uVar26 = 1;
        }
      }
      else {
        if (*(char *)(iVar23 + 0x60) == '\0') {
          *(float *)(iVar18 + 0x98) = FLOAT_803de8e0;
        }
        else {
          while (fVar5 <= *(float *)(iVar18 + 0x98)) {
            *(float *)(iVar18 + 0x98) = *(float *)(iVar18 + 0x98) - fVar5;
          }
        }
        uVar26 = 1;
      }
      if (pfVar19 != (float *)0x0) {
        *(undefined *)((int)pfVar19 + 0x12) = 0;
        fVar5 = FLOAT_803de8f0;
        pfVar19[2] = FLOAT_803de8f0;
        pfVar19[1] = fVar5;
        *pfVar19 = fVar5;
        if (*(int *)(iVar18 + 0x60) != 0) {
          *(undefined *)((int)pfVar19 + 0x1b) = 0;
          iVar22 = **(int **)(iVar18 + 0x60) >> 1;
          if (iVar22 != 0) {
            iVar30 = (int)(FLOAT_803de8f8 * fVar4);
            iVar25 = (int)(FLOAT_803de8f8 * *(float *)(iVar18 + 0x98));
            bVar29 = iVar25 < iVar30;
            if (fVar3 < FLOAT_803de8f0) {
              bVar29 = bVar29 | 2;
            }
            iVar24 = 0;
            iVar20 = 0;
            while ((iVar24 < iVar22 && (*(char *)((int)pfVar19 + 0x1b) < '\b'))) {
              uVar16 = (uint)*(short *)(*(int *)(*(int *)(iVar18 + 0x60) + 4) + iVar20);
              uVar15 = uVar16 & 0x1ff;
              uVar16 = uVar16 >> 9 & 0x7f;
              if (uVar16 != 0x7f) {
                uVar17 = (undefined)uVar16;
                if (((bVar29 == 0) && (iVar30 <= (int)uVar15)) && ((int)uVar15 < iVar25)) {
                  cVar2 = *(char *)((int)pfVar19 + 0x1b);
                  *(char *)((int)pfVar19 + 0x1b) = cVar2 + '\x01';
                  *(undefined *)((int)pfVar19 + cVar2 + 0x13) = uVar17;
                }
                if ((bVar29 == 1) && ((iVar30 <= (int)uVar15 || ((int)uVar15 < iVar25)))) {
                  cVar2 = *(char *)((int)pfVar19 + 0x1b);
                  *(char *)((int)pfVar19 + 0x1b) = cVar2 + '\x01';
                  *(undefined *)((int)pfVar19 + cVar2 + 0x13) = uVar17;
                }
                if (((bVar29 == 3) && (iVar25 < (int)uVar15)) && ((int)uVar15 <= iVar30)) {
                  cVar2 = *(char *)((int)pfVar19 + 0x1b);
                  *(char *)((int)pfVar19 + 0x1b) = cVar2 + '\x01';
                  *(undefined *)((int)pfVar19 + cVar2 + 0x13) = uVar17;
                }
                if ((bVar29 == 2) && ((iVar25 < (int)uVar15 || ((int)uVar15 <= iVar30)))) {
                  cVar2 = *(char *)((int)pfVar19 + 0x1b);
                  *(char *)((int)pfVar19 + 0x1b) = cVar2 + '\x01';
                  *(undefined *)((int)pfVar19 + cVar2 + 0x13) = uVar17;
                }
              }
              iVar20 = iVar20 + 2;
              iVar24 = iVar24 + 1;
            }
          }
        }
        if ((*(ushort *)(*piVar21 + 2) & 0x40) == 0) {
          iVar22 = *(int *)(*(int *)(*piVar21 + 100) + (uint)*(ushort *)(iVar23 + 0x44) * 4);
        }
        else {
          iVar22 = *(int *)(iVar23 + (uint)*(ushort *)(iVar23 + 0x44) * 4 + 0x1c) + 0x80;
        }
        if (*(short *)(iVar22 + 4) == 0) {
          *(undefined *)((int)pfVar19 + 0x12) = 0;
        }
        else {
          *(undefined *)((int)pfVar19 + 0x12) = 1;
          pfVar27 = (float *)(iVar22 + *(short *)(iVar22 + 4));
          fVar5 = *pfVar27;
          fVar6 = *(float *)(iVar18 + 8);
          iVar22 = (int)*(short *)(pfVar27 + 1);
          psVar28 = (short *)((int)pfVar27 + 6);
          local_30 = (double)CONCAT44(0x43300000,iVar22 - 1U ^ 0x80000000);
          fVar13 = (float)(local_30 - DOUBLE_803de900) * fVar4;
          uVar15 = (uint)fVar13;
          dVar31 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000) - DOUBLE_803de900;
          fVar14 = (float)(local_30 - DOUBLE_803de900) * *(float *)(iVar18 + 0x98);
          uVar16 = (uint)fVar14;
          dVar1 = (double)CONCAT44(0x43300000,uVar16 ^ 0x80000000) - DOUBLE_803de900;
          iVar30 = 0;
          fVar9 = FLOAT_803de8f0;
          fVar11 = FLOAT_803de8e0;
          if (*(ushort *)(iVar23 + 0x5a) != 0) {
            local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar23 + 0x5a));
            fVar9 = (float)(local_30 - DOUBLE_803de8e8) / FLOAT_803de8f4;
            if ((*(ushort *)(*piVar21 + 2) & 0x40) == 0) {
              iVar23 = *(int *)(*(int *)(*piVar21 + 100) + (uint)*(ushort *)(iVar23 + 0x48) * 4);
            }
            else {
              iVar23 = *(int *)(iVar23 + (uint)*(ushort *)(iVar23 + 0x48) * 4 + 0x24) + 0x80;
            }
            iVar30 = iVar23 + *(short *)(iVar23 + 4) + 6;
            fVar11 = FLOAT_803de8e0 - fVar9;
          }
          iVar25 = 0;
          iVar23 = (iVar22 - 1U) * 2;
          pfVar27 = pfVar19;
          do {
            if (*psVar28 == 0) {
              psVar28 = psVar28 + 1;
              if (iVar30 != 0) {
                iVar30 = iVar30 + 2;
              }
              if (iVar25 < 3) {
                *pfVar19 = FLOAT_803de8f0;
              }
              else {
                *(undefined2 *)((int)pfVar27 + 6) = 0;
              }
            }
            else {
              if (iVar30 != 0) {
                iVar30 = iVar30 + 2;
              }
              local_30 = (double)CONCAT44(0x43300000,(int)psVar28[uVar15 + 1] ^ 0x80000000);
              fVar7 = fVar11 * (float)(local_30 - DOUBLE_803de900);
              if (iVar30 != 0) {
                local_38 = (double)CONCAT44(0x43300000,
                                            (int)*(short *)(uVar15 * 2 + iVar30) ^ 0x80000000);
                fVar7 = fVar9 * (float)(local_38 - DOUBLE_803de900) + fVar7;
              }
              fVar8 = fVar11 * (float)((double)CONCAT44(0x43300000,
                                                        (int)(psVar28 + uVar15 + 1)[1] ^ 0x80000000)
                                      - DOUBLE_803de900);
              if (iVar30 != 0) {
                local_48 = (double)CONCAT44(0x43300000,
                                            (int)*(short *)(uVar15 * 2 + iVar30 + 2) ^ 0x80000000);
                fVar8 = fVar9 * (float)(local_48 - DOUBLE_803de900) + fVar8;
              }
              fVar10 = fVar11 * (float)((double)CONCAT44(0x43300000,
                                                         (int)psVar28[uVar16 + 1] ^ 0x80000000) -
                                       DOUBLE_803de900);
              if (iVar30 != 0) {
                fVar10 = fVar9 * (float)((double)CONCAT44(0x43300000,
                                                          (int)*(short *)(uVar16 * 2 + iVar30) ^
                                                          0x80000000) - DOUBLE_803de900) + fVar10;
              }
              fVar12 = fVar11 * (float)((double)CONCAT44(0x43300000,
                                                         (int)(psVar28 + uVar16 + 1)[1] ^ 0x80000000
                                                        ) - DOUBLE_803de900);
              if (iVar30 != 0) {
                local_20 = (double)CONCAT44(0x43300000,
                                            (int)*(short *)(uVar16 * 2 + iVar30 + 2) ^ 0x80000000);
                fVar12 = fVar9 * (float)(local_20 - DOUBLE_803de900) + fVar12;
              }
              fVar10 = (fVar14 - (float)dVar1) * (fVar12 - fVar10) + fVar10;
              if (fVar3 <= FLOAT_803de8f0) {
                if (fVar4 < *(float *)(iVar18 + 0x98)) {
                  local_20 = (double)CONCAT44(0x43300000,(int)psVar28[iVar22] ^ 0x80000000);
                  fVar10 = -(fVar11 * (float)(local_20 - DOUBLE_803de900) - fVar10);
                  if (iVar30 != 0) {
                    local_20 = (double)CONCAT44(0x43300000,
                                                (int)*(short *)(iVar23 + iVar30) ^ 0x80000000);
                    fVar10 = fVar9 * (float)(local_20 - DOUBLE_803de900) + fVar10;
                  }
                }
              }
              else if (*(float *)(iVar18 + 0x98) < fVar4) {
                local_20 = (double)CONCAT44(0x43300000,(int)psVar28[iVar22] ^ 0x80000000);
                fVar10 = fVar11 * (float)(local_20 - DOUBLE_803de900) + fVar10;
                if (iVar30 != 0) {
                  local_20 = (double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar23 + iVar30) ^ 0x80000000);
                  fVar10 = fVar9 * (float)(local_20 - DOUBLE_803de900) + fVar10;
                }
              }
              fVar10 = fVar10 - ((fVar13 - (float)dVar31) * (fVar8 - fVar7) + fVar7);
              if (iVar25 < 3) {
                *pfVar19 = fVar10 * fVar5 * fVar6;
              }
              else {
                *(short *)((int)pfVar27 + 6) = (short)(int)fVar10;
              }
              psVar28 = psVar28 + iVar22 + 1;
              if (iVar30 != 0) {
                iVar30 = iVar30 + iVar22 * 2;
              }
            }
            pfVar19 = pfVar19 + 1;
            pfVar27 = (float *)((int)pfVar27 + 2);
            iVar25 = iVar25 + 1;
          } while (iVar25 < 6);
        }
      }
    }
  }
  FUN_80286128(uVar26);
  return;
}

