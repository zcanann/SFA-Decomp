// Function: FUN_8002fb40
// Entry: 8002fb40
// Size: 2236 bytes

void FUN_8002fb40(undefined8 param_1,double param_2)

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
  float *pfVar26;
  short *psVar27;
  byte bVar28;
  int iVar29;
  double dVar30;
  double extraout_f1;
  undefined8 uVar31;
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_20;
  
  uVar31 = FUN_80286840();
  iVar18 = (int)((ulonglong)uVar31 >> 0x20);
  pfVar19 = (float *)uVar31;
  dVar30 = (double)FLOAT_803df58c;
  if ((dVar30 <= extraout_f1) && (dVar30 = extraout_f1, (double)FLOAT_803df560 < extraout_f1)) {
    dVar30 = (double)FLOAT_803df560;
  }
  piVar21 = *(int **)(*(int *)(iVar18 + 0x7c) + *(char *)(iVar18 + 0xad) * 4);
  if ((*(short *)(*piVar21 + 0xec) != 0) && (iVar23 = piVar21[0xb], iVar23 != 0)) {
    *(float *)(iVar23 + 0xc) = (float)(dVar30 * (double)*(float *)(iVar23 + 0x14));
    if (*(short *)(iVar23 + 0x58) != 0) {
      if ((*(byte *)(iVar23 + 99) & 8) != 0) {
        *(undefined4 *)(iVar23 + 0x10) = *(undefined4 *)(iVar23 + 0xc);
      }
      *(float *)(iVar23 + 8) =
           (float)((double)*(float *)(iVar23 + 0x10) * param_2 + (double)*(float *)(iVar23 + 8));
      fVar4 = FLOAT_803df570;
      fVar3 = *(float *)(iVar23 + 0x18);
      if (*(char *)(iVar23 + 0x61) == '\0') {
        fVar4 = *(float *)(iVar23 + 8);
        fVar5 = FLOAT_803df570;
        if ((FLOAT_803df570 <= fVar4) && (fVar5 = fVar4, fVar3 < fVar4)) {
          fVar5 = fVar3;
        }
        *(float *)(iVar23 + 8) = fVar5;
      }
      else {
        if (*(float *)(iVar23 + 8) < FLOAT_803df570) {
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
                                                                 (uint)*(ushort *)(iVar23 + 0x5e)) -
                                               DOUBLE_803df568) * param_2 -
                               (double)(float)((double)CONCAT44(0x43300000,
                                                                *(ushort *)(iVar23 + 0x58) ^
                                                                0x80000000) - DOUBLE_803df580));
        fVar3 = FLOAT_803df570;
        if ((-1 < (int)uVar15) &&
           (uVar15 = uVar15 ^ 0x80000000, fVar3 = FLOAT_803df574,
           (float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803df580) <= FLOAT_803df574)) {
          local_38 = (double)CONCAT44(0x43300000,uVar15);
          fVar3 = (float)(local_38 - DOUBLE_803df580);
        }
        *(short *)(iVar23 + 0x58) = (short)(int)fVar3;
      }
      if (*(short *)(iVar23 + 0x58) == 0) {
        *(undefined2 *)(iVar23 + 0x5c) = 0;
      }
    }
    fVar4 = *(float *)(iVar18 + 0x98);
    fVar3 = (float)(dVar30 * param_2);
    *(float *)(iVar18 + 0x98) = fVar4 + fVar3;
    fVar6 = FLOAT_803df570;
    fVar5 = FLOAT_803df560;
    if (*(float *)(iVar18 + 0x98) < FLOAT_803df560) {
      if (*(float *)(iVar18 + 0x98) < FLOAT_803df570) {
        if (*(char *)(iVar23 + 0x60) == '\0') {
          *(float *)(iVar18 + 0x98) = FLOAT_803df570;
        }
        else {
          while (*(float *)(iVar18 + 0x98) < fVar6) {
            *(float *)(iVar18 + 0x98) = *(float *)(iVar18 + 0x98) + fVar5;
          }
        }
      }
    }
    else if (*(char *)(iVar23 + 0x60) == '\0') {
      *(float *)(iVar18 + 0x98) = FLOAT_803df560;
    }
    else {
      while (fVar5 <= *(float *)(iVar18 + 0x98)) {
        *(float *)(iVar18 + 0x98) = *(float *)(iVar18 + 0x98) - fVar5;
      }
    }
    if (pfVar19 != (float *)0x0) {
      *(undefined *)((int)pfVar19 + 0x12) = 0;
      fVar5 = FLOAT_803df570;
      pfVar19[2] = FLOAT_803df570;
      pfVar19[1] = fVar5;
      *pfVar19 = fVar5;
      if (*(int *)(iVar18 + 0x60) != 0) {
        *(undefined *)((int)pfVar19 + 0x1b) = 0;
        iVar22 = **(int **)(iVar18 + 0x60) >> 1;
        if (iVar22 != 0) {
          iVar29 = (int)(FLOAT_803df578 * fVar4);
          iVar25 = (int)(FLOAT_803df578 * *(float *)(iVar18 + 0x98));
          bVar28 = iVar25 < iVar29;
          if (fVar3 < FLOAT_803df570) {
            bVar28 = bVar28 | 2;
          }
          iVar24 = 0;
          iVar20 = 0;
          while ((iVar24 < iVar22 && (*(char *)((int)pfVar19 + 0x1b) < '\b'))) {
            uVar16 = (uint)*(short *)(*(int *)(*(int *)(iVar18 + 0x60) + 4) + iVar20);
            uVar15 = uVar16 & 0x1ff;
            uVar16 = uVar16 >> 9 & 0x7f;
            if (uVar16 != 0x7f) {
              uVar17 = (undefined)uVar16;
              if (((bVar28 == 0) && (iVar29 <= (int)uVar15)) && ((int)uVar15 < iVar25)) {
                cVar2 = *(char *)((int)pfVar19 + 0x1b);
                *(char *)((int)pfVar19 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar19 + cVar2 + 0x13) = uVar17;
              }
              if ((bVar28 == 1) && ((iVar29 <= (int)uVar15 || ((int)uVar15 < iVar25)))) {
                cVar2 = *(char *)((int)pfVar19 + 0x1b);
                *(char *)((int)pfVar19 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar19 + cVar2 + 0x13) = uVar17;
              }
              if (((bVar28 == 3) && (iVar25 < (int)uVar15)) && ((int)uVar15 <= iVar29)) {
                cVar2 = *(char *)((int)pfVar19 + 0x1b);
                *(char *)((int)pfVar19 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar19 + cVar2 + 0x13) = uVar17;
              }
              if ((bVar28 == 2) && ((iVar25 < (int)uVar15 || ((int)uVar15 <= iVar29)))) {
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
        pfVar26 = (float *)(iVar22 + *(short *)(iVar22 + 4));
        fVar5 = *pfVar26;
        fVar6 = *(float *)(iVar18 + 8);
        iVar22 = (int)*(short *)(pfVar26 + 1);
        psVar27 = (short *)((int)pfVar26 + 6);
        local_30 = (double)CONCAT44(0x43300000,iVar22 - 1U ^ 0x80000000);
        fVar7 = (float)(local_30 - DOUBLE_803df580) * fVar4;
        uVar15 = (uint)fVar7;
        dVar30 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000) - DOUBLE_803df580;
        fVar8 = (float)(local_30 - DOUBLE_803df580) * *(float *)(iVar18 + 0x98);
        uVar16 = (uint)fVar8;
        dVar1 = (double)CONCAT44(0x43300000,uVar16 ^ 0x80000000) - DOUBLE_803df580;
        iVar29 = 0;
        fVar11 = FLOAT_803df570;
        fVar13 = FLOAT_803df560;
        if (*(ushort *)(iVar23 + 0x5a) != 0) {
          local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar23 + 0x5a));
          fVar11 = (float)(local_30 - DOUBLE_803df568) / FLOAT_803df574;
          if ((*(ushort *)(*piVar21 + 2) & 0x40) == 0) {
            iVar23 = *(int *)(*(int *)(*piVar21 + 100) + (uint)*(ushort *)(iVar23 + 0x48) * 4);
          }
          else {
            iVar23 = *(int *)(iVar23 + (uint)*(ushort *)(iVar23 + 0x48) * 4 + 0x24) + 0x80;
          }
          iVar29 = iVar23 + *(short *)(iVar23 + 4) + 6;
          fVar13 = FLOAT_803df560 - fVar11;
        }
        iVar25 = 0;
        iVar23 = (iVar22 - 1U) * 2;
        pfVar26 = pfVar19;
        do {
          if (*psVar27 == 0) {
            psVar27 = psVar27 + 1;
            if (iVar29 != 0) {
              iVar29 = iVar29 + 2;
            }
            if (iVar25 < 3) {
              *pfVar19 = FLOAT_803df570;
            }
            else {
              *(undefined2 *)((int)pfVar26 + 6) = 0;
            }
          }
          else {
            if (iVar29 != 0) {
              iVar29 = iVar29 + 2;
            }
            local_30 = (double)CONCAT44(0x43300000,(int)psVar27[uVar15 + 1] ^ 0x80000000);
            fVar9 = fVar13 * (float)(local_30 - DOUBLE_803df580);
            if (iVar29 != 0) {
              local_38 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(uVar15 * 2 + iVar29) ^ 0x80000000);
              fVar9 = fVar11 * (float)(local_38 - DOUBLE_803df580) + fVar9;
            }
            fVar10 = fVar13 * (float)((double)CONCAT44(0x43300000,
                                                       (int)(psVar27 + uVar15 + 1)[1] ^ 0x80000000)
                                     - DOUBLE_803df580);
            if (iVar29 != 0) {
              local_48 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(uVar15 * 2 + iVar29 + 2) ^ 0x80000000);
              fVar10 = fVar11 * (float)(local_48 - DOUBLE_803df580) + fVar10;
            }
            fVar12 = fVar13 * (float)((double)CONCAT44(0x43300000,
                                                       (int)psVar27[uVar16 + 1] ^ 0x80000000) -
                                     DOUBLE_803df580);
            if (iVar29 != 0) {
              fVar12 = fVar11 * (float)((double)CONCAT44(0x43300000,
                                                         (int)*(short *)(uVar16 * 2 + iVar29) ^
                                                         0x80000000) - DOUBLE_803df580) + fVar12;
            }
            fVar14 = fVar13 * (float)((double)CONCAT44(0x43300000,
                                                       (int)(psVar27 + uVar16 + 1)[1] ^ 0x80000000)
                                     - DOUBLE_803df580);
            if (iVar29 != 0) {
              local_20 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(uVar16 * 2 + iVar29 + 2) ^ 0x80000000);
              fVar14 = fVar11 * (float)(local_20 - DOUBLE_803df580) + fVar14;
            }
            fVar12 = (fVar8 - (float)dVar1) * (fVar14 - fVar12) + fVar12;
            if (fVar3 <= FLOAT_803df570) {
              if (fVar4 < *(float *)(iVar18 + 0x98)) {
                local_20 = (double)CONCAT44(0x43300000,(int)psVar27[iVar22] ^ 0x80000000);
                fVar12 = -(fVar13 * (float)(local_20 - DOUBLE_803df580) - fVar12);
                if (iVar29 != 0) {
                  local_20 = (double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar23 + iVar29) ^ 0x80000000);
                  fVar12 = fVar11 * (float)(local_20 - DOUBLE_803df580) + fVar12;
                }
              }
            }
            else if (*(float *)(iVar18 + 0x98) < fVar4) {
              local_20 = (double)CONCAT44(0x43300000,(int)psVar27[iVar22] ^ 0x80000000);
              fVar12 = fVar13 * (float)(local_20 - DOUBLE_803df580) + fVar12;
              if (iVar29 != 0) {
                local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar23 + iVar29) ^ 0x80000000
                                           );
                fVar12 = fVar11 * (float)(local_20 - DOUBLE_803df580) + fVar12;
              }
            }
            fVar12 = fVar12 - ((fVar7 - (float)dVar30) * (fVar10 - fVar9) + fVar9);
            if (iVar25 < 3) {
              *pfVar19 = fVar12 * fVar5 * fVar6;
            }
            else {
              *(short *)((int)pfVar26 + 6) = (short)(int)fVar12;
            }
            psVar27 = psVar27 + iVar22 + 1;
            if (iVar29 != 0) {
              iVar29 = iVar29 + iVar22 * 2;
            }
          }
          pfVar19 = pfVar19 + 1;
          pfVar26 = (float *)((int)pfVar26 + 2);
          iVar25 = iVar25 + 1;
        } while (iVar25 < 6);
      }
    }
  }
  FUN_8028688c();
  return;
}

