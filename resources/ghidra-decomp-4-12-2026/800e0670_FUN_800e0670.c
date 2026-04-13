// Function: FUN_800e0670
// Entry: 800e0670
// Size: 1572 bytes

/* WARNING: Removing unreachable block (ram,0x800e0c74) */
/* WARNING: Removing unreachable block (ram,0x800e0680) */

void FUN_800e0670(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  float *pfVar8;
  char *pcVar9;
  undefined *puVar10;
  undefined4 *puVar11;
  uint uVar12;
  uint uVar13;
  int iVar14;
  undefined4 *puVar15;
  int *in_r6;
  int *piVar16;
  int iVar17;
  int iVar18;
  int iVar19;
  float *pfVar20;
  float *pfVar21;
  int iVar22;
  int iVar23;
  float *pfVar24;
  int iVar25;
  uint uVar26;
  double in_f31;
  double dVar27;
  double in_ps31_1;
  int local_6d8;
  int local_6d4;
  float local_6d0 [4];
  int local_6c0 [4];
  float local_6b0 [40];
  int local_610 [40];
  char local_570 [48];
  undefined local_540 [1336];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar5 = FUN_80286818();
  if ((iVar5 != 0) && (iVar6 = FUN_800e397c(*(uint *)(iVar5 + 0x14),&local_6d8), iVar6 != 0)) {
    iVar6 = 0;
    iVar18 = 0;
    pfVar20 = local_6d0;
    pfVar21 = pfVar20;
    iVar22 = iVar5;
    do {
      if (-1 < *(int *)(iVar22 + 0x1c)) {
        pcVar9 = local_570;
        iVar25 = 0x1b;
        iVar14 = 0;
        do {
          iVar19 = iVar14;
          *pcVar9 = '\0';
          pcVar9[1] = '\0';
          pcVar9[2] = '\0';
          pcVar9[3] = '\0';
          pcVar9[4] = '\0';
          pcVar9[5] = '\0';
          pcVar9[6] = '\0';
          pcVar9[7] = '\0';
          pcVar9[8] = '\0';
          pcVar9[9] = '\0';
          pcVar9[10] = '\0';
          pcVar9[0xb] = '\0';
          pcVar9[0xc] = '\0';
          pcVar9[0xd] = '\0';
          pcVar9[0xe] = '\0';
          pcVar9[0xf] = '\0';
          pcVar9[0x10] = '\0';
          pcVar9[0x11] = '\0';
          pcVar9[0x12] = '\0';
          pcVar9[0x13] = '\0';
          pcVar9[0x14] = '\0';
          pcVar9[0x15] = '\0';
          pcVar9[0x16] = '\0';
          pcVar9[0x17] = '\0';
          pcVar9[0x18] = '\0';
          pcVar9[0x19] = '\0';
          pcVar9[0x1a] = '\0';
          pcVar9[0x1b] = '\0';
          pcVar9[0x1c] = '\0';
          pcVar9[0x1d] = '\0';
          pcVar9[0x1e] = '\0';
          pcVar9[0x1f] = '\0';
          pcVar9[0x20] = '\0';
          pcVar9[0x21] = '\0';
          pcVar9[0x22] = '\0';
          pcVar9[0x23] = '\0';
          pcVar9[0x24] = '\0';
          pcVar9[0x25] = '\0';
          pcVar9[0x26] = '\0';
          pcVar9[0x27] = '\0';
          pcVar9[0x28] = '\0';
          pcVar9[0x29] = '\0';
          pcVar9[0x2a] = '\0';
          pcVar9[0x2b] = '\0';
          pcVar9[0x2c] = '\0';
          pcVar9[0x2d] = '\0';
          pcVar9[0x2e] = '\0';
          pcVar9[0x2f] = '\0';
          pcVar9 = pcVar9 + 0x30;
          iVar14 = iVar19 + 0x30;
          iVar25 = iVar25 + -1;
        } while (iVar25 != 0);
        puVar10 = local_540 + iVar19;
        iVar25 = 0x514 - iVar14;
        if (iVar14 < 0x514) {
          do {
            *puVar10 = 0;
            puVar10 = puVar10 + 1;
            iVar25 = iVar25 + -1;
          } while (iVar25 != 0);
        }
        local_570[local_6d8] = '\x01';
        iVar14 = FUN_800e397c(*(uint *)(iVar22 + 0x1c),&local_6d4);
        if (iVar14 != 0) {
          fVar1 = *(float *)(iVar14 + 0x10) - *(float *)(iVar5 + 0x10);
          fVar2 = *(float *)(iVar14 + 8) - *(float *)(iVar5 + 8);
          fVar3 = *(float *)(iVar14 + 0xc) - *(float *)(iVar5 + 0xc);
          local_6b0[0] = fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3;
          iVar14 = 1;
          local_610[0] = local_6d4;
          local_570[local_6d4] = '\x01';
          bVar4 = false;
          pfVar24 = pfVar21;
          do {
            if (iVar14 < 1) {
              bVar4 = true;
            }
            else {
              iVar14 = iVar14 + -1;
              iVar25 = iVar14 * 4;
              local_6d4 = local_610[iVar14];
              iVar19 = (&DAT_803a2448)[local_610[iVar14]];
              dVar27 = (double)local_6b0[iVar14];
              if (*(char *)(iVar19 + 0x34) == '\x01') {
                bVar4 = true;
                *pfVar24 = local_6b0[iVar14];
                pfVar21 = pfVar21 + 1;
                pfVar24 = pfVar24 + 1;
                local_6b0[iVar6 + -4] = *(float *)(iVar22 + 0x1c);
                iVar6 = iVar6 + 1;
              }
              else {
                iVar17 = 0;
                iVar23 = iVar19;
                do {
                  if ((((-1 < (int)*(uint *)(iVar23 + 0x1c)) &&
                       (iVar7 = FUN_800e397c(*(uint *)(iVar23 + 0x1c),&local_6d4), iVar7 != 0)) &&
                      (local_570[local_6d4] == '\0')) && (iVar14 < 0x28)) {
                    fVar1 = *(float *)(iVar19 + 0x10) - *(float *)(iVar7 + 0x10);
                    fVar2 = *(float *)(iVar19 + 8) - *(float *)(iVar7 + 8);
                    fVar3 = *(float *)(iVar19 + 0xc) - *(float *)(iVar7 + 0xc);
                    fVar1 = fVar1 * fVar1 +
                            (float)(dVar27 + (double)(fVar2 * fVar2)) + fVar3 * fVar3;
                    iVar7 = 0;
                    for (pfVar8 = local_6b0; (iVar7 < iVar14 && (fVar1 < *pfVar8));
                        pfVar8 = pfVar8 + 1) {
                      iVar7 = iVar7 + 1;
                    }
                    puVar11 = (undefined4 *)((int)local_610 + iVar25);
                    puVar15 = (undefined4 *)((int)local_6b0 + iVar25);
                    uVar12 = iVar14 - iVar7;
                    if (iVar7 < iVar14) {
                      uVar26 = uVar12 >> 3;
                      if (uVar26 != 0) {
                        do {
                          *puVar11 = puVar11[-1];
                          *puVar15 = puVar15[-1];
                          puVar11[-1] = puVar11[-2];
                          puVar15[-1] = puVar15[-2];
                          puVar11[-2] = puVar11[-3];
                          puVar15[-2] = puVar15[-3];
                          puVar11[-3] = puVar11[-4];
                          puVar15[-3] = puVar15[-4];
                          puVar11[-4] = puVar11[-5];
                          puVar15[-4] = puVar15[-5];
                          puVar11[-5] = puVar11[-6];
                          puVar15[-5] = puVar15[-6];
                          puVar11[-6] = puVar11[-7];
                          puVar15[-6] = puVar15[-7];
                          puVar11[-7] = puVar11[-8];
                          puVar15[-7] = puVar15[-8];
                          puVar11 = puVar11 + -8;
                          puVar15 = puVar15 + -8;
                          uVar26 = uVar26 - 1;
                        } while (uVar26 != 0);
                        uVar12 = uVar12 & 7;
                        if (uVar12 == 0) goto LAB_800e0a70;
                      }
                      do {
                        *puVar11 = puVar11[-1];
                        *puVar15 = puVar15[-1];
                        puVar11 = puVar11 + -1;
                        puVar15 = puVar15 + -1;
                        uVar12 = uVar12 - 1;
                      } while (uVar12 != 0);
                    }
LAB_800e0a70:
                    iVar14 = iVar14 + 1;
                    iVar25 = iVar25 + 4;
                    local_6b0[iVar7] = fVar1;
                    local_610[iVar7] = local_6d4;
                    local_570[local_6d4] = '\x01';
                  }
                  iVar23 = iVar23 + 4;
                  iVar17 = iVar17 + 1;
                } while (iVar17 < 4);
              }
            }
          } while (!bVar4);
        }
      }
      iVar22 = iVar22 + 4;
      iVar18 = iVar18 + 1;
    } while (iVar18 < 4);
    if (iVar6 != 0) {
      if (iVar6 == 1) {
        *in_r6 = *(int *)(iVar5 + 0x14);
      }
      else if (1 < iVar6) {
        iVar22 = 0;
        for (iVar18 = 0; iVar18 < iVar6; iVar18 = iVar18 + 1) {
          piVar16 = (int *)((int)local_6c0 + iVar22);
          if (*in_r6 == *piVar16) {
            puVar11 = (undefined4 *)((int)local_6d0 + iVar22);
            uVar12 = (iVar6 + -1) - iVar18;
            if (iVar18 < iVar6 + -1) {
              uVar26 = uVar12 >> 3;
              uVar13 = uVar12;
              if (uVar26 == 0) goto LAB_800e0be4;
              do {
                *piVar16 = piVar16[1];
                *puVar11 = puVar11[1];
                piVar16[1] = piVar16[2];
                puVar11[1] = puVar11[2];
                piVar16[2] = piVar16[3];
                puVar11[2] = puVar11[3];
                piVar16[3] = piVar16[4];
                puVar11[3] = puVar11[4];
                piVar16[4] = piVar16[5];
                puVar11[4] = puVar11[5];
                piVar16[5] = piVar16[6];
                puVar11[5] = puVar11[6];
                piVar16[6] = piVar16[7];
                puVar11[6] = puVar11[7];
                piVar16[7] = piVar16[8];
                puVar11[7] = puVar11[8];
                piVar16 = piVar16 + 8;
                puVar11 = puVar11 + 8;
                iVar22 = iVar22 + 0x20;
                uVar26 = uVar26 - 1;
              } while (uVar26 != 0);
              for (uVar13 = uVar12 & 7; uVar13 != 0; uVar13 = uVar13 - 1) {
LAB_800e0be4:
                *piVar16 = piVar16[1];
                *puVar11 = puVar11[1];
                piVar16 = piVar16 + 1;
                puVar11 = puVar11 + 1;
                iVar22 = iVar22 + 4;
              }
              iVar18 = iVar18 + uVar12;
            }
            iVar6 = iVar6 + -1;
          }
          iVar22 = iVar22 + 4;
        }
        *in_r6 = *(int *)(iVar5 + 0x14);
        iVar5 = 0;
        iVar22 = 0;
        if (0 < iVar6) {
          do {
            if (*pfVar20 < local_6d0[iVar5]) {
              iVar5 = iVar22;
            }
            pfVar20 = pfVar20 + 1;
            iVar22 = iVar22 + 1;
            iVar6 = iVar6 + -1;
          } while (iVar6 != 0);
        }
      }
    }
  }
  FUN_80286864();
  return;
}

