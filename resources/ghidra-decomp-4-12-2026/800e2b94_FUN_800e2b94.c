// Function: FUN_800e2b94
// Entry: 800e2b94
// Size: 1612 bytes

/* WARNING: Removing unreachable block (ram,0x800e31c0) */
/* WARNING: Removing unreachable block (ram,0x800e2ba4) */

void FUN_800e2b94(undefined4 param_1,undefined4 param_2,int param_3,int *param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  char *pcVar8;
  undefined *puVar9;
  undefined4 *puVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  undefined4 *puVar14;
  int iVar15;
  int *piVar16;
  int iVar17;
  int iVar18;
  float *pfVar19;
  float *pfVar20;
  int iVar21;
  int iVar22;
  float *pfVar23;
  int iVar24;
  int iVar25;
  uint uVar26;
  double in_f31;
  double dVar27;
  double in_ps31_1;
  undefined8 uVar28;
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
  uVar28 = FUN_80286810();
  iVar15 = (int)((ulonglong)uVar28 >> 0x20);
  if ((iVar15 != 0) && (iVar5 = FUN_800e397c(*(uint *)(iVar15 + 0x14),&local_6d8), iVar5 != 0)) {
    iVar5 = 0;
    iVar18 = 0;
    pfVar19 = local_6d0;
    pfVar20 = pfVar19;
    iVar21 = iVar15;
    do {
      if (-1 < *(int *)(iVar21 + 0x1c)) {
        pcVar8 = local_570;
        iVar25 = 0x1b;
        iVar13 = 0;
        do {
          iVar24 = iVar13;
          *pcVar8 = '\0';
          pcVar8[1] = '\0';
          pcVar8[2] = '\0';
          pcVar8[3] = '\0';
          pcVar8[4] = '\0';
          pcVar8[5] = '\0';
          pcVar8[6] = '\0';
          pcVar8[7] = '\0';
          pcVar8[8] = '\0';
          pcVar8[9] = '\0';
          pcVar8[10] = '\0';
          pcVar8[0xb] = '\0';
          pcVar8[0xc] = '\0';
          pcVar8[0xd] = '\0';
          pcVar8[0xe] = '\0';
          pcVar8[0xf] = '\0';
          pcVar8[0x10] = '\0';
          pcVar8[0x11] = '\0';
          pcVar8[0x12] = '\0';
          pcVar8[0x13] = '\0';
          pcVar8[0x14] = '\0';
          pcVar8[0x15] = '\0';
          pcVar8[0x16] = '\0';
          pcVar8[0x17] = '\0';
          pcVar8[0x18] = '\0';
          pcVar8[0x19] = '\0';
          pcVar8[0x1a] = '\0';
          pcVar8[0x1b] = '\0';
          pcVar8[0x1c] = '\0';
          pcVar8[0x1d] = '\0';
          pcVar8[0x1e] = '\0';
          pcVar8[0x1f] = '\0';
          pcVar8[0x20] = '\0';
          pcVar8[0x21] = '\0';
          pcVar8[0x22] = '\0';
          pcVar8[0x23] = '\0';
          pcVar8[0x24] = '\0';
          pcVar8[0x25] = '\0';
          pcVar8[0x26] = '\0';
          pcVar8[0x27] = '\0';
          pcVar8[0x28] = '\0';
          pcVar8[0x29] = '\0';
          pcVar8[0x2a] = '\0';
          pcVar8[0x2b] = '\0';
          pcVar8[0x2c] = '\0';
          pcVar8[0x2d] = '\0';
          pcVar8[0x2e] = '\0';
          pcVar8[0x2f] = '\0';
          pcVar8 = pcVar8 + 0x30;
          iVar13 = iVar24 + 0x30;
          iVar25 = iVar25 + -1;
        } while (iVar25 != 0);
        puVar9 = local_540 + iVar24;
        iVar25 = 0x514 - iVar13;
        if (iVar13 < 0x514) {
          do {
            *puVar9 = 0;
            puVar9 = puVar9 + 1;
            iVar25 = iVar25 + -1;
          } while (iVar25 != 0);
        }
        local_570[local_6d8] = '\x01';
        iVar13 = FUN_800e397c(*(uint *)(iVar21 + 0x1c),&local_6d4);
        if (iVar13 != 0) {
          fVar1 = *(float *)(iVar13 + 0x10) - *(float *)(iVar15 + 0x10);
          fVar2 = *(float *)(iVar13 + 8) - *(float *)(iVar15 + 8);
          fVar3 = *(float *)(iVar13 + 0xc) - *(float *)(iVar15 + 0xc);
          local_6b0[0] = fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3;
          iVar13 = 1;
          local_610[0] = local_6d4;
          local_570[local_6d4] = '\x01';
          bVar4 = false;
          pfVar23 = pfVar20;
          do {
            if (iVar13 < 1) {
              bVar4 = true;
            }
            else {
              iVar13 = iVar13 + -1;
              local_6d4 = local_610[iVar13];
              iVar25 = (&DAT_803a2448)[local_610[iVar13]];
              dVar27 = (double)local_6b0[iVar13];
              if (((int)*(char *)(iVar25 + 0x19) == (int)uVar28) &&
                 ((param_3 == -1 || (param_3 == *(char *)(iVar25 + 0x18))))) {
                bVar4 = true;
                *pfVar23 = local_6b0[iVar13];
                pfVar20 = pfVar20 + 1;
                pfVar23 = pfVar23 + 1;
                local_6b0[iVar5 + -4] = *(float *)(iVar21 + 0x1c);
                iVar5 = iVar5 + 1;
              }
              else {
                iVar17 = 0;
                iVar24 = iVar13 * 4;
                iVar22 = iVar25;
                do {
                  if ((((-1 < (int)*(uint *)(iVar22 + 0x1c)) &&
                       (iVar6 = FUN_800e397c(*(uint *)(iVar22 + 0x1c),&local_6d4), iVar6 != 0)) &&
                      (local_570[local_6d4] == '\0')) && (iVar13 < 0x28)) {
                    fVar1 = *(float *)(iVar25 + 0x10) - *(float *)(iVar6 + 0x10);
                    fVar2 = *(float *)(iVar25 + 8) - *(float *)(iVar6 + 8);
                    fVar3 = *(float *)(iVar25 + 0xc) - *(float *)(iVar6 + 0xc);
                    fVar1 = fVar1 * fVar1 +
                            (float)(dVar27 + (double)(fVar2 * fVar2)) + fVar3 * fVar3;
                    iVar6 = 0;
                    for (pfVar7 = local_6b0; (iVar6 < iVar13 && (fVar1 < *pfVar7));
                        pfVar7 = pfVar7 + 1) {
                      iVar6 = iVar6 + 1;
                    }
                    puVar10 = (undefined4 *)((int)local_610 + iVar24);
                    puVar14 = (undefined4 *)((int)local_6b0 + iVar24);
                    uVar11 = iVar13 - iVar6;
                    if (iVar6 < iVar13) {
                      uVar26 = uVar11 >> 3;
                      if (uVar26 != 0) {
                        do {
                          *puVar10 = puVar10[-1];
                          *puVar14 = puVar14[-1];
                          puVar10[-1] = puVar10[-2];
                          puVar14[-1] = puVar14[-2];
                          puVar10[-2] = puVar10[-3];
                          puVar14[-2] = puVar14[-3];
                          puVar10[-3] = puVar10[-4];
                          puVar14[-3] = puVar14[-4];
                          puVar10[-4] = puVar10[-5];
                          puVar14[-4] = puVar14[-5];
                          puVar10[-5] = puVar10[-6];
                          puVar14[-5] = puVar14[-6];
                          puVar10[-6] = puVar10[-7];
                          puVar14[-6] = puVar14[-7];
                          puVar10[-7] = puVar10[-8];
                          puVar14[-7] = puVar14[-8];
                          puVar10 = puVar10 + -8;
                          puVar14 = puVar14 + -8;
                          uVar26 = uVar26 - 1;
                        } while (uVar26 != 0);
                        uVar11 = uVar11 & 7;
                        if (uVar11 == 0) goto LAB_800e2fbc;
                      }
                      do {
                        *puVar10 = puVar10[-1];
                        *puVar14 = puVar14[-1];
                        puVar10 = puVar10 + -1;
                        puVar14 = puVar14 + -1;
                        uVar11 = uVar11 - 1;
                      } while (uVar11 != 0);
                    }
LAB_800e2fbc:
                    iVar13 = iVar13 + 1;
                    iVar24 = iVar24 + 4;
                    local_6b0[iVar6] = fVar1;
                    local_610[iVar6] = local_6d4;
                    local_570[local_6d4] = '\x01';
                  }
                  iVar22 = iVar22 + 4;
                  iVar17 = iVar17 + 1;
                } while (iVar17 < 4);
              }
            }
          } while (!bVar4);
        }
      }
      iVar21 = iVar21 + 4;
      iVar18 = iVar18 + 1;
    } while (iVar18 < 4);
    if (iVar5 != 0) {
      if (iVar5 == 1) {
        *param_4 = *(int *)(iVar15 + 0x14);
      }
      else if (1 < iVar5) {
        iVar21 = 0;
        for (iVar18 = 0; iVar18 < iVar5; iVar18 = iVar18 + 1) {
          piVar16 = (int *)((int)local_6c0 + iVar21);
          if (*param_4 == *piVar16) {
            puVar10 = (undefined4 *)((int)local_6d0 + iVar21);
            uVar11 = (iVar5 + -1) - iVar18;
            if (iVar18 < iVar5 + -1) {
              uVar26 = uVar11 >> 3;
              uVar12 = uVar11;
              if (uVar26 == 0) goto LAB_800e3130;
              do {
                *piVar16 = piVar16[1];
                *puVar10 = puVar10[1];
                piVar16[1] = piVar16[2];
                puVar10[1] = puVar10[2];
                piVar16[2] = piVar16[3];
                puVar10[2] = puVar10[3];
                piVar16[3] = piVar16[4];
                puVar10[3] = puVar10[4];
                piVar16[4] = piVar16[5];
                puVar10[4] = puVar10[5];
                piVar16[5] = piVar16[6];
                puVar10[5] = puVar10[6];
                piVar16[6] = piVar16[7];
                puVar10[6] = puVar10[7];
                piVar16[7] = piVar16[8];
                puVar10[7] = puVar10[8];
                piVar16 = piVar16 + 8;
                puVar10 = puVar10 + 8;
                iVar21 = iVar21 + 0x20;
                uVar26 = uVar26 - 1;
              } while (uVar26 != 0);
              for (uVar12 = uVar11 & 7; uVar12 != 0; uVar12 = uVar12 - 1) {
LAB_800e3130:
                *piVar16 = piVar16[1];
                *puVar10 = puVar10[1];
                piVar16 = piVar16 + 1;
                puVar10 = puVar10 + 1;
                iVar21 = iVar21 + 4;
              }
              iVar18 = iVar18 + uVar11;
            }
            iVar5 = iVar5 + -1;
          }
          iVar21 = iVar21 + 4;
        }
        *param_4 = *(int *)(iVar15 + 0x14);
        iVar15 = 0;
        iVar21 = 0;
        if (0 < iVar5) {
          do {
            if (*pfVar19 < local_6d0[iVar15]) {
              iVar15 = iVar21;
            }
            pfVar19 = pfVar19 + 1;
            iVar21 = iVar21 + 1;
            iVar5 = iVar5 + -1;
          } while (iVar5 != 0);
        }
      }
    }
  }
  FUN_8028685c();
  return;
}

