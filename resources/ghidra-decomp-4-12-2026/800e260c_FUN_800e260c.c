// Function: FUN_800e260c
// Entry: 800e260c
// Size: 1332 bytes

/* WARNING: Removing unreachable block (ram,0x800e2b20) */
/* WARNING: Removing unreachable block (ram,0x800e261c) */

void FUN_800e260c(undefined4 param_1,undefined4 param_2,uint param_3,int *param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  uint uVar8;
  char *pcVar9;
  undefined *puVar10;
  undefined4 *puVar11;
  int iVar12;
  undefined4 *puVar13;
  float *pfVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  undefined4 *puVar18;
  float *pfVar19;
  int iVar20;
  int iVar21;
  undefined4 *puVar22;
  float *pfVar23;
  int iVar24;
  int iVar25;
  uint uVar26;
  double in_f31;
  double dVar27;
  double in_ps31_1;
  undefined8 uVar28;
  char local_6e4 [4];
  int local_6e0;
  int local_6dc;
  float local_6d8 [4];
  undefined4 local_6c8 [4];
  float local_6b8 [40];
  int local_618 [40];
  char local_578 [48];
  undefined local_548 [1344];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar28 = FUN_8028680c();
  iVar5 = FUN_800e397c((uint)((ulonglong)uVar28 >> 0x20),&local_6e0);
  if (iVar5 != 0) {
    iVar16 = 0;
    iVar17 = 0;
    pfVar14 = local_6d8;
    puVar18 = local_6c8;
    pfVar19 = pfVar14;
    iVar20 = iVar5;
    do {
      if (-1 < *(int *)(iVar20 + 0x1c)) {
        pcVar9 = local_578;
        iVar25 = 0x1b;
        iVar12 = 0;
        do {
          iVar24 = iVar12;
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
          iVar12 = iVar24 + 0x30;
          iVar25 = iVar25 + -1;
        } while (iVar25 != 0);
        puVar10 = local_548 + iVar24;
        iVar25 = 0x514 - iVar12;
        if (iVar12 < 0x514) {
          do {
            *puVar10 = 0;
            puVar10 = puVar10 + 1;
            iVar25 = iVar25 + -1;
          } while (iVar25 != 0);
        }
        local_578[local_6e0] = '\x01';
        iVar12 = FUN_800e397c(*(uint *)(iVar20 + 0x1c),&local_6dc);
        if (iVar12 != 0) {
          fVar1 = *(float *)(iVar12 + 0x10) - *(float *)(iVar5 + 0x10);
          fVar2 = *(float *)(iVar12 + 8) - *(float *)(iVar5 + 8);
          fVar3 = *(float *)(iVar12 + 0xc) - *(float *)(iVar5 + 0xc);
          local_6b8[0] = fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3;
          iVar12 = 1;
          local_618[0] = local_6dc;
          local_578[local_6dc] = '\x01';
          bVar4 = false;
          puVar22 = puVar18;
          pfVar23 = pfVar19;
          do {
            if (iVar12 < 1) {
              bVar4 = true;
            }
            else {
              iVar12 = iVar12 + -1;
              local_6dc = local_618[iVar12];
              iVar25 = (&DAT_803a2448)[local_618[iVar12]];
              dVar27 = (double)local_6b8[iVar12];
              if ((((int)*(char *)(iVar25 + 0x19) == (int)uVar28) || ((int)uVar28 == -1)) &&
                 ((*(byte *)(iVar25 + 0x31) == param_3 ||
                  ((*(byte *)(iVar25 + 0x32) == param_3 || (*(byte *)(iVar25 + 0x33) == param_3)))))
                 ) {
                bVar4 = true;
                *pfVar23 = local_6b8[iVar12];
                if (iVar16 < 4) {
                  *puVar22 = *(undefined4 *)(iVar25 + 0x14);
                  pfVar19 = pfVar19 + 1;
                  puVar18 = puVar18 + 1;
                  pfVar23 = pfVar23 + 1;
                  puVar22 = puVar22 + 1;
                  local_6e4[iVar16] = (char)iVar17;
                  iVar16 = iVar16 + 1;
                }
              }
              else {
                iVar15 = 0;
                iVar24 = iVar12 * 4;
                iVar21 = iVar25;
                do {
                  if ((((-1 < (int)*(uint *)(iVar21 + 0x1c)) &&
                       (iVar6 = FUN_800e397c(*(uint *)(iVar21 + 0x1c),&local_6dc), iVar6 != 0)) &&
                      (local_578[local_6dc] == '\0')) && (iVar12 < 0x28)) {
                    fVar1 = *(float *)(iVar25 + 0x10) - *(float *)(iVar6 + 0x10);
                    fVar2 = *(float *)(iVar25 + 8) - *(float *)(iVar6 + 8);
                    fVar3 = *(float *)(iVar25 + 0xc) - *(float *)(iVar6 + 0xc);
                    fVar1 = fVar1 * fVar1 +
                            (float)(dVar27 + (double)(fVar2 * fVar2)) + fVar3 * fVar3;
                    iVar6 = 0;
                    for (pfVar7 = local_6b8; (iVar6 < iVar12 && (fVar1 < *pfVar7));
                        pfVar7 = pfVar7 + 1) {
                      iVar6 = iVar6 + 1;
                    }
                    puVar11 = (undefined4 *)((int)local_618 + iVar24);
                    puVar13 = (undefined4 *)((int)local_6b8 + iVar24);
                    uVar8 = iVar12 - iVar6;
                    if (iVar6 < iVar12) {
                      uVar26 = uVar8 >> 3;
                      if (uVar26 != 0) {
                        do {
                          *puVar11 = puVar11[-1];
                          *puVar13 = puVar13[-1];
                          puVar11[-1] = puVar11[-2];
                          puVar13[-1] = puVar13[-2];
                          puVar11[-2] = puVar11[-3];
                          puVar13[-2] = puVar13[-3];
                          puVar11[-3] = puVar11[-4];
                          puVar13[-3] = puVar13[-4];
                          puVar11[-4] = puVar11[-5];
                          puVar13[-4] = puVar13[-5];
                          puVar11[-5] = puVar11[-6];
                          puVar13[-5] = puVar13[-6];
                          puVar11[-6] = puVar11[-7];
                          puVar13[-6] = puVar13[-7];
                          puVar11[-7] = puVar11[-8];
                          puVar13[-7] = puVar13[-8];
                          puVar11 = puVar11 + -8;
                          puVar13 = puVar13 + -8;
                          uVar26 = uVar26 - 1;
                        } while (uVar26 != 0);
                        uVar8 = uVar8 & 7;
                        if (uVar8 == 0) goto LAB_800e2a50;
                      }
                      do {
                        *puVar11 = puVar11[-1];
                        *puVar13 = puVar13[-1];
                        puVar11 = puVar11 + -1;
                        puVar13 = puVar13 + -1;
                        uVar8 = uVar8 - 1;
                      } while (uVar8 != 0);
                    }
LAB_800e2a50:
                    iVar12 = iVar12 + 1;
                    iVar24 = iVar24 + 4;
                    local_6b8[iVar6] = fVar1;
                    local_618[iVar6] = local_6dc;
                    local_578[local_6dc] = '\x01';
                  }
                  iVar21 = iVar21 + 4;
                  iVar15 = iVar15 + 1;
                } while (iVar15 < 4);
              }
            }
          } while (!bVar4);
        }
      }
      iVar20 = iVar20 + 4;
      iVar17 = iVar17 + 1;
    } while (iVar17 < 4);
    if (0 < iVar16) {
      iVar5 = 0;
      iVar20 = 0;
      if (0 < iVar16) {
        do {
          if (*pfVar14 < local_6d8[iVar5]) {
            iVar5 = iVar20;
          }
          pfVar14 = pfVar14 + 1;
          iVar20 = iVar20 + 1;
          iVar16 = iVar16 + -1;
        } while (iVar16 != 0);
      }
      if (param_4 != (int *)0x0) {
        *param_4 = (int)local_6e4[iVar5];
      }
    }
  }
  FUN_80286858();
  return;
}

