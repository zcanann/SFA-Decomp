// Function: FUN_800e2388
// Entry: 800e2388
// Size: 1332 bytes

/* WARNING: Removing unreachable block (ram,0x800e289c) */

void FUN_800e2388(undefined4 param_1,undefined4 param_2,uint param_3,int *param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  float *pfVar8;
  uint uVar9;
  char *pcVar10;
  undefined *puVar11;
  undefined4 *puVar12;
  int iVar13;
  undefined4 *puVar14;
  float *pfVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  undefined4 *puVar19;
  float *pfVar20;
  int iVar21;
  int iVar22;
  undefined4 *puVar23;
  float *pfVar24;
  int iVar25;
  int iVar26;
  uint uVar27;
  undefined4 uVar28;
  undefined8 in_f31;
  double dVar29;
  undefined8 uVar30;
  char local_6e4 [4];
  int local_6e0;
  int local_6dc;
  float local_6d8 [4];
  undefined4 local_6c8 [4];
  float local_6b8 [40];
  int local_618 [40];
  char local_578 [48];
  undefined local_548 [1344];
  undefined auStack8 [8];
  
  uVar28 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar30 = FUN_802860a8();
  iVar5 = FUN_800e36f8((int)((ulonglong)uVar30 >> 0x20),&local_6e0);
  if (iVar5 == 0) {
    uVar6 = 0xffffffff;
  }
  else {
    iVar17 = 0;
    iVar18 = 0;
    pfVar15 = local_6d8;
    puVar19 = local_6c8;
    pfVar20 = pfVar15;
    iVar21 = iVar5;
    do {
      if (-1 < *(int *)(iVar21 + 0x1c)) {
        pcVar10 = local_578;
        iVar26 = 0x1b;
        iVar13 = 0;
        do {
          iVar25 = iVar13;
          *pcVar10 = '\0';
          pcVar10[1] = '\0';
          pcVar10[2] = '\0';
          pcVar10[3] = '\0';
          pcVar10[4] = '\0';
          pcVar10[5] = '\0';
          pcVar10[6] = '\0';
          pcVar10[7] = '\0';
          pcVar10[8] = '\0';
          pcVar10[9] = '\0';
          pcVar10[10] = '\0';
          pcVar10[0xb] = '\0';
          pcVar10[0xc] = '\0';
          pcVar10[0xd] = '\0';
          pcVar10[0xe] = '\0';
          pcVar10[0xf] = '\0';
          pcVar10[0x10] = '\0';
          pcVar10[0x11] = '\0';
          pcVar10[0x12] = '\0';
          pcVar10[0x13] = '\0';
          pcVar10[0x14] = '\0';
          pcVar10[0x15] = '\0';
          pcVar10[0x16] = '\0';
          pcVar10[0x17] = '\0';
          pcVar10[0x18] = '\0';
          pcVar10[0x19] = '\0';
          pcVar10[0x1a] = '\0';
          pcVar10[0x1b] = '\0';
          pcVar10[0x1c] = '\0';
          pcVar10[0x1d] = '\0';
          pcVar10[0x1e] = '\0';
          pcVar10[0x1f] = '\0';
          pcVar10[0x20] = '\0';
          pcVar10[0x21] = '\0';
          pcVar10[0x22] = '\0';
          pcVar10[0x23] = '\0';
          pcVar10[0x24] = '\0';
          pcVar10[0x25] = '\0';
          pcVar10[0x26] = '\0';
          pcVar10[0x27] = '\0';
          pcVar10[0x28] = '\0';
          pcVar10[0x29] = '\0';
          pcVar10[0x2a] = '\0';
          pcVar10[0x2b] = '\0';
          pcVar10[0x2c] = '\0';
          pcVar10[0x2d] = '\0';
          pcVar10[0x2e] = '\0';
          pcVar10[0x2f] = '\0';
          pcVar10 = pcVar10 + 0x30;
          iVar13 = iVar25 + 0x30;
          iVar26 = iVar26 + -1;
        } while (iVar26 != 0);
        puVar11 = local_548 + iVar25;
        iVar26 = 0x514 - iVar13;
        if (iVar13 < 0x514) {
          do {
            *puVar11 = 0;
            puVar11 = puVar11 + 1;
            iVar13 = iVar13 + 1;
            iVar26 = iVar26 + -1;
          } while (iVar26 != 0);
        }
        local_578[local_6e0] = '\x01';
        iVar13 = FUN_800e36f8(*(undefined4 *)(iVar21 + 0x1c),&local_6dc,iVar13);
        if (iVar13 != 0) {
          fVar1 = *(float *)(iVar13 + 0x10) - *(float *)(iVar5 + 0x10);
          fVar2 = *(float *)(iVar13 + 8) - *(float *)(iVar5 + 8);
          fVar3 = *(float *)(iVar13 + 0xc) - *(float *)(iVar5 + 0xc);
          local_6b8[0] = fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3;
          iVar13 = 1;
          local_618[0] = local_6dc;
          local_578[local_6dc] = '\x01';
          bVar4 = false;
          puVar23 = puVar19;
          pfVar24 = pfVar20;
          do {
            if (iVar13 < 1) {
              bVar4 = true;
            }
            else {
              iVar13 = iVar13 + -1;
              local_6dc = local_618[iVar13];
              iVar26 = (&DAT_803a17e8)[local_618[iVar13]];
              dVar29 = (double)local_6b8[iVar13];
              if ((((int)*(char *)(iVar26 + 0x19) == (int)uVar30) || ((int)uVar30 == -1)) &&
                 ((*(byte *)(iVar26 + 0x31) == param_3 ||
                  ((*(byte *)(iVar26 + 0x32) == param_3 || (*(byte *)(iVar26 + 0x33) == param_3)))))
                 ) {
                bVar4 = true;
                *pfVar24 = local_6b8[iVar13];
                if (iVar17 < 4) {
                  *puVar23 = *(undefined4 *)(iVar26 + 0x14);
                  pfVar20 = pfVar20 + 1;
                  puVar19 = puVar19 + 1;
                  pfVar24 = pfVar24 + 1;
                  puVar23 = puVar23 + 1;
                  local_6e4[iVar17] = (char)iVar18;
                  iVar17 = iVar17 + 1;
                }
              }
              else {
                iVar16 = 0;
                iVar25 = iVar13 * 4;
                iVar22 = iVar26;
                do {
                  if ((((-1 < *(int *)(iVar22 + 0x1c)) &&
                       (iVar7 = FUN_800e36f8(*(int *)(iVar22 + 0x1c),&local_6dc), iVar7 != 0)) &&
                      (local_578[local_6dc] == '\0')) && (iVar13 < 0x28)) {
                    fVar1 = *(float *)(iVar26 + 0x10) - *(float *)(iVar7 + 0x10);
                    fVar2 = *(float *)(iVar26 + 8) - *(float *)(iVar7 + 8);
                    fVar3 = *(float *)(iVar26 + 0xc) - *(float *)(iVar7 + 0xc);
                    fVar1 = fVar1 * fVar1 +
                            (float)(dVar29 + (double)(fVar2 * fVar2)) + fVar3 * fVar3;
                    iVar7 = 0;
                    for (pfVar8 = local_6b8; (iVar7 < iVar13 && (fVar1 < *pfVar8));
                        pfVar8 = pfVar8 + 1) {
                      iVar7 = iVar7 + 1;
                    }
                    puVar12 = (undefined4 *)((int)local_618 + iVar25);
                    puVar14 = (undefined4 *)((int)local_6b8 + iVar25);
                    uVar9 = iVar13 - iVar7;
                    if (iVar7 < iVar13) {
                      uVar27 = uVar9 >> 3;
                      if (uVar27 != 0) {
                        do {
                          *puVar12 = puVar12[-1];
                          *puVar14 = puVar14[-1];
                          puVar12[-1] = puVar12[-2];
                          puVar14[-1] = puVar14[-2];
                          puVar12[-2] = puVar12[-3];
                          puVar14[-2] = puVar14[-3];
                          puVar12[-3] = puVar12[-4];
                          puVar14[-3] = puVar14[-4];
                          puVar12[-4] = puVar12[-5];
                          puVar14[-4] = puVar14[-5];
                          puVar12[-5] = puVar12[-6];
                          puVar14[-5] = puVar14[-6];
                          puVar12[-6] = puVar12[-7];
                          puVar14[-6] = puVar14[-7];
                          puVar12[-7] = puVar12[-8];
                          puVar14[-7] = puVar14[-8];
                          puVar12 = puVar12 + -8;
                          puVar14 = puVar14 + -8;
                          uVar27 = uVar27 - 1;
                        } while (uVar27 != 0);
                        uVar9 = uVar9 & 7;
                        if (uVar9 == 0) goto LAB_800e27cc;
                      }
                      do {
                        *puVar12 = puVar12[-1];
                        *puVar14 = puVar14[-1];
                        puVar12 = puVar12 + -1;
                        puVar14 = puVar14 + -1;
                        uVar9 = uVar9 - 1;
                      } while (uVar9 != 0);
                    }
LAB_800e27cc:
                    iVar13 = iVar13 + 1;
                    iVar25 = iVar25 + 4;
                    local_6b8[iVar7] = fVar1;
                    local_618[iVar7] = local_6dc;
                    local_578[local_6dc] = '\x01';
                  }
                  iVar22 = iVar22 + 4;
                  iVar16 = iVar16 + 1;
                } while (iVar16 < 4);
              }
            }
          } while (!bVar4);
        }
      }
      iVar21 = iVar21 + 4;
      iVar18 = iVar18 + 1;
    } while (iVar18 < 4);
    if (iVar17 < 1) {
      uVar6 = 0xffffffff;
    }
    else {
      iVar5 = 0;
      iVar21 = 0;
      if (iVar17 >= 1) {
        do {
          if (*pfVar15 < local_6d8[iVar5]) {
            iVar5 = iVar21;
          }
          pfVar15 = pfVar15 + 1;
          iVar21 = iVar21 + 1;
          iVar17 = iVar17 + -1;
        } while (iVar17 != 0);
      }
      if (param_4 != (int *)0x0) {
        *param_4 = (int)local_6e4[iVar5];
      }
      uVar6 = local_6c8[iVar5];
    }
  }
  __psq_l0(auStack8,uVar28);
  __psq_l1(auStack8,uVar28);
  FUN_802860f4(uVar6);
  return;
}

