// Function: FUN_80068748
// Entry: 80068748
// Size: 3060 bytes

/* WARNING: Removing unreachable block (ram,0x8006931c) */
/* WARNING: Removing unreachable block (ram,0x80069314) */
/* WARNING: Removing unreachable block (ram,0x80068f54) */
/* WARNING: Removing unreachable block (ram,0x80068f64) */
/* WARNING: Removing unreachable block (ram,0x80068760) */
/* WARNING: Removing unreachable block (ram,0x80068758) */
/* WARNING: Removing unreachable block (ram,0x8006903c) */
/* WARNING: Removing unreachable block (ram,0x80069044) */
/* WARNING: Removing unreachable block (ram,0x80068f5c) */
/* WARNING: Removing unreachable block (ram,0x80069034) */

void FUN_80068748(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5,
                 int param_6,int param_7,uint param_8,char param_9)

{
  short sVar1;
  short sVar2;
  bool bVar3;
  uint uVar4;
  uint uVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  ushort *puVar10;
  ushort *puVar11;
  short *psVar12;
  undefined uVar13;
  float *pfVar14;
  uint uVar15;
  int iVar16;
  uint uVar17;
  int iVar18;
  int iVar19;
  int *piVar20;
  float *pfVar21;
  int *piVar22;
  int iVar23;
  int iVar24;
  int *piVar25;
  int *piVar26;
  int iVar27;
  uint uVar28;
  int *piVar29;
  byte bVar30;
  int iVar31;
  int iVar32;
  int iVar33;
  ushort *puVar34;
  int iVar35;
  float *pfVar36;
  int iVar37;
  int iVar38;
  double dVar39;
  double dVar40;
  double dVar41;
  double in_f30;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar42;
  uint local_1b8;
  uint local_1b0;
  uint local_1ac;
  uint local_1a4;
  uint uStack_1a0;
  uint local_19c;
  uint local_198;
  float local_194;
  float local_190;
  float local_18c;
  float local_188;
  float local_184;
  float local_180;
  float local_17c [3];
  float afStack_170 [3];
  float afStack_164 [3];
  float afStack_158 [3];
  float afStack_14c [3];
  int local_140 [16];
  undefined4 local_100;
  uint uStack_fc;
  longlong local_f8;
  undefined4 local_f0;
  uint uStack_ec;
  longlong local_e8;
  undefined4 local_e0;
  uint uStack_dc;
  longlong local_d8;
  undefined4 local_d0;
  uint uStack_cc;
  longlong local_c8;
  uint local_c0;
  uint local_bc;
  undefined local_b8;
  ushort *local_b4;
  uint local_b0;
  int local_ac;
  int local_a8;
  int local_a4;
  int local_a0;
  int *local_9c;
  int *local_98;
  uint local_94;
  uint local_90;
  uint local_8c;
  uint local_88;
  uint local_84;
  uint local_80;
  uint local_7c;
  uint local_78;
  uint local_74;
  undefined4 *local_70;
  int local_6c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar42 = FUN_8028680c();
  pfVar21 = (float *)((ulonglong)uVar42 >> 0x20);
  uVar4 = (int)uVar42 - DAT_803dda48;
  uVar5 = param_4 - DAT_803dda4c;
  local_1ac = param_5 - DAT_803dda48;
  local_1a4 = param_7 - DAT_803dda4c;
  local_1b8 = uVar4;
  if ((int)local_1ac < (int)uVar4) {
    local_1b8 = local_1ac;
    local_1ac = uVar4;
  }
  local_1b0 = uVar5;
  if ((int)local_1a4 < (int)uVar5) {
    local_1b0 = local_1a4;
    local_1a4 = uVar5;
  }
  uStack_fc = local_1b8 ^ 0x80000000;
  local_100 = 0x43300000;
  dVar39 = (double)FUN_802925a0();
  iVar9 = (int)dVar39;
  local_f8 = (longlong)iVar9;
  uStack_ec = local_1b0 ^ 0x80000000;
  local_f0 = 0x43300000;
  dVar39 = (double)FUN_802925a0();
  iVar23 = (int)dVar39;
  local_e8 = (longlong)iVar23;
  uStack_dc = local_1ac ^ 0x80000000;
  local_e0 = 0x43300000;
  dVar39 = (double)FUN_802925a0();
  local_d8 = (longlong)(int)dVar39;
  uStack_cc = local_1a4 ^ 0x80000000;
  local_d0 = 0x43300000;
  dVar40 = (double)FUN_802925a0();
  local_c8 = (longlong)(int)dVar40;
  iVar31 = 0;
  iVar33 = 0;
  piVar29 = local_140;
  piVar6 = &DAT_8038eaa4;
  local_9c = &DAT_8038eaa4;
  local_98 = piVar29;
  do {
    iVar27 = iVar9 * 0x280;
    piVar20 = piVar29;
    piVar22 = piVar6;
    iVar37 = iVar9;
    while ((iVar37 <= (int)dVar39 && (iVar31 < 0x10))) {
      iVar24 = iVar23 * 0x280;
      piVar25 = piVar20;
      piVar26 = piVar22;
      iVar35 = iVar23;
      while ((iVar35 <= (int)dVar40 && (iVar31 < 0x10))) {
        iVar8 = FUN_8005b0a8(iVar37,iVar35,iVar33);
        if (iVar8 != 0) {
          *piVar20 = iVar8;
          *piVar22 = iVar27;
          piVar22[2] = iVar24;
          piVar20 = piVar20 + 1;
          piVar22 = piVar22 + 3;
          piVar25 = piVar25 + 1;
          piVar26 = piVar26 + 3;
          piVar29 = piVar29 + 1;
          piVar6 = piVar6 + 3;
          iVar31 = iVar31 + 1;
        }
        iVar24 = iVar24 + 0x280;
        iVar35 = iVar35 + 1;
      }
      iVar27 = iVar27 + 0x280;
      iVar37 = iVar37 + 1;
      piVar20 = piVar25;
      piVar22 = piVar26;
    }
    iVar33 = iVar33 + 1;
  } while (iVar33 < 5);
  if (iVar31 != 0) {
    iVar9 = FUN_80060858(local_140[0],0);
    local_c0 = 0;
    local_198 = 0;
    FUN_8001fa3c(iVar9,(uint)*(ushort *)(local_140[0] + 0x98) << 3,&local_198,&local_19c,0x2000);
    FUN_8001fa3c(*(undefined4 *)(local_140[0] + 0x58),(uint)*(ushort *)(local_140[0] + 0x90) * 6,
                 &local_19c,&uStack_1a0,0x2000);
    local_70 = &DAT_8038eaa4;
    local_78 = param_8 & 0x40;
    local_7c = param_8 & 0x80;
    local_80 = param_8 & 0x200;
    local_84 = param_8 & 0x120;
    local_88 = param_8 & 0x20;
    local_8c = param_8 & 8;
    local_90 = param_8 & 0x100;
    local_94 = param_8 & 4;
    local_6c = iVar31 + -1;
    for (local_ac = 0; uVar4 = local_19c, local_ac < iVar31; local_ac = local_ac + 1) {
      local_bc = local_198;
      if (local_ac < local_6c) {
        iVar23 = local_98[1];
        local_c0 = local_c0 ^ 0x2000;
        uVar5 = local_c0 + 0x2000;
        iVar9 = FUN_80060858(iVar23,0);
        local_198 = local_c0;
        iVar9 = FUN_8001fa3c(iVar9,(uint)*(ushort *)(iVar23 + 0x98) << 3,&local_198,&local_19c,uVar5
                            );
        iVar23 = FUN_8001fa3c(*(undefined4 *)(iVar23 + 0x58),(uint)*(ushort *)(iVar23 + 0x90) * 6,
                              &local_19c,&uStack_1a0,uVar5);
        FUN_80022a88(iVar9 + iVar23 & 0xff);
      }
      else {
        FUN_80022a88(0);
      }
      iVar23 = *local_98;
      iVar9 = *local_9c;
      local_a0 = local_1b8 - iVar9;
      local_a8 = local_1ac - iVar9;
      local_a4 = local_1b0 - local_9c[2];
      iVar33 = local_1a4 - local_9c[2];
      *local_9c = iVar9 + DAT_803dda48;
      local_9c[2] = local_9c[2] + DAT_803dda4c;
      if (local_a0 < 0) {
        local_a0 = 0;
      }
      if (0x280 < local_a8) {
        local_a8 = 0x280;
      }
      if (local_a4 < 0) {
        local_a4 = 0;
      }
      if (0x280 < iVar33) {
        iVar33 = 0x280;
      }
      sVar1 = (short)*local_9c - (short)*local_70;
      sVar2 = (short)local_9c[2] - (short)local_70[2];
      uVar5 = 0;
      uVar15 = 1;
      iVar9 = 0;
      iVar37 = 2;
      do {
        if ((local_a0 <= iVar9 + 0x50) && (iVar9 <= local_a8)) {
          uVar5 = uVar5 | uVar15;
        }
        uVar15 = (uint)(short)((int)(short)uVar15 << 1);
        if ((local_a0 <= iVar9 + 0xa0) && (iVar9 + 0x50 <= local_a8)) {
          uVar5 = uVar5 | uVar15;
        }
        uVar15 = (uint)(short)(uVar15 << 1);
        if ((local_a0 <= iVar9 + 0xf0) && (iVar9 + 0xa0 <= local_a8)) {
          uVar5 = uVar5 | uVar15;
        }
        uVar15 = (uint)(short)(uVar15 << 1);
        if ((local_a0 <= iVar9 + 0x140) && (iVar9 + 0xf0 <= local_a8)) {
          uVar5 = uVar5 | uVar15;
        }
        uVar15 = (uint)(short)(uVar15 << 1);
        iVar9 = iVar9 + 0x140;
        iVar37 = iVar37 + -1;
      } while (iVar37 != 0);
      iVar9 = 0;
      iVar37 = 2;
      do {
        if ((local_a4 <= iVar9 + 0x50) && (iVar9 <= iVar33)) {
          uVar5 = uVar5 | uVar15;
        }
        uVar15 = (uint)(short)((int)(short)uVar15 << 1);
        if ((local_a4 <= iVar9 + 0xa0) && (iVar9 + 0x50 <= iVar33)) {
          uVar5 = uVar5 | uVar15;
        }
        uVar15 = (uint)(short)(uVar15 << 1);
        if ((local_a4 <= iVar9 + 0xf0) && (iVar9 + 0xa0 <= iVar33)) {
          uVar5 = uVar5 | uVar15;
        }
        uVar15 = (uint)(short)(uVar15 << 1);
        if ((local_a4 <= iVar9 + 0x140) && (iVar9 + 0xf0 <= iVar33)) {
          uVar5 = uVar5 | uVar15;
        }
        uVar15 = (uint)(short)(uVar15 << 1);
        iVar9 = iVar9 + 0x140;
        iVar37 = iVar37 + -1;
      } while (iVar37 != 0);
      puVar11 = *(ushort **)(iVar23 + 0x50);
      local_b4 = puVar11 + (uint)*(ushort *)(iVar23 + 0x9a) * 10;
      local_74 = (uint)(short)uVar5;
      for (; puVar11 < local_b4; puVar11 = puVar11 + 10) {
        uVar5 = *(uint *)(puVar11 + 8);
        if ((((uVar5 & 0x10) == 0) || (local_78 == 0)) && (((uVar5 & 4) != 0 || (local_7c == 0)))) {
          if ((uVar5 & 8) == 0) {
            if (((uVar5 & 2) == 0) || (local_88 != 0)) {
              bVar30 = 2;
              goto LAB_80068e30;
            }
          }
          else if (((uVar5 & 1) == 0) && (local_80 == 0)) {
            bVar30 = 4;
            if (local_84 == 0) {
              bVar30 = 0x14;
            }
LAB_80068e30:
            if (((((int)(short)puVar11[3] + (int)*(short *)(iVar23 + 0x8e) <= param_6) &&
                 (param_3 <= (int)(short)puVar11[4] + (int)*(short *)(iVar23 + 0x8e))) &&
                ((short)puVar11[1] <= local_a8)) &&
               (((local_a0 <= (short)puVar11[2] && ((short)puVar11[5] <= iVar33)) &&
                (local_a4 <= (short)puVar11[6])))) {
              if ((uVar5 & 4) != 0) {
                bVar30 = bVar30 | 8;
              }
              uVar5 = FUN_800607e4((int)puVar11);
              local_b8 = (undefined)uVar5;
              uVar5 = (uint)*puVar11;
              puVar34 = (ushort *)(local_bc + uVar5 * 8);
              local_b0 = (uint)puVar11[10];
              for (; (int)uVar5 < (int)local_b0; uVar5 = uVar5 + 1) {
                if (((local_74 & puVar34[3] & 0xff) != 0) && ((local_74 & puVar34[3] & 0xff00) != 0)
                   ) {
                  psVar12 = (short *)(uVar4 + (uint)*puVar34 * 6);
                  iVar9 = (int)*psVar12 >> 3;
                  iVar27 = ((int)psVar12[1] >> 3) + (int)*(short *)(iVar23 + 0x8e);
                  iVar24 = (int)psVar12[2] >> 3;
                  *(short *)(pfVar21 + 4) = (short)iVar9 + sVar1;
                  *(short *)((int)pfVar21 + 0x16) = (short)iVar27;
                  *(short *)(pfVar21 + 7) = (short)iVar24 + sVar2;
                  local_188 = (float)(double)((longlong)(double)*(short *)(pfVar21 + 4) *
                                             0x3ff0000000000000);
                  local_184 = (float)(double)((longlong)(double)*(short *)((int)pfVar21 + 0x16) *
                                             0x3ff0000000000000);
                  local_180 = (float)(double)((longlong)(double)*(short *)(pfVar21 + 7) *
                                             0x3ff0000000000000);
                  uVar15 = 0;
                  uVar28 = 0;
                  uVar17 = 1;
                  pfVar14 = local_17c;
                  iVar38 = 2;
                  iVar37 = iVar9;
                  iVar35 = iVar27;
                  iVar8 = iVar24;
                  puVar10 = puVar34;
                  pfVar36 = pfVar21;
                  do {
                    puVar10 = puVar10 + 1;
                    psVar12 = (short *)(uVar4 + (uint)*puVar10 * 6);
                    iVar7 = (int)*psVar12 >> 3;
                    iVar18 = ((int)psVar12[1] >> 3) + (int)*(short *)(iVar23 + 0x8e);
                    iVar16 = (int)psVar12[2] >> 3;
                    iVar19 = iVar7;
                    if ((iVar7 <= iVar37) && (iVar19 = iVar37, iVar7 < iVar9)) {
                      iVar9 = iVar7;
                    }
                    if (iVar35 < iVar18) {
                      uVar15 = uVar17 & 0xff;
                      iVar35 = iVar18;
                    }
                    else if (iVar18 < iVar27) {
                      uVar28 = uVar17 & 0xff;
                      iVar27 = iVar18;
                    }
                    iVar32 = iVar16;
                    if ((iVar16 <= iVar8) && (iVar32 = iVar8, iVar16 < iVar24)) {
                      iVar24 = iVar16;
                    }
                    *(short *)((int)pfVar36 + 0x12) = (short)iVar7 + sVar1;
                    *(short *)(pfVar36 + 6) = (short)iVar18;
                    *(short *)((int)pfVar36 + 0x1e) = (short)iVar16 + sVar2;
                    *pfVar14 = (float)(double)((longlong)(double)*(short *)((int)pfVar36 + 0x12) *
                                              0x3ff0000000000000);
                    pfVar14[1] = (float)(double)((longlong)(double)*(short *)(pfVar36 + 6) *
                                                0x3ff0000000000000);
                    pfVar14[2] = (float)(double)((longlong)(double)*(short *)((int)pfVar36 + 0x1e) *
                                                0x3ff0000000000000);
                    pfVar14 = pfVar14 + 3;
                    uVar17 = uVar17 + 1;
                    iVar38 = iVar38 + -1;
                    iVar37 = iVar19;
                    iVar8 = iVar32;
                    pfVar36 = (float *)((int)pfVar36 + 2);
                  } while (iVar38 != 0);
                  if ((((iVar27 <= param_6) && (param_3 <= iVar35)) && (iVar9 <= local_a8)) &&
                     (((local_a0 <= iVar19 && (iVar24 <= iVar33)) && (local_a4 <= iVar32)))) {
                    FUN_80247eb8(&local_188,local_17c,afStack_164);
                    FUN_80247eb8(local_17c,afStack_170,afStack_158);
                    FUN_80247fb0(afStack_164,afStack_158,pfVar21 + 1);
                    dVar39 = FUN_80247f54(pfVar21 + 1);
                    if (((double)FLOAT_803df934 < dVar39) &&
                       ((((FUN_80247edc((double)(float)((double)FLOAT_803df944 / dVar39),pfVar21 + 1
                                        ,pfVar21 + 1), local_8c == 0 ||
                          ((pfVar21[2] < FLOAT_803df930 && (FLOAT_803df96c < pfVar21[2])))) ||
                         ((bVar30 == 4 && (local_90 != 0)))) &&
                        (((local_94 == 0 || (FLOAT_803df930 <= pfVar21[2])) ||
                         (pfVar21[2] <= FLOAT_803df96c)))))) {
                      dVar39 = FUN_80247f90(pfVar21 + 1,&local_188);
                      *pfVar21 = (float)-dVar39;
                      if (param_9 != '\0') {
                        FUN_80247eb8(afStack_170,&local_188,afStack_14c);
                        bVar3 = false;
                        iVar37 = 0;
                        pfVar36 = afStack_164;
                        dVar39 = (double)FLOAT_803df934;
                        dVar40 = (double)FLOAT_803df944;
                        iVar9 = 0;
                        do {
                          FUN_80247fb0(pfVar21 + 1,pfVar36,&local_194);
                          dVar41 = FUN_80247f54(&local_194);
                          if (dVar41 <= dVar39) {
                            bVar3 = true;
                            break;
                          }
                          FUN_80247edc((double)(float)(dVar40 / dVar41),&local_194,&local_194);
                          pfVar21[iVar9 + 9] = local_194;
                          pfVar21[iVar9 + 10] = local_190;
                          pfVar21[iVar9 + 0xb] = local_18c;
                          pfVar36 = pfVar36 + 3;
                          iVar37 = iVar37 + 1;
                          iVar9 = iVar9 + 3;
                        } while (iVar37 < 3);
                        if (bVar3) goto LAB_800692bc;
                      }
                      uVar13 = local_b8;
                      if ((*(uint *)(puVar11 + 8) & 8) != 0) {
                        uVar13 = 0xe;
                      }
                      if ((*(uint *)(puVar11 + 8) & 0x20) != 0) {
                        bVar30 = bVar30 | 0x40;
                      }
                      *(undefined *)(pfVar21 + 0x12) = uVar13;
                      *(byte *)((int)pfVar21 + 0x4a) = (byte)(uVar15 << 4) | (byte)uVar28;
                      *(byte *)((int)pfVar21 + 0x49) = bVar30;
                      pfVar21 = pfVar21 + 0x13;
                      if (DAT_803ddbf0 <= pfVar21) goto LAB_80069314;
                    }
                  }
                }
LAB_800692bc:
                puVar34 = puVar34 + 4;
              }
            }
          }
        }
      }
      local_98 = local_98 + 1;
      local_9c = local_9c + 3;
    }
  }
LAB_80069314:
  FUN_80286858();
  return;
}

