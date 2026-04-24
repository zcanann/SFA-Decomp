// Function: FUN_800d6d5c
// Entry: 800d6d5c
// Size: 2004 bytes

/* WARNING: Removing unreachable block (ram,0x800d7510) */
/* WARNING: Removing unreachable block (ram,0x800d7508) */
/* WARNING: Removing unreachable block (ram,0x800d7500) */
/* WARNING: Removing unreachable block (ram,0x800d74f8) */
/* WARNING: Removing unreachable block (ram,0x800d74f0) */
/* WARNING: Removing unreachable block (ram,0x800d74e8) */
/* WARNING: Removing unreachable block (ram,0x800d74e0) */
/* WARNING: Removing unreachable block (ram,0x800d74d8) */
/* WARNING: Removing unreachable block (ram,0x800d74d0) */
/* WARNING: Removing unreachable block (ram,0x800d74c8) */
/* WARNING: Removing unreachable block (ram,0x800d74c0) */
/* WARNING: Removing unreachable block (ram,0x800d6dbc) */
/* WARNING: Removing unreachable block (ram,0x800d6db4) */
/* WARNING: Removing unreachable block (ram,0x800d6dac) */
/* WARNING: Removing unreachable block (ram,0x800d6da4) */
/* WARNING: Removing unreachable block (ram,0x800d6d9c) */
/* WARNING: Removing unreachable block (ram,0x800d6d94) */
/* WARNING: Removing unreachable block (ram,0x800d6d8c) */
/* WARNING: Removing unreachable block (ram,0x800d6d84) */
/* WARNING: Removing unreachable block (ram,0x800d6d7c) */
/* WARNING: Removing unreachable block (ram,0x800d6d74) */
/* WARNING: Removing unreachable block (ram,0x800d6d6c) */

void FUN_800d6d5c(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  float *pfVar8;
  char *pcVar9;
  int iVar10;
  char *pcVar11;
  undefined4 *puVar12;
  int iVar13;
  uint uVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double in_f21;
  double dVar22;
  double in_f22;
  double in_f23;
  double in_f24;
  double in_f25;
  double in_f26;
  double dVar23;
  double in_f27;
  double dVar24;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps21_1;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar25;
  int local_2c8;
  int local_2c4;
  char local_2c0 [200];
  int local_1f8 [64];
  undefined4 local_f8;
  uint uStack_f4;
  undefined4 local_f0;
  uint uStack_ec;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
  float local_a8;
  float fStack_a4;
  float local_98;
  float fStack_94;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  local_98 = (float)in_f22;
  fStack_94 = (float)in_ps22_1;
  local_a8 = (float)in_f21;
  fStack_a4 = (float)in_ps21_1;
  uVar25 = FUN_8028682c();
  iVar6 = (int)((ulonglong)uVar25 >> 0x20);
  pfVar8 = (float *)uVar25;
  iVar10 = 0;
  if (0 < DAT_803de090) {
    if (8 < DAT_803de090) {
      pcVar9 = local_2c0;
      uVar14 = DAT_803de090 - 1U >> 3;
      if (0 < DAT_803de090 + -8) {
        do {
          *pcVar9 = '\0';
          pcVar9[1] = '\0';
          pcVar9[2] = '\0';
          pcVar9[3] = '\0';
          pcVar9[4] = '\0';
          pcVar9[5] = '\0';
          pcVar9[6] = '\0';
          pcVar9[7] = '\0';
          pcVar9 = pcVar9 + 8;
          iVar10 = iVar10 + 8;
          uVar14 = uVar14 - 1;
        } while (uVar14 != 0);
      }
    }
    pcVar9 = local_2c0 + iVar10;
    iVar4 = DAT_803de090 - iVar10;
    if (iVar10 < DAT_803de090) {
      do {
        *pcVar9 = '\0';
        pcVar9 = pcVar9 + 1;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  iVar10 = FUN_800d57bc((uint)pfVar8[4],&local_2c4);
  if (iVar10 == 0) {
    iVar4 = 0;
    puVar12 = &DAT_8039d0b8;
    pcVar9 = local_2c0;
    iVar10 = 0;
    for (iVar5 = 0; iVar5 < DAT_803de090; iVar5 = iVar5 + 1) {
      iVar7 = puVar12[1];
      iVar13 = iVar10;
      if ((*pcVar9 == '\0') && ((param_3 == -1 || (*(char *)(iVar7 + 0x28) == param_3)))) {
        in_f25 = (double)(*(float *)(iVar7 + 8) - *(float *)(iVar6 + 0xc));
        fVar1 = *(float *)(iVar7 + 0xc) - *(float *)(iVar6 + 0x10);
        in_f24 = (double)(*(float *)(iVar7 + 0x10) - *(float *)(iVar6 + 0x14));
        if ((float)(in_f24 * in_f24 + (double)(float)(in_f25 * in_f25 + (double)(fVar1 * fVar1))) <
            FLOAT_803e119c) {
          iVar13 = iVar10 + 1;
          local_1f8[iVar10] = iVar5;
          iVar7 = (int)&DAT_8039d0b8 + iVar4;
          pcVar11 = local_2c0 + iVar5;
          iVar10 = DAT_803de090 - iVar5;
          if (iVar5 < DAT_803de090) {
            do {
              if (param_3 == *(char *)(*(int *)(iVar7 + 4) + 0x28)) {
                *pcVar11 = '\x01';
              }
              iVar7 = iVar7 + 8;
              pcVar11 = pcVar11 + 1;
              iVar10 = iVar10 + -1;
            } while (iVar10 != 0);
          }
        }
      }
      puVar12 = puVar12 + 2;
      pcVar9 = pcVar9 + 1;
      iVar4 = iVar4 + 8;
      iVar10 = iVar13;
    }
  }
  else {
    iVar10 = 1;
    local_1f8[0] = local_2c4;
  }
  iVar4 = 0;
  if (0 < DAT_803de090) {
    if (8 < DAT_803de090) {
      pcVar9 = local_2c0;
      uVar14 = DAT_803de090 - 1U >> 3;
      if (0 < DAT_803de090 + -8) {
        do {
          *pcVar9 = '\0';
          pcVar9[1] = '\0';
          pcVar9[2] = '\0';
          pcVar9[3] = '\0';
          pcVar9[4] = '\0';
          pcVar9[5] = '\0';
          pcVar9[6] = '\0';
          pcVar9[7] = '\0';
          pcVar9 = pcVar9 + 8;
          iVar4 = iVar4 + 8;
          uVar14 = uVar14 - 1;
        } while (uVar14 != 0);
      }
    }
    pcVar9 = local_2c0 + iVar4;
    iVar5 = DAT_803de090 - iVar4;
    if (iVar4 < DAT_803de090) {
      do {
        *pcVar9 = '\0';
        pcVar9 = pcVar9 + 1;
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
  }
  while (0 < iVar10) {
    iVar10 = iVar10 + -1;
    local_2c4 = local_1f8[iVar10];
    iVar4 = (&DAT_8039d0bc)[local_2c4 * 2];
    if (iVar4 == 0) goto LAB_800d74c0;
    iVar13 = 0;
    iVar5 = iVar4;
    do {
      iVar7 = FUN_800d57bc(*(uint *)(iVar5 + 0x20),&local_2c8);
      if (iVar7 != 0) {
        uStack_f4 = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
        local_f8 = 0x43300000;
        dVar15 = (double)FUN_802945e0();
        uStack_ec = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
        local_f0 = 0x43300000;
        dVar16 = (double)FUN_80294964();
        dVar22 = -(double)(float)((double)*(float *)(iVar4 + 8) * dVar15 +
                                 (double)(float)((double)*(float *)(iVar4 + 0x10) * dVar16));
        uStack_e4 = (uint)*(byte *)(iVar7 + 0x29) << 8 ^ 0x80000000;
        local_e8 = 0x43300000;
        dVar17 = (double)FUN_802945e0();
        uStack_dc = (uint)*(byte *)(iVar7 + 0x29) << 8 ^ 0x80000000;
        local_e0 = 0x43300000;
        dVar18 = (double)FUN_80294964();
        dVar20 = (double)*(float *)(iVar7 + 8);
        dVar19 = (double)*(float *)(iVar7 + 0x10);
        fVar1 = -(float)(dVar20 * dVar17 + (double)(float)(dVar19 * dVar18));
        dVar24 = (double)(float)(dVar22 + (double)(float)(dVar15 * (double)*(float *)(iVar6 + 0xc) +
                                                         (double)(float)(dVar16 * (double)*(float *)
                                                  (iVar6 + 0x14))));
        dVar23 = (double)(fVar1 + (float)(dVar17 * (double)*(float *)(iVar6 + 0xc) +
                                         (double)(float)(dVar18 * (double)*(float *)(iVar6 + 0x14)))
                         );
        dVar22 = (double)(float)(dVar22 + (double)(float)(dVar15 * dVar20 +
                                                         (double)(float)(dVar16 * dVar19)));
        dVar21 = (double)(fVar1 + (float)(dVar17 * (double)*(float *)(iVar4 + 8) +
                                         (double)(float)(dVar18 * (double)*(float *)(iVar4 + 0x10)))
                         );
        if ((((dVar22 <= (double)FLOAT_803e1168) && (dVar24 <= (double)FLOAT_803e1168)) ||
            (((double)FLOAT_803e1168 < dVar22 && ((double)FLOAT_803e1168 < dVar24)))) &&
           (((dVar21 <= (double)FLOAT_803e1168 && (dVar23 <= (double)FLOAT_803e1168)) ||
            (((double)FLOAT_803e1168 < dVar21 && ((double)FLOAT_803e1168 < dVar23)))))) {
          dVar21 = (double)(float)((double)*(float *)(iVar4 + 8) - dVar20);
          dVar22 = (double)(*(float *)(iVar4 + 0xc) - *(float *)(iVar7 + 0xc));
          dVar20 = (double)(float)((double)*(float *)(iVar4 + 0x10) - dVar19);
          dVar19 = FUN_80293900((double)(float)(dVar20 * dVar20 +
                                               (double)(float)(dVar21 * dVar21 +
                                                              (double)(float)(dVar22 * dVar22))));
          if (DOUBLE_803e11a0 < dVar19) {
            in_f25 = (double)(float)(dVar21 * (double)(float)((double)FLOAT_803e1184 / dVar19));
            in_f24 = (double)(float)(dVar20 * (double)(float)((double)FLOAT_803e1184 / dVar19));
          }
          fVar1 = (float)(-dVar24 /
                         (double)(float)(dVar15 * in_f25 + (double)(float)(dVar16 * in_f24)));
          fVar2 = fVar1 + (float)(dVar23 / (double)(float)(dVar17 * in_f25 +
                                                          (double)(float)(dVar18 * in_f24)));
          if ((FLOAT_803e11a8 < fVar2) || (fVar3 = FLOAT_803e1168, fVar2 < FLOAT_803e11ac)) {
            fVar3 = fVar1 / fVar2;
          }
          dVar15 = (double)fVar3;
          if ((double)fVar3 < (double)FLOAT_803e1168) {
            dVar15 = (double)FLOAT_803e1168;
          }
          if ((double)FLOAT_803e1198 <= dVar15) {
            dVar15 = (double)FLOAT_803e1198;
          }
          uStack_dc = (uint)*(byte *)(iVar4 + 0x2a);
          local_e0 = 0x43300000;
          dVar16 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x2a)) -
                                  DOUBLE_803e1178);
          uStack_e4 = (uint)*(byte *)(iVar7 + 0x2a);
          local_e8 = 0x43300000;
          fVar1 = (float)(dVar15 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    (uint)*(byte *)(
                                                  iVar7 + 0x2a)) - DOUBLE_803e1178) - dVar16) +
                         dVar16);
          fVar2 = (*(float *)(iVar6 + 0x10) -
                  -(float)(dVar22 * dVar15 - (double)*(float *)(iVar4 + 0xc))) / fVar1;
          fVar1 = (-(float)(-(double)(float)(dVar21 * dVar15 - (double)*(float *)(iVar4 + 8)) *
                            in_f24 - (double)(float)(-(double)(float)(dVar20 * dVar15 -
                                                                     (double)*(float *)(iVar4 + 0x10
                                                                                       )) * in_f25))
                  + (float)((double)*(float *)(iVar6 + 0xc) * in_f24 -
                           (double)(float)((double)*(float *)(iVar6 + 0x14) * in_f25))) / fVar1;
          if ((((FLOAT_803e11b0 <= fVar1) && (fVar1 <= FLOAT_803e11b4)) && (FLOAT_803e11b8 <= fVar2)
              ) && (fVar2 <= FLOAT_803e11b4)) {
            pfVar8[4] = *(float *)(iVar4 + 0x14);
            pfVar8[5] = *(float *)(iVar4 + 0x14);
            *pfVar8 = fVar1;
            pfVar8[1] = fVar2;
            pfVar8[2] = (float)dVar15;
            *(short *)(pfVar8 + 8) = (short)*(char *)(iVar4 + 0x28);
            goto LAB_800d74c0;
          }
        }
      }
      iVar5 = iVar5 + 4;
      iVar13 = iVar13 + 1;
    } while (iVar13 < 2);
    if (local_2c0[local_2c4] == '\0') {
      iVar5 = 1;
      iVar4 = iVar4 + 4;
      do {
        iVar7 = FUN_800d57bc(*(uint *)(iVar4 + 0x18),&local_2c8);
        iVar13 = iVar10;
        if (((iVar7 != 0) && (local_2c0[local_2c8] == '\0')) && (iVar10 < 0x3c)) {
          iVar13 = iVar10 + 1;
          local_1f8[iVar10] = local_2c8;
        }
        iVar7 = FUN_800d57bc(*(uint *)(iVar4 + 0x20),&local_2c8);
        iVar10 = iVar13;
        if (((iVar7 != 0) && (local_2c0[local_2c8] == '\0')) && (iVar13 < 0x3c)) {
          iVar10 = iVar13 + 1;
          local_1f8[iVar13] = local_2c8;
        }
        iVar4 = iVar4 + -4;
        iVar5 = iVar5 + -1;
      } while (-1 < iVar5);
      local_2c0[local_2c4] = '\x01';
    }
  }
  pfVar8[4] = -NAN;
LAB_800d74c0:
  FUN_80286878();
  return;
}

