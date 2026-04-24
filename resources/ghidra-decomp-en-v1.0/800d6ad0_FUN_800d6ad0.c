// Function: FUN_800d6ad0
// Entry: 800d6ad0
// Size: 2004 bytes

/* WARNING: Removing unreachable block (ram,0x800d727c) */
/* WARNING: Removing unreachable block (ram,0x800d726c) */
/* WARNING: Removing unreachable block (ram,0x800d725c) */
/* WARNING: Removing unreachable block (ram,0x800d724c) */
/* WARNING: Removing unreachable block (ram,0x800d723c) */
/* WARNING: Removing unreachable block (ram,0x800d7234) */
/* WARNING: Removing unreachable block (ram,0x800d7244) */
/* WARNING: Removing unreachable block (ram,0x800d7254) */
/* WARNING: Removing unreachable block (ram,0x800d7264) */
/* WARNING: Removing unreachable block (ram,0x800d7274) */
/* WARNING: Removing unreachable block (ram,0x800d7284) */

void FUN_800d6ad0(undefined4 param_1,undefined4 param_2,int param_3)

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
  undefined4 uVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  undefined8 in_f21;
  double dVar23;
  undefined8 in_f22;
  undefined8 in_f23;
  double in_f24;
  double in_f25;
  undefined8 in_f26;
  double dVar24;
  undefined8 in_f27;
  double dVar25;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar26;
  int local_2c8;
  int local_2c4;
  char local_2c0 [200];
  int local_1f8 [64];
  undefined4 local_f8;
  uint uStack244;
  undefined4 local_f0;
  uint uStack236;
  undefined4 local_e8;
  uint uStack228;
  undefined4 local_e0;
  uint uStack220;
  undefined auStack168 [16];
  undefined auStack152 [16];
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,SUB84(in_f25,0),0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,SUB84(in_f24,0),0);
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  __psq_st0(auStack152,(int)((ulonglong)in_f22 >> 0x20),0);
  __psq_st1(auStack152,(int)in_f22,0);
  __psq_st0(auStack168,(int)((ulonglong)in_f21 >> 0x20),0);
  __psq_st1(auStack168,(int)in_f21,0);
  uVar26 = FUN_802860c8();
  iVar6 = (int)((ulonglong)uVar26 >> 0x20);
  pfVar8 = (float *)uVar26;
  iVar10 = 0;
  if (0 < DAT_803dd410) {
    if (8 < DAT_803dd410) {
      pcVar9 = local_2c0;
      uVar14 = DAT_803dd410 - 1U >> 3;
      if (0 < DAT_803dd410 + -8) {
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
    iVar4 = DAT_803dd410 - iVar10;
    if (iVar10 < DAT_803dd410) {
      do {
        *pcVar9 = '\0';
        pcVar9 = pcVar9 + 1;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  iVar10 = FUN_800d5530(pfVar8[4],&local_2c4);
  if (iVar10 == 0) {
    iVar4 = 0;
    puVar12 = &DAT_8039c458;
    pcVar9 = local_2c0;
    iVar10 = 0;
    for (iVar5 = 0; iVar5 < DAT_803dd410; iVar5 = iVar5 + 1) {
      iVar7 = puVar12[1];
      iVar13 = iVar10;
      if ((*pcVar9 == '\0') && ((param_3 == -1 || (*(char *)(iVar7 + 0x28) == param_3)))) {
        in_f25 = (double)(*(float *)(iVar7 + 8) - *(float *)(iVar6 + 0xc));
        fVar1 = *(float *)(iVar7 + 0xc) - *(float *)(iVar6 + 0x10);
        in_f24 = (double)(*(float *)(iVar7 + 0x10) - *(float *)(iVar6 + 0x14));
        if ((float)(in_f24 * in_f24 + (double)(float)(in_f25 * in_f25 + (double)(fVar1 * fVar1))) <
            FLOAT_803e051c) {
          iVar13 = iVar10 + 1;
          local_1f8[iVar10] = iVar5;
          iVar7 = (int)&DAT_8039c458 + iVar4;
          pcVar11 = local_2c0 + iVar5;
          iVar10 = DAT_803dd410 - iVar5;
          if (iVar5 < DAT_803dd410) {
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
  if (0 < DAT_803dd410) {
    if (8 < DAT_803dd410) {
      pcVar9 = local_2c0;
      uVar14 = DAT_803dd410 - 1U >> 3;
      if (0 < DAT_803dd410 + -8) {
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
    iVar5 = DAT_803dd410 - iVar4;
    if (iVar4 < DAT_803dd410) {
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
    iVar4 = (&DAT_8039c45c)[local_2c4 * 2];
    if (iVar4 == 0) goto LAB_800d7234;
    iVar13 = 0;
    iVar5 = iVar4;
    do {
      iVar7 = FUN_800d5530(*(undefined4 *)(iVar5 + 0x20),&local_2c8);
      if (iVar7 != 0) {
        uStack244 = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
        local_f8 = 0x43300000;
        dVar16 = (double)FUN_80293e80((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack244) -
                                                      DOUBLE_803e04f0)) / FLOAT_803e04dc));
        uStack236 = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
        local_f0 = 0x43300000;
        dVar17 = (double)FUN_80294204((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack236) -
                                                      DOUBLE_803e04f0)) / FLOAT_803e04dc));
        dVar23 = -(double)(float)((double)*(float *)(iVar4 + 8) * dVar16 +
                                 (double)(float)((double)*(float *)(iVar4 + 0x10) * dVar17));
        uStack228 = (uint)*(byte *)(iVar7 + 0x29) << 8 ^ 0x80000000;
        local_e8 = 0x43300000;
        dVar18 = (double)FUN_80293e80((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack228) -
                                                      DOUBLE_803e04f0)) / FLOAT_803e04dc));
        uStack220 = (uint)*(byte *)(iVar7 + 0x29) << 8 ^ 0x80000000;
        local_e0 = 0x43300000;
        dVar19 = (double)FUN_80294204((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack220) -
                                                      DOUBLE_803e04f0)) / FLOAT_803e04dc));
        dVar21 = (double)*(float *)(iVar7 + 8);
        dVar20 = (double)*(float *)(iVar7 + 0x10);
        fVar1 = -(float)(dVar21 * dVar18 + (double)(float)(dVar20 * dVar19));
        dVar25 = (double)(float)(dVar23 + (double)(float)(dVar16 * (double)*(float *)(iVar6 + 0xc) +
                                                         (double)(float)(dVar17 * (double)*(float *)
                                                  (iVar6 + 0x14))));
        dVar24 = (double)(fVar1 + (float)(dVar18 * (double)*(float *)(iVar6 + 0xc) +
                                         (double)(float)(dVar19 * (double)*(float *)(iVar6 + 0x14)))
                         );
        dVar23 = (double)(float)(dVar23 + (double)(float)(dVar16 * dVar21 +
                                                         (double)(float)(dVar17 * dVar20)));
        dVar22 = (double)(fVar1 + (float)(dVar18 * (double)*(float *)(iVar4 + 8) +
                                         (double)(float)(dVar19 * (double)*(float *)(iVar4 + 0x10)))
                         );
        if ((((dVar23 <= (double)FLOAT_803e04e8) && (dVar25 <= (double)FLOAT_803e04e8)) ||
            (((double)FLOAT_803e04e8 < dVar23 && ((double)FLOAT_803e04e8 < dVar25)))) &&
           (((dVar22 <= (double)FLOAT_803e04e8 && (dVar24 <= (double)FLOAT_803e04e8)) ||
            (((double)FLOAT_803e04e8 < dVar22 && ((double)FLOAT_803e04e8 < dVar24)))))) {
          dVar22 = (double)(float)((double)*(float *)(iVar4 + 8) - dVar21);
          dVar23 = (double)(*(float *)(iVar4 + 0xc) - *(float *)(iVar7 + 0xc));
          dVar21 = (double)(float)((double)*(float *)(iVar4 + 0x10) - dVar20);
          dVar20 = (double)FUN_802931a0((double)(float)(dVar21 * dVar21 +
                                                       (double)(float)(dVar22 * dVar22 +
                                                                      (double)(float)(dVar23 * 
                                                  dVar23))));
          if (DOUBLE_803e0520 < dVar20) {
            in_f25 = (double)(float)(dVar22 * (double)(float)((double)FLOAT_803e0504 / dVar20));
            in_f24 = (double)(float)(dVar21 * (double)(float)((double)FLOAT_803e0504 / dVar20));
          }
          fVar1 = (float)(-dVar25 /
                         (double)(float)(dVar16 * in_f25 + (double)(float)(dVar17 * in_f24)));
          fVar2 = fVar1 + (float)(dVar24 / (double)(float)(dVar18 * in_f25 +
                                                          (double)(float)(dVar19 * in_f24)));
          if ((FLOAT_803e0528 < fVar2) || (fVar3 = FLOAT_803e04e8, fVar2 < FLOAT_803e052c)) {
            fVar3 = fVar1 / fVar2;
          }
          dVar16 = (double)fVar3;
          if ((double)fVar3 < (double)FLOAT_803e04e8) {
            dVar16 = (double)FLOAT_803e04e8;
          }
          if ((double)FLOAT_803e0518 <= dVar16) {
            dVar16 = (double)FLOAT_803e0518;
          }
          uStack220 = (uint)*(byte *)(iVar4 + 0x2a);
          local_e0 = 0x43300000;
          dVar17 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x2a)) -
                                  DOUBLE_803e04f8);
          uStack228 = (uint)*(byte *)(iVar7 + 0x2a);
          local_e8 = 0x43300000;
          fVar1 = (float)(dVar16 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    (uint)*(byte *)(
                                                  iVar7 + 0x2a)) - DOUBLE_803e04f8) - dVar17) +
                         dVar17);
          fVar2 = (*(float *)(iVar6 + 0x10) -
                  -(float)(dVar23 * dVar16 - (double)*(float *)(iVar4 + 0xc))) / fVar1;
          fVar1 = (-(float)(-(double)(float)(dVar22 * dVar16 - (double)*(float *)(iVar4 + 8)) *
                            in_f24 - (double)(float)(-(double)(float)(dVar21 * dVar16 -
                                                                     (double)*(float *)(iVar4 + 0x10
                                                                                       )) * in_f25))
                  + (float)((double)*(float *)(iVar6 + 0xc) * in_f24 -
                           (double)(float)((double)*(float *)(iVar6 + 0x14) * in_f25))) / fVar1;
          if ((((FLOAT_803e0530 <= fVar1) && (fVar1 <= FLOAT_803e0534)) && (FLOAT_803e0538 <= fVar2)
              ) && (fVar2 <= FLOAT_803e0534)) {
            pfVar8[4] = *(float *)(iVar4 + 0x14);
            pfVar8[5] = *(float *)(iVar4 + 0x14);
            *pfVar8 = fVar1;
            pfVar8[1] = fVar2;
            pfVar8[2] = (float)dVar16;
            *(short *)(pfVar8 + 8) = (short)*(char *)(iVar4 + 0x28);
            goto LAB_800d7234;
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
        iVar7 = FUN_800d5530(*(undefined4 *)(iVar4 + 0x18),&local_2c8);
        iVar13 = iVar10;
        if (((iVar7 != 0) && (local_2c0[local_2c8] == '\0')) && (iVar10 < 0x3c)) {
          iVar13 = iVar10 + 1;
          local_1f8[iVar10] = local_2c8;
        }
        iVar7 = FUN_800d5530(*(undefined4 *)(iVar4 + 0x20),&local_2c8);
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
LAB_800d7234:
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  __psq_l0(auStack40,uVar15);
  __psq_l1(auStack40,uVar15);
  __psq_l0(auStack56,uVar15);
  __psq_l1(auStack56,uVar15);
  __psq_l0(auStack72,uVar15);
  __psq_l1(auStack72,uVar15);
  __psq_l0(auStack88,uVar15);
  __psq_l1(auStack88,uVar15);
  __psq_l0(auStack104,uVar15);
  __psq_l1(auStack104,uVar15);
  __psq_l0(auStack120,uVar15);
  __psq_l1(auStack120,uVar15);
  __psq_l0(auStack136,uVar15);
  __psq_l1(auStack136,uVar15);
  __psq_l0(auStack152,uVar15);
  __psq_l1(auStack152,uVar15);
  __psq_l0(auStack168,uVar15);
  __psq_l1(auStack168,uVar15);
  FUN_80286114();
  return;
}

