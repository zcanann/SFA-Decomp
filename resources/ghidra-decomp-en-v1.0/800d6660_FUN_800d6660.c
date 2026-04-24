// Function: FUN_800d6660
// Entry: 800d6660
// Size: 1136 bytes

/* WARNING: Removing unreachable block (ram,0x800d6aa8) */
/* WARNING: Removing unreachable block (ram,0x800d6a98) */
/* WARNING: Removing unreachable block (ram,0x800d6a88) */
/* WARNING: Removing unreachable block (ram,0x800d6a78) */
/* WARNING: Removing unreachable block (ram,0x800d6a68) */
/* WARNING: Removing unreachable block (ram,0x800d6a70) */
/* WARNING: Removing unreachable block (ram,0x800d6a80) */
/* WARNING: Removing unreachable block (ram,0x800d6a90) */
/* WARNING: Removing unreachable block (ram,0x800d6aa0) */
/* WARNING: Removing unreachable block (ram,0x800d6ab0) */

void FUN_800d6660(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  short sVar7;
  int iVar8;
  undefined4 uVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  undefined8 in_f22;
  undefined8 in_f23;
  double dVar18;
  double in_f24;
  double in_f25;
  undefined8 in_f26;
  double dVar19;
  undefined8 in_f27;
  double dVar20;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar21;
  undefined auStack216 [4];
  undefined auStack212 [4];
  undefined4 local_d0;
  uint uStack204;
  undefined4 local_c8;
  uint uStack196;
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
  
  uVar9 = 0;
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
  uVar21 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar21 >> 0x20);
  iVar8 = (int)uVar21;
  if (*(int *)(iVar8 + 0x18) < 0) {
    *(undefined4 *)(iVar8 + 0x1c) = 0;
    *(float *)(iVar8 + 0xc) = FLOAT_803e04e8;
    if (*(int *)(iVar8 + 0x10) < 0) {
      uVar4 = 0;
      goto LAB_800d6a68;
    }
    *(int *)(iVar8 + 0x18) = *(int *)(iVar8 + 0x10);
  }
  iVar5 = FUN_800d5530(*(undefined4 *)(iVar8 + 0x18),auStack216);
  if (iVar5 == 0) {
    *(undefined4 *)(iVar8 + 0x18) = 0xffffffff;
    uVar4 = 0;
  }
  else {
    uStack204 = (uint)*(byte *)(iVar5 + 0x29) << 8 ^ 0x80000000;
    local_d0 = 0x43300000;
    dVar10 = (double)FUN_80293e80((double)((FLOAT_803e04d8 *
                                           (float)((double)CONCAT44(0x43300000,uStack204) -
                                                  DOUBLE_803e04f0)) / FLOAT_803e04dc));
    uStack196 = (uint)*(byte *)(iVar5 + 0x29) << 8 ^ 0x80000000;
    local_c8 = 0x43300000;
    dVar11 = (double)FUN_80294204((double)((FLOAT_803e04d8 *
                                           (float)((double)CONCAT44(0x43300000,uStack196) -
                                                  DOUBLE_803e04f0)) / FLOAT_803e04dc));
    dVar18 = -(double)(float)((double)*(float *)(iVar5 + 8) * dVar10 +
                             (double)(float)((double)*(float *)(iVar5 + 0x10) * dVar11));
    dVar20 = (double)(float)(dVar18 + (double)(float)(dVar10 * (double)*(float *)(iVar3 + 0xc) +
                                                     (double)(float)(dVar11 * (double)*(float *)(
                                                  iVar3 + 0x14))));
    if ((*(int *)(iVar5 + 0x18) < 0) || (dVar20 < (double)FLOAT_803e04e8)) {
      if (*(int *)(iVar5 + 0x20) < 0) {
        uVar4 = (uint)*(byte *)(iVar5 + 0x29);
      }
      else {
        iVar6 = FUN_800d5530(*(int *)(iVar5 + 0x20),auStack212);
        sVar7 = FUN_800217c0((double)(*(float *)(iVar6 + 8) - *(float *)(iVar5 + 8)),
                             (double)(*(float *)(iVar6 + 0x10) - *(float *)(iVar5 + 0x10)));
        uVar4 = (uint)sVar7;
        uStack196 = (uint)*(byte *)(iVar6 + 0x29) << 8 ^ 0x80000000;
        local_c8 = 0x43300000;
        dVar12 = (double)FUN_80293e80((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack196) -
                                                      DOUBLE_803e04f0)) / FLOAT_803e04dc));
        uStack204 = (uint)*(byte *)(iVar6 + 0x29) << 8 ^ 0x80000000;
        local_d0 = 0x43300000;
        dVar13 = (double)FUN_80294204((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack204) -
                                                      DOUBLE_803e04f0)) / FLOAT_803e04dc));
        fVar2 = FLOAT_803e04e8;
        dVar16 = (double)*(float *)(iVar6 + 8);
        dVar15 = (double)*(float *)(iVar6 + 0x10);
        fVar1 = -(float)(dVar16 * dVar12 + (double)(float)(dVar15 * dVar13));
        dVar19 = (double)(fVar1 + (float)(dVar12 * (double)*(float *)(iVar3 + 0xc) +
                                         (double)(float)(dVar13 * (double)*(float *)(iVar3 + 0x14)))
                         );
        dVar14 = (double)FLOAT_803e04e8;
        if (dVar14 <= dVar19) {
          dVar18 = (double)(float)(dVar18 + (double)(float)(dVar10 * dVar16 +
                                                           (double)(float)(dVar11 * dVar15)));
          dVar17 = (double)(fVar1 + (float)(dVar12 * (double)*(float *)(iVar5 + 8) +
                                           (double)(float)(dVar13 * (double)*(float *)(iVar5 + 0x10)
                                                          )));
          if ((((dVar18 < dVar14) && (dVar20 < dVar14)) ||
              (((double)FLOAT_803e04e8 <= dVar18 && ((double)FLOAT_803e04e8 <= dVar20)))) &&
             (((dVar17 <= (double)FLOAT_803e04e8 && (dVar19 <= (double)FLOAT_803e04e8)) ||
              (((double)FLOAT_803e04e8 < dVar17 && ((double)FLOAT_803e04e8 < dVar19)))))) {
            dVar16 = (double)(float)((double)*(float *)(iVar5 + 8) - dVar16);
            fVar1 = *(float *)(iVar5 + 0xc) - *(float *)(iVar6 + 0xc);
            dVar14 = (double)(float)((double)*(float *)(iVar5 + 0x10) - dVar15);
            dVar18 = (double)FUN_802931a0((double)(float)(dVar14 * dVar14 +
                                                         (double)(float)(dVar16 * dVar16 +
                                                                        (double)(fVar1 * fVar1))));
            if ((double)FLOAT_803e04e8 < dVar18) {
              in_f25 = (double)(float)(dVar16 * (double)(float)((double)FLOAT_803e0504 / dVar18));
              in_f24 = (double)(float)(dVar14 * (double)(float)((double)FLOAT_803e0504 / dVar18));
            }
            dVar10 = (double)(float)(dVar10 * in_f25 + (double)(float)(dVar11 * in_f24));
            if ((dVar10 <= (double)FLOAT_803e0510) || ((double)FLOAT_803e0514 <= dVar10)) {
              dVar11 = (double)(float)(dVar12 * in_f25 + (double)(float)(dVar13 * in_f24));
              if ((dVar11 <= (double)FLOAT_803e0510) || ((double)FLOAT_803e0514 <= dVar11)) {
                fVar1 = (float)(-dVar20 / dVar10) + (float)(dVar19 / dVar11);
                fVar2 = FLOAT_803e04e8;
                if (FLOAT_803e04e8 != fVar1) {
                  fVar2 = (float)(-dVar20 / dVar10) / fVar1;
                }
                *(float *)(iVar8 + 0xc) = fVar2;
                if (*(float *)(iVar8 + 0xc) < FLOAT_803e04e8) {
                  *(float *)(iVar8 + 0xc) = FLOAT_803e04e8;
                }
                if (FLOAT_803e0518 <= *(float *)(iVar8 + 0xc)) {
                  *(float *)(iVar8 + 0xc) = FLOAT_803e0518;
                }
              }
            }
          }
        }
        else {
          *(undefined4 *)(iVar8 + 0x18) = *(undefined4 *)(iVar5 + 0x20);
          *(float *)(iVar8 + 0xc) = fVar2;
          *(int *)(iVar8 + 0x1c) = *(int *)(iVar8 + 0x1c) + 1;
        }
      }
    }
    else {
      *(int *)(iVar8 + 0x18) = *(int *)(iVar5 + 0x18);
      *(float *)(iVar8 + 0xc) = FLOAT_803e050c;
      *(int *)(iVar8 + 0x1c) = *(int *)(iVar8 + 0x1c) + -1;
      uVar4 = (uint)*(byte *)(iVar5 + 0x29);
    }
  }
LAB_800d6a68:
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  __psq_l0(auStack56,uVar9);
  __psq_l1(auStack56,uVar9);
  __psq_l0(auStack72,uVar9);
  __psq_l1(auStack72,uVar9);
  __psq_l0(auStack88,uVar9);
  __psq_l1(auStack88,uVar9);
  __psq_l0(auStack104,uVar9);
  __psq_l1(auStack104,uVar9);
  __psq_l0(auStack120,uVar9);
  __psq_l1(auStack120,uVar9);
  __psq_l0(auStack136,uVar9);
  __psq_l1(auStack136,uVar9);
  __psq_l0(auStack152,uVar9);
  __psq_l1(auStack152,uVar9);
  FUN_80286128(uVar4);
  return;
}

