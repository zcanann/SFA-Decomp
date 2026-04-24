// Function: FUN_8016dfe0
// Entry: 8016dfe0
// Size: 1780 bytes

/* WARNING: Removing unreachable block (ram,0x8016e6ac) */
/* WARNING: Removing unreachable block (ram,0x8016e69c) */
/* WARNING: Removing unreachable block (ram,0x8016e68c) */
/* WARNING: Removing unreachable block (ram,0x8016e684) */
/* WARNING: Removing unreachable block (ram,0x8016e694) */
/* WARNING: Removing unreachable block (ram,0x8016e6a4) */
/* WARNING: Removing unreachable block (ram,0x8016e6b4) */

void FUN_8016dfe0(void)

{
  uint uVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  int extraout_r4;
  int iVar6;
  int *piVar7;
  short *in_r6;
  float *pfVar8;
  float *pfVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  float *pfVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  int *piVar17;
  int iVar18;
  undefined4 uVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  double dVar23;
  double dVar24;
  undefined8 in_f25;
  double dVar25;
  double dVar26;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar27;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  float local_138 [4];
  float local_128 [4];
  float local_118 [4];
  float local_108 [4];
  float local_f8 [4];
  float local_e8 [4];
  int local_d8 [4];
  double local_c8;
  undefined4 local_c0;
  uint uStack188;
  double local_b8;
  double local_b0;
  double local_a8;
  undefined4 local_a0;
  uint uStack156;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar19 = 0;
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
  __psq_st1(auStack104,(int)in_f25,0);
  FUN_802860c8();
  if ((*(int *)(extraout_r4 + 0x48) != 0) && (*(char *)(extraout_r4 + 0xbc) == '\0')) {
    iVar6 = (int)*in_r6;
    if (*(short **)(in_r6 + 0x18) != (short *)0x0) {
      iVar6 = iVar6 + **(short **)(in_r6 + 0x18);
    }
    local_c8 = (double)CONCAT44(0x43300000,-iVar6 ^ 0x80000000);
    dVar25 = (double)((FLOAT_803e3304 * (float)(local_c8 - DOUBLE_803e3318)) / FLOAT_803e3308);
    dVar21 = (double)FUN_80293e80(dVar25);
    dVar25 = (double)FUN_80294204(dVar25);
    iVar6 = FUN_8002b588(in_r6);
    iVar6 = *(int *)(iVar6 + 0x2c);
    if ((*(int **)(in_r6 + 0x2e) != (int *)0x0) && (0 < **(int **)(in_r6 + 0x2e))) {
      piVar17 = *(int **)(extraout_r4 + 0x48);
      uVar1 = (uint)(FLOAT_803e330c * *(float *)(iVar6 + 0x14));
      local_c8 = (double)(longlong)(int)uVar1;
      dVar26 = (double)((float)piVar17[2] * *(float *)(iVar6 + 0x14));
      if ((*(byte *)(piVar17 + 5) & 1) != 0) {
        *(undefined4 *)(extraout_r4 + 0x8c) = *(undefined4 *)(in_r6 + 0xc);
        *(undefined4 *)(extraout_r4 + 0x90) = *(undefined4 *)(in_r6 + 0xe);
        *(undefined4 *)(extraout_r4 + 0x94) = *(undefined4 *)(in_r6 + 0x10);
        *(float *)(extraout_r4 + 0x98) = FLOAT_803e32b4;
        *(byte *)(piVar17 + 5) = *(byte *)(piVar17 + 5) & 0xfe;
      }
      dVar22 = (double)*(float *)(extraout_r4 + 0x98);
      dVar20 = (double)*(float *)(iVar6 + 4);
      if (dVar26 < dVar22) {
        *(float *)(extraout_r4 + 0x98) = *(float *)(iVar6 + 4);
        goto LAB_8016e684;
      }
      if (dVar26 < dVar20) {
        dVar20 = dVar26;
      }
      iVar16 = *(int *)(*(int *)(in_r6 + 0x2e) + 4);
      if ((double)FLOAT_803e32b4 <= dVar22) {
        dVar22 = (double)FUN_80291e40((double)(float)(dVar22 * (double)FLOAT_803e32a4));
        dVar22 = (double)((float)(dVar22 / (double)FLOAT_803e32a4) * FLOAT_803e330c);
        dVar20 = (double)FUN_80291e40((double)(float)(dVar20 * (double)FLOAT_803e32a4));
        dVar27 = (double)((float)(dVar20 / (double)FLOAT_803e32a4) * FLOAT_803e330c);
        uVar14 = (uint)dVar22;
        local_c8 = (double)(longlong)(int)uVar14;
        uStack188 = uVar14 ^ 0x80000000;
        local_c0 = 0x43300000;
        dVar20 = (double)(float)(dVar22 - (double)(float)((double)CONCAT44(0x43300000,
                                                                           uVar14 ^ 0x80000000) -
                                                         DOUBLE_803e3318));
        uVar15 = (uint)((float)(dVar27 - dVar22) / FLOAT_803e32ac);
        local_b8 = (double)(longlong)(int)uVar15;
        if (uVar15 == 0) {
          if (dVar26 < (double)*(float *)(iVar6 + 4)) {
            *(float *)(extraout_r4 + 0x98) = *(float *)(iVar6 + 4);
          }
          goto LAB_8016e684;
        }
        dVar26 = (double)FLOAT_803e32b4;
        local_b8 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000);
        dVar22 = (double)(FLOAT_803e3288 / (float)(local_b8 - DOUBLE_803e3318));
        bVar4 = true;
        while (uVar15 != 0) {
          if (*(short *)((int)piVar17 + 0xe) == 0xbb6) {
            uVar15 = 0;
          }
          else {
            dVar20 = (double)(float)(dVar20 + (double)FLOAT_803e32ac);
            if ((double)FLOAT_803e3288 <= dVar20) {
              dVar20 = (double)(float)(dVar20 - (double)FLOAT_803e3288);
              uVar14 = uVar14 + 1;
              bVar4 = true;
            }
            dVar26 = (double)(float)(dVar26 + dVar22);
            if (bVar4) {
              local_d8[0] = uVar14 - 1;
              local_d8[1] = uVar14;
              local_d8[2] = uVar14 + 1;
              local_d8[3] = uVar14 + 2;
              if ((int)(uVar14 - 1) < 0) {
                local_d8[0] = 0;
              }
              if ((int)uVar1 <= (int)uVar14) {
                local_d8[1] = uVar1;
              }
              if ((int)uVar1 <= (int)(uVar14 + 1)) {
                local_d8[2] = uVar1;
              }
              if ((int)uVar1 <= (int)(uVar14 + 2)) {
                local_d8[3] = uVar1;
              }
              piVar7 = local_d8;
              pfVar13 = local_e8;
              pfVar8 = local_f8;
              pfVar9 = local_108;
              pfVar10 = local_118;
              pfVar11 = local_128;
              pfVar12 = local_138;
              iVar18 = 4;
              do {
                iVar5 = *piVar7 * 0xc;
                local_b8 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar16 + iVar5) ^ 0x80000000)
                ;
                *pfVar13 = (float)(local_b8 - DOUBLE_803e3318) / FLOAT_803e32f4;
                uStack188 = (int)*(short *)(iVar16 + iVar5 + 2) ^ 0x80000000;
                local_c0 = 0x43300000;
                *pfVar8 = (float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803e3318) /
                          FLOAT_803e32f4;
                local_c8 = (double)CONCAT44(0x43300000,
                                            (int)*(short *)(iVar16 + iVar5 + 4) ^ 0x80000000);
                *pfVar9 = (float)(local_c8 - DOUBLE_803e3318) / FLOAT_803e32f4;
                local_b0 = (double)CONCAT44(0x43300000,
                                            (int)*(short *)(iVar16 + iVar5 + 6) ^ 0x80000000);
                *pfVar10 = (float)(local_b0 - DOUBLE_803e3318) / FLOAT_803e32f4;
                local_a8 = (double)CONCAT44(0x43300000,
                                            (int)*(short *)(iVar16 + iVar5 + 8) ^ 0x80000000);
                *pfVar11 = (float)(local_a8 - DOUBLE_803e3318) / FLOAT_803e32f4;
                uStack156 = (int)*(short *)(iVar16 + iVar5 + 10) ^ 0x80000000;
                local_a0 = 0x43300000;
                *pfVar12 = (float)((double)CONCAT44(0x43300000,uStack156) - DOUBLE_803e3318) /
                           FLOAT_803e32f4;
                fVar2 = *pfVar13;
                fVar3 = *pfVar9;
                *pfVar13 = (float)(dVar25 * (double)fVar2 - (double)(float)(dVar21 * (double)fVar3))
                ;
                *pfVar9 = (float)(dVar21 * (double)fVar2 + (double)(float)(dVar25 * (double)fVar3));
                fVar2 = *pfVar10;
                fVar3 = *pfVar12;
                *pfVar10 = (float)(dVar25 * (double)fVar2 - (double)(float)(dVar21 * (double)fVar3))
                ;
                *pfVar12 = (float)(dVar21 * (double)fVar2 + (double)(float)(dVar25 * (double)fVar3))
                ;
                piVar7 = piVar7 + 1;
                pfVar13 = pfVar13 + 1;
                pfVar8 = pfVar8 + 1;
                pfVar9 = pfVar9 + 1;
                pfVar10 = pfVar10 + 1;
                pfVar11 = pfVar11 + 1;
                pfVar12 = pfVar12 + 1;
                iVar18 = iVar18 + -1;
              } while (iVar18 != 0);
              bVar4 = false;
            }
            pfVar13 = (float *)(*piVar17 + (uint)*(ushort *)((int)piVar17 + 0xe) * 0x14);
            dVar23 = (double)FUN_80010ee0(dVar20,local_118,0);
            *pfVar13 = (float)dVar23;
            dVar23 = (double)FUN_80010ee0(dVar20,local_128,0);
            pfVar13[1] = (float)dVar23;
            dVar23 = (double)FUN_80010ee0(dVar20,local_138,0);
            pfVar13[2] = (float)dVar23;
            *pfVar13 = *pfVar13 +
                       (float)(dVar26 * (double)(float)((double)*(float *)(in_r6 + 0xc) -
                                                       (double)*(float *)(extraout_r4 + 0x8c)) +
                              (double)*(float *)(extraout_r4 + 0x8c));
            pfVar13[1] = pfVar13[1] +
                         (float)(dVar26 * (double)(float)((double)*(float *)(in_r6 + 0xe) -
                                                         (double)*(float *)(extraout_r4 + 0x90)) +
                                (double)*(float *)(extraout_r4 + 0x90));
            pfVar13[2] = pfVar13[2] +
                         (float)(dVar26 * (double)(float)((double)*(float *)(in_r6 + 0x10) -
                                                         (double)*(float *)(extraout_r4 + 0x94)) +
                                (double)*(float *)(extraout_r4 + 0x94));
            uStack156 = uVar14 ^ 0x80000000;
            local_a0 = 0x43300000;
            fVar2 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack156) - DOUBLE_803e3318
                                           ) + dVar20);
            dVar23 = (double)fVar2;
            pfVar13[3] = fVar2;
            fVar2 = FLOAT_803e32f4 * (float)(dVar27 - (double)pfVar13[3]) * FLOAT_803e3310;
            fVar3 = FLOAT_803e32b4;
            if ((FLOAT_803e32b4 <= fVar2) && (fVar3 = fVar2, FLOAT_803e32f4 < fVar2)) {
              fVar3 = FLOAT_803e32f4;
            }
            local_a8 = (double)(longlong)(int)(FLOAT_803e32f4 - fVar3);
            *(short *)(pfVar13 + 4) = (short)(int)(FLOAT_803e32f4 - fVar3);
            dVar24 = (double)FUN_80010ee0(dVar20,local_e8,0);
            pfVar13[5] = (float)dVar24;
            dVar24 = (double)FUN_80010ee0(dVar20,local_f8,0);
            pfVar13[6] = (float)dVar24;
            dVar24 = (double)FUN_80010ee0(dVar20,local_108,0);
            pfVar13[7] = (float)dVar24;
            pfVar13[5] = pfVar13[5] +
                         (float)(dVar26 * (double)(float)((double)*(float *)(in_r6 + 0xc) -
                                                         (double)*(float *)(extraout_r4 + 0x8c)) +
                                (double)*(float *)(extraout_r4 + 0x8c));
            pfVar13[6] = pfVar13[6] +
                         (float)(dVar26 * (double)(float)((double)*(float *)(in_r6 + 0xe) -
                                                         (double)*(float *)(extraout_r4 + 0x90)) +
                                (double)*(float *)(extraout_r4 + 0x90));
            pfVar13[7] = pfVar13[7] +
                         (float)(dVar26 * (double)(float)((double)*(float *)(in_r6 + 0x10) -
                                                         (double)*(float *)(extraout_r4 + 0x94)) +
                                (double)*(float *)(extraout_r4 + 0x94));
            pfVar13[8] = (float)dVar23;
            fVar2 = FLOAT_803e32f4 * (float)(dVar27 - (double)pfVar13[8]) * FLOAT_803e3310;
            fVar3 = FLOAT_803e32b4;
            if ((FLOAT_803e32b4 <= fVar2) && (fVar3 = fVar2, FLOAT_803e32f4 < fVar2)) {
              fVar3 = FLOAT_803e32f4;
            }
            local_b0 = (double)(longlong)(int)(FLOAT_803e32f4 - fVar3);
            *(short *)(pfVar13 + 9) = (short)(int)(FLOAT_803e32f4 - fVar3);
            *(short *)((int)piVar17 + 0x12) = *(short *)((int)piVar17 + 0x12) + 2;
            *(short *)((int)piVar17 + 0xe) = *(short *)((int)piVar17 + 0xe) + 2;
            uVar15 = uVar15 - 1;
          }
        }
      }
    }
    *(undefined4 *)(extraout_r4 + 0x8c) = *(undefined4 *)(in_r6 + 0xc);
    *(undefined4 *)(extraout_r4 + 0x90) = *(undefined4 *)(in_r6 + 0xe);
    *(undefined4 *)(extraout_r4 + 0x94) = *(undefined4 *)(in_r6 + 0x10);
    *(undefined4 *)(extraout_r4 + 0x98) = *(undefined4 *)(iVar6 + 4);
  }
LAB_8016e684:
  __psq_l0(auStack8,uVar19);
  __psq_l1(auStack8,uVar19);
  __psq_l0(auStack24,uVar19);
  __psq_l1(auStack24,uVar19);
  __psq_l0(auStack40,uVar19);
  __psq_l1(auStack40,uVar19);
  __psq_l0(auStack56,uVar19);
  __psq_l1(auStack56,uVar19);
  __psq_l0(auStack72,uVar19);
  __psq_l1(auStack72,uVar19);
  __psq_l0(auStack88,uVar19);
  __psq_l1(auStack88,uVar19);
  __psq_l0(auStack104,uVar19);
  __psq_l1(auStack104,uVar19);
  FUN_80286114();
  return;
}

