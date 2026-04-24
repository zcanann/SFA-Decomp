// Function: FUN_8023503c
// Entry: 8023503c
// Size: 1076 bytes

/* WARNING: Removing unreachable block (ram,0x80235448) */
/* WARNING: Removing unreachable block (ram,0x80235438) */
/* WARNING: Removing unreachable block (ram,0x80235428) */
/* WARNING: Removing unreachable block (ram,0x80235418) */
/* WARNING: Removing unreachable block (ram,0x80235420) */
/* WARNING: Removing unreachable block (ram,0x80235430) */
/* WARNING: Removing unreachable block (ram,0x80235440) */
/* WARNING: Removing unreachable block (ram,0x80235450) */

void FUN_8023503c(undefined4 param_1,undefined4 param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short **ppsVar4;
  int *piVar5;
  short sVar6;
  short *psVar7;
  int iVar8;
  float *pfVar9;
  uint uVar10;
  int iVar11;
  undefined4 uVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  undefined8 in_f24;
  undefined8 in_f25;
  double dVar16;
  undefined8 in_f26;
  double dVar17;
  undefined8 in_f27;
  double dVar18;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar19;
  undefined8 in_f31;
  double dVar20;
  undefined8 uVar21;
  int local_c8 [2];
  undefined4 local_c0;
  uint uStack188;
  undefined4 local_b8;
  uint uStack180;
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar12 = 0;
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
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  uVar21 = FUN_802860c8();
  iVar3 = (int)((ulonglong)uVar21 >> 0x20);
  pfVar9 = *(float **)(iVar3 + 0xb8);
  dVar18 = (double)FLOAT_803e72b0;
  dVar15 = dVar18;
  ppsVar4 = (short **)FUN_80036f50(0x14,local_c8);
  uVar10 = 0;
  for (iVar11 = 0; iVar11 < local_c8[0]; iVar11 = iVar11 + 1) {
    psVar7 = *ppsVar4;
    if ((*(byte *)(*(int *)(psVar7 + 0x26) + 0x1a) & 2) != 0) {
      uVar10 = 1;
      fVar1 = *(float *)(psVar7 + 8) - *(float *)(iVar3 + 0x10);
      if ((fVar1 <= FLOAT_803e72b4) && (FLOAT_803e72b8 <= fVar1)) {
        fVar1 = *(float *)(psVar7 + 6) - *(float *)(iVar3 + 0xc);
        fVar2 = *(float *)(psVar7 + 10) - *(float *)(iVar3 + 0x14);
        dVar13 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
        uStack188 = (uint)*(byte *)(*(int *)(psVar7 + 0x26) + 0x19);
        local_c0 = 0x43300000;
        dVar19 = (double)(FLOAT_803e72bc *
                         (float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803e72d8));
        if (dVar13 < dVar19) {
          dVar19 = (double)((float)((double)(float)(dVar19 - dVar13) / dVar19) *
                           FLOAT_803e72c0 * *(float *)(psVar7 + 4));
          uStack188 = (int)*psVar7 ^ 0x80000000;
          local_c0 = 0x43300000;
          dVar13 = (double)FUN_80293e80((double)((FLOAT_803e72c4 *
                                                 (float)((double)CONCAT44(0x43300000,uStack188) -
                                                        DOUBLE_803e72e0)) / FLOAT_803e72c8));
          dVar15 = (double)(float)(dVar19 * dVar13 + dVar15);
          uStack180 = (int)*psVar7 ^ 0x80000000;
          local_b8 = 0x43300000;
          dVar13 = (double)FUN_80294204((double)((FLOAT_803e72c4 *
                                                 (float)((double)CONCAT44(0x43300000,uStack180) -
                                                        DOUBLE_803e72e0)) / FLOAT_803e72c8));
          dVar18 = (double)(float)(dVar19 * dVar13 + dVar18);
        }
      }
    }
    ppsVar4 = ppsVar4 + 1;
  }
  piVar5 = (int *)FUN_80036f50(0x50,local_c8);
  dVar19 = (double)FLOAT_803e72c0;
  dVar20 = (double)FLOAT_803e72b4;
  dVar13 = DOUBLE_803e72d8;
  for (iVar11 = 0; fVar2 = FLOAT_803e72cc, fVar1 = FLOAT_803e72b0, iVar11 < local_c8[0];
      iVar11 = iVar11 + 1) {
    iVar8 = *piVar5;
    uStack180 = (uint)*(byte *)(*(int *)(iVar8 + 0x4c) + 0x32);
    local_b8 = 0x43300000;
    dVar17 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack180) - dVar13) /
                            dVar19);
    uVar10 = 1;
    dVar14 = (double)(*(float *)(iVar8 + 0x10) - *(float *)(iVar3 + 0x10));
    if ((dVar14 <= dVar20) && ((double)FLOAT_803e72b8 <= dVar14)) {
      dVar16 = (double)(*(float *)(iVar8 + 0xc) - *(float *)(iVar3 + 0xc));
      dVar14 = (double)(*(float *)(iVar8 + 0x14) - *(float *)(iVar3 + 0x14));
      sVar6 = FUN_800217c0(dVar16,dVar14);
      dVar14 = (double)FUN_802931a0((double)(float)(dVar16 * dVar16 +
                                                   (double)(float)(dVar14 * dVar14)));
      uStack180 = (uint)*(byte *)(*(int *)(iVar8 + 0x4c) + 0x29) << 3 ^ 0x80000000;
      local_b8 = 0x43300000;
      dVar16 = (double)(float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803e72e0);
      if (dVar14 < dVar16) {
        dVar17 = (double)(float)((double)(float)((double)(float)(dVar16 - dVar14) / dVar16) * dVar17
                                );
        uStack180 = (int)(short)(sVar6 + -0x7b30) ^ 0x80000000;
        local_b8 = 0x43300000;
        dVar16 = (double)((FLOAT_803e72c4 *
                          (float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803e72e0)) /
                         FLOAT_803e72c8);
        dVar14 = (double)FUN_80293e80(dVar16);
        dVar15 = (double)(float)(dVar17 * dVar14 + dVar15);
        dVar14 = (double)FUN_80294204(dVar16);
        dVar18 = (double)(float)(dVar17 * dVar14 + dVar18);
      }
    }
    piVar5 = piVar5 + 1;
  }
  if (uVar10 == 0) {
    *(float *)uVar21 = FLOAT_803e72b0;
    *param_3 = fVar1;
  }
  else {
    uStack188 = uVar10 ^ 0x80000000;
    local_b8 = 0x43300000;
    local_c0 = 0x43300000;
    dVar13 = (double)CONCAT44(0x43300000,uStack188) - DOUBLE_803e72e0;
    *pfVar9 = -(FLOAT_803e72cc *
                (float)(dVar15 / (double)(float)((double)CONCAT44(0x43300000,uStack188) -
                                                DOUBLE_803e72e0)) - *pfVar9);
    pfVar9[1] = -(fVar2 * (float)(dVar18 / (double)(float)dVar13) - pfVar9[1]);
    fVar1 = FLOAT_803e72d0;
    *pfVar9 = *pfVar9 * FLOAT_803e72d0;
    pfVar9[1] = pfVar9[1] * fVar1;
    uStack180 = uStack188;
    dVar15 = (double)FUN_802931a0((double)(*pfVar9 * *pfVar9 + pfVar9[1] * pfVar9[1]));
    if ((double)FLOAT_803e72d4 < dVar15) {
      fVar1 = (float)((double)FLOAT_803e72d4 / dVar15);
      *pfVar9 = *pfVar9 * fVar1;
      pfVar9[1] = pfVar9[1] * fVar1;
    }
    *(float *)uVar21 = *pfVar9 * FLOAT_803db414;
    *param_3 = pfVar9[1] * FLOAT_803db414;
  }
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  __psq_l0(auStack24,uVar12);
  __psq_l1(auStack24,uVar12);
  __psq_l0(auStack40,uVar12);
  __psq_l1(auStack40,uVar12);
  __psq_l0(auStack56,uVar12);
  __psq_l1(auStack56,uVar12);
  __psq_l0(auStack72,uVar12);
  __psq_l1(auStack72,uVar12);
  __psq_l0(auStack88,uVar12);
  __psq_l1(auStack88,uVar12);
  __psq_l0(auStack104,uVar12);
  __psq_l1(auStack104,uVar12);
  __psq_l0(auStack120,uVar12);
  __psq_l1(auStack120,uVar12);
  FUN_80286114();
  return;
}

