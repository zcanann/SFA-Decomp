// Function: FUN_800659a8
// Entry: 800659a8
// Size: 1192 bytes

/* WARNING: Removing unreachable block (ram,0x80065e28) */
/* WARNING: Removing unreachable block (ram,0x80065e18) */
/* WARNING: Removing unreachable block (ram,0x80065e08) */
/* WARNING: Removing unreachable block (ram,0x80065df8) */
/* WARNING: Removing unreachable block (ram,0x80065e00) */
/* WARNING: Removing unreachable block (ram,0x80065e10) */
/* WARNING: Removing unreachable block (ram,0x80065e20) */
/* WARNING: Removing unreachable block (ram,0x80065e30) */

void FUN_800659a8(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5,int param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  bool bVar7;
  int iVar8;
  int iVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  float *pfVar13;
  undefined4 uVar14;
  double extraout_f1;
  double dVar15;
  undefined8 in_f24;
  double dVar16;
  undefined8 in_f25;
  double dVar17;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar18;
  undefined8 in_f28;
  double dVar19;
  undefined8 in_f29;
  double dVar20;
  undefined8 in_f30;
  double dVar21;
  undefined8 in_f31;
  double dVar22;
  undefined8 uVar23;
  undefined auStack360 [4];
  float local_164;
  undefined auStack352 [4];
  float local_15c;
  float local_158;
  float local_154;
  float local_14c [7];
  float local_130 [7];
  float local_114 [7];
  undefined4 local_f8;
  uint uStack244;
  undefined4 local_f0;
  uint uStack236;
  undefined4 local_e8;
  uint uStack228;
  undefined4 local_e0;
  uint uStack220;
  undefined4 local_d8;
  uint uStack212;
  undefined4 local_d0;
  uint uStack204;
  undefined4 local_c8;
  uint uStack196;
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
  
  uVar14 = 0;
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
  uVar23 = FUN_802860c0();
  pfVar13 = (float *)((ulonglong)uVar23 >> 0x20);
  dVar17 = extraout_f1;
  if (*param_5 == 0.0) {
    uStack244 = DAT_8038de44 ^ 0x80000000;
    local_f8 = 0x43300000;
    dVar17 = (double)(float)(extraout_f1 -
                            (double)(float)((double)CONCAT44(0x43300000,uStack244) - DOUBLE_803decd8
                                           ));
    uStack236 = DAT_8038de4c ^ 0x80000000;
    local_f0 = 0x43300000;
    param_2 = (double)(float)(param_2 -
                             (double)(float)((double)CONCAT44(0x43300000,uStack236) -
                                            DOUBLE_803decd8));
  }
  for (; pfVar13 < (float *)uVar23; pfVar13 = pfVar13 + 0x13) {
    if (((*(byte *)((int)pfVar13 + 0x49) & 0x10) == 0) ||
       ((*(byte *)((int)pfVar13 + 0x49) & 4) != 0)) {
      local_15c = pfVar13[1];
      local_158 = pfVar13[2];
      local_154 = pfVar13[3];
      if ((FLOAT_803decb4 < local_158) || ((param_6 != 0 && (FLOAT_803decb4 != local_158)))) {
        local_164 = -(*pfVar13 +
                     (float)((double)local_15c * dVar17 +
                            (double)(float)((double)local_154 * param_2))) / local_158;
        uStack236 = (int)*(short *)(pfVar13 + 4) ^ 0x80000000U;
        local_f0 = 0x43300000;
        local_114[0] = (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(pfVar13 + 4) ^ 0x80000000U) -
                              DOUBLE_803decd8);
        uStack244 = (int)*(short *)((int)pfVar13 + 0x16) ^ 0x80000000;
        local_f8 = 0x43300000;
        local_130[0] = (float)((double)CONCAT44(0x43300000,uStack244) - DOUBLE_803decd8);
        uStack228 = (int)*(short *)(pfVar13 + 7) ^ 0x80000000U;
        local_e8 = 0x43300000;
        local_14c[0] = (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(pfVar13 + 7) ^ 0x80000000U) -
                              DOUBLE_803decd8);
        uStack220 = (int)*(short *)((int)pfVar13 + 0x12) ^ 0x80000000;
        local_e0 = 0x43300000;
        local_114[1] = (float)((double)CONCAT44(0x43300000,uStack220) - DOUBLE_803decd8);
        uStack212 = (int)*(short *)(pfVar13 + 6) ^ 0x80000000U;
        local_d8 = 0x43300000;
        local_130[1] = (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(pfVar13 + 6) ^ 0x80000000U) -
                              DOUBLE_803decd8);
        uStack204 = (int)*(short *)((int)pfVar13 + 0x1e) ^ 0x80000000;
        local_d0 = 0x43300000;
        local_14c[1] = (float)((double)CONCAT44(0x43300000,uStack204) - DOUBLE_803decd8);
        uStack196 = (int)*(short *)(pfVar13 + 5) ^ 0x80000000U;
        local_c8 = 0x43300000;
        local_114[2] = (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(pfVar13 + 5) ^ 0x80000000U) -
                              DOUBLE_803decd8);
        uStack188 = (int)*(short *)((int)pfVar13 + 0x1a) ^ 0x80000000;
        local_c0 = 0x43300000;
        local_130[2] = (float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803decd8);
        uStack180 = (int)*(short *)(pfVar13 + 8) ^ 0x80000000U;
        local_b8 = 0x43300000;
        local_14c[2] = (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(pfVar13 + 8) ^ 0x80000000U) -
                              DOUBLE_803decd8);
        bVar7 = true;
        iVar9 = 0;
        dVar21 = (double)FLOAT_803decc0;
        dVar22 = (double)FLOAT_803decb4;
        dVar16 = (double)FLOAT_803dece4;
        pfVar10 = local_14c;
        pfVar11 = local_130;
        pfVar12 = local_114;
        do {
          iVar8 = iVar9 + 1;
          if (2 < iVar8) {
            iVar8 = 0;
          }
          local_114[3] = (float)(dVar21 * (double)local_15c + (double)*pfVar12);
          local_130[3] = (float)(dVar21 * (double)local_158 + (double)*pfVar11);
          local_14c[3] = (float)(dVar21 * (double)local_154 + (double)*pfVar10);
          fVar4 = local_14c[iVar8];
          fVar1 = *pfVar10;
          fVar2 = *pfVar11;
          fVar5 = local_130[iVar8];
          dVar18 = (double)(local_130[3] * (fVar1 - fVar4) +
                           fVar2 * (fVar4 - local_14c[3]) + fVar5 * (local_14c[3] - fVar1));
          fVar6 = local_114[iVar8];
          fVar3 = *pfVar12;
          dVar19 = (double)(local_14c[3] * (fVar3 - fVar6) +
                           fVar1 * (fVar6 - local_114[3]) + fVar4 * (local_114[3] - fVar3));
          dVar20 = (double)(local_114[3] * (fVar2 - fVar5) +
                           fVar3 * (fVar5 - local_130[3]) + fVar6 * (local_130[3] - fVar2));
          dVar15 = (double)FUN_802931a0((double)(float)(dVar20 * dVar20 +
                                                       (double)(float)(dVar18 * dVar18 +
                                                                      (double)(float)(dVar19 * 
                                                  dVar19))));
          if (dVar22 < dVar15) {
            dVar15 = (double)(float)((double)FLOAT_803decc4 / dVar15);
            dVar18 = (double)(float)(dVar18 * dVar15);
            dVar19 = (double)(float)(dVar19 * dVar15);
            dVar20 = (double)(float)(dVar20 * dVar15);
          }
          if (dVar16 < (double)(-(float)(dVar20 * (double)*pfVar10 +
                                        (double)(float)(dVar18 * (double)*pfVar12 +
                                                       (double)(float)(dVar19 * (double)*pfVar11)))
                               + (float)(dVar20 * param_2 +
                                        (double)(float)(dVar18 * dVar17 +
                                                       (double)(float)(dVar19 * (double)local_164)))
                               )) {
            bVar7 = false;
            break;
          }
          pfVar12 = pfVar12 + 1;
          pfVar11 = pfVar11 + 1;
          pfVar10 = pfVar10 + 1;
          iVar9 = iVar9 + 1;
        } while (iVar9 < 3);
        if (bVar7) {
          if ('\"' < DAT_803dcf60) break;
          if (*param_5 != 0.0) {
            FUN_800226cc(dVar17,(double)local_164,param_2,param_5[3],auStack352,&local_164,
                         auStack360);
            FUN_80022650(param_5[3],&local_15c,&local_15c);
          }
          *DAT_803dcf68 = local_164;
          *(undefined *)(DAT_803dcf68 + 5) = *(undefined *)(pfVar13 + 0x12);
          DAT_803dcf68[1] = local_15c;
          DAT_803dcf68[2] = local_158;
          DAT_803dcf68[3] = local_154;
          DAT_803dcf68[4] = *param_5;
          DAT_803dcf68 = DAT_803dcf68 + 6;
          DAT_803dcf60 = DAT_803dcf60 + '\x01';
        }
      }
    }
  }
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  __psq_l0(auStack24,uVar14);
  __psq_l1(auStack24,uVar14);
  __psq_l0(auStack40,uVar14);
  __psq_l1(auStack40,uVar14);
  __psq_l0(auStack56,uVar14);
  __psq_l1(auStack56,uVar14);
  __psq_l0(auStack72,uVar14);
  __psq_l1(auStack72,uVar14);
  __psq_l0(auStack88,uVar14);
  __psq_l1(auStack88,uVar14);
  __psq_l0(auStack104,uVar14);
  __psq_l1(auStack104,uVar14);
  __psq_l0(auStack120,uVar14);
  __psq_l1(auStack120,uVar14);
  FUN_8028610c();
  return;
}

