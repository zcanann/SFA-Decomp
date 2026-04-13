// Function: FUN_80065b24
// Entry: 80065b24
// Size: 1192 bytes

/* WARNING: Removing unreachable block (ram,0x80065fac) */
/* WARNING: Removing unreachable block (ram,0x80065fa4) */
/* WARNING: Removing unreachable block (ram,0x80065f9c) */
/* WARNING: Removing unreachable block (ram,0x80065f94) */
/* WARNING: Removing unreachable block (ram,0x80065f8c) */
/* WARNING: Removing unreachable block (ram,0x80065f84) */
/* WARNING: Removing unreachable block (ram,0x80065f7c) */
/* WARNING: Removing unreachable block (ram,0x80065f74) */
/* WARNING: Removing unreachable block (ram,0x80065b6c) */
/* WARNING: Removing unreachable block (ram,0x80065b64) */
/* WARNING: Removing unreachable block (ram,0x80065b5c) */
/* WARNING: Removing unreachable block (ram,0x80065b54) */
/* WARNING: Removing unreachable block (ram,0x80065b4c) */
/* WARNING: Removing unreachable block (ram,0x80065b44) */
/* WARNING: Removing unreachable block (ram,0x80065b3c) */
/* WARNING: Removing unreachable block (ram,0x80065b34) */

void FUN_80065b24(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int *param_5,int param_6)

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
  double extraout_f1;
  double dVar14;
  double in_f24;
  double dVar15;
  double in_f25;
  double dVar16;
  double in_f26;
  double in_f27;
  double dVar17;
  double in_f28;
  double dVar18;
  double in_f29;
  double dVar19;
  double in_f30;
  double dVar20;
  double in_f31;
  double dVar21;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar22;
  float fStack_168;
  float local_164;
  float fStack_160;
  float local_15c;
  float local_158;
  float local_154;
  float local_14c [7];
  float local_130 [7];
  float local_114 [7];
  undefined4 local_f8;
  uint uStack_f4;
  undefined4 local_f0;
  uint uStack_ec;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
  undefined4 local_d8;
  uint uStack_d4;
  undefined4 local_d0;
  uint uStack_cc;
  undefined4 local_c8;
  uint uStack_c4;
  undefined4 local_c0;
  uint uStack_bc;
  undefined4 local_b8;
  uint uStack_b4;
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
  uVar22 = FUN_80286824();
  pfVar13 = (float *)((ulonglong)uVar22 >> 0x20);
  dVar16 = extraout_f1;
  if ((float)*param_5 == 0.0) {
    uStack_f4 = DAT_8038eaa4 ^ 0x80000000;
    local_f8 = 0x43300000;
    dVar16 = (double)(float)(extraout_f1 -
                            (double)(float)((double)CONCAT44(0x43300000,uStack_f4) - DOUBLE_803df958
                                           ));
    uStack_ec = DAT_8038eaac ^ 0x80000000;
    local_f0 = 0x43300000;
    param_2 = (double)(float)(param_2 -
                             (double)(float)((double)CONCAT44(0x43300000,uStack_ec) -
                                            DOUBLE_803df958));
  }
  for (; pfVar13 < (float *)uVar22; pfVar13 = pfVar13 + 0x13) {
    if (((*(byte *)((int)pfVar13 + 0x49) & 0x10) == 0) ||
       ((*(byte *)((int)pfVar13 + 0x49) & 4) != 0)) {
      local_15c = pfVar13[1];
      local_158 = pfVar13[2];
      local_154 = pfVar13[3];
      if ((FLOAT_803df934 < local_158) || ((param_6 != 0 && (FLOAT_803df934 != local_158)))) {
        local_164 = -(*pfVar13 +
                     (float)((double)local_15c * dVar16 +
                            (double)(float)((double)local_154 * param_2))) / local_158;
        uStack_ec = (int)*(short *)(pfVar13 + 4) ^ 0x80000000U;
        local_f0 = 0x43300000;
        local_114[0] = (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(pfVar13 + 4) ^ 0x80000000U) -
                              DOUBLE_803df958);
        uStack_f4 = (int)*(short *)((int)pfVar13 + 0x16) ^ 0x80000000;
        local_f8 = 0x43300000;
        local_130[0] = (float)((double)CONCAT44(0x43300000,uStack_f4) - DOUBLE_803df958);
        uStack_e4 = (int)*(short *)(pfVar13 + 7) ^ 0x80000000U;
        local_e8 = 0x43300000;
        local_14c[0] = (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(pfVar13 + 7) ^ 0x80000000U) -
                              DOUBLE_803df958);
        uStack_dc = (int)*(short *)((int)pfVar13 + 0x12) ^ 0x80000000;
        local_e0 = 0x43300000;
        local_114[1] = (float)((double)CONCAT44(0x43300000,uStack_dc) - DOUBLE_803df958);
        uStack_d4 = (int)*(short *)(pfVar13 + 6) ^ 0x80000000U;
        local_d8 = 0x43300000;
        local_130[1] = (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(pfVar13 + 6) ^ 0x80000000U) -
                              DOUBLE_803df958);
        uStack_cc = (int)*(short *)((int)pfVar13 + 0x1e) ^ 0x80000000;
        local_d0 = 0x43300000;
        local_14c[1] = (float)((double)CONCAT44(0x43300000,uStack_cc) - DOUBLE_803df958);
        uStack_c4 = (int)*(short *)(pfVar13 + 5) ^ 0x80000000U;
        local_c8 = 0x43300000;
        local_114[2] = (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(pfVar13 + 5) ^ 0x80000000U) -
                              DOUBLE_803df958);
        uStack_bc = (int)*(short *)((int)pfVar13 + 0x1a) ^ 0x80000000;
        local_c0 = 0x43300000;
        local_130[2] = (float)((double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803df958);
        uStack_b4 = (int)*(short *)(pfVar13 + 8) ^ 0x80000000U;
        local_b8 = 0x43300000;
        local_14c[2] = (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(pfVar13 + 8) ^ 0x80000000U) -
                              DOUBLE_803df958);
        bVar7 = true;
        iVar9 = 0;
        dVar20 = (double)FLOAT_803df940;
        dVar21 = (double)FLOAT_803df934;
        dVar15 = (double)FLOAT_803df964;
        pfVar10 = local_14c;
        pfVar11 = local_130;
        pfVar12 = local_114;
        do {
          iVar8 = iVar9 + 1;
          if (2 < iVar8) {
            iVar8 = 0;
          }
          local_114[3] = (float)(dVar20 * (double)local_15c + (double)*pfVar12);
          local_130[3] = (float)(dVar20 * (double)local_158 + (double)*pfVar11);
          local_14c[3] = (float)(dVar20 * (double)local_154 + (double)*pfVar10);
          fVar4 = local_14c[iVar8];
          fVar1 = *pfVar10;
          fVar2 = *pfVar11;
          fVar5 = local_130[iVar8];
          dVar17 = (double)(local_130[3] * (fVar1 - fVar4) +
                           fVar2 * (fVar4 - local_14c[3]) + fVar5 * (local_14c[3] - fVar1));
          fVar6 = local_114[iVar8];
          fVar3 = *pfVar12;
          dVar18 = (double)(local_14c[3] * (fVar3 - fVar6) +
                           fVar1 * (fVar6 - local_114[3]) + fVar4 * (local_114[3] - fVar3));
          dVar19 = (double)(local_114[3] * (fVar2 - fVar5) +
                           fVar3 * (fVar5 - local_130[3]) + fVar6 * (local_130[3] - fVar2));
          dVar14 = FUN_80293900((double)(float)(dVar19 * dVar19 +
                                               (double)(float)(dVar17 * dVar17 +
                                                              (double)(float)(dVar18 * dVar18))));
          if (dVar21 < dVar14) {
            dVar14 = (double)(float)((double)FLOAT_803df944 / dVar14);
            dVar17 = (double)(float)(dVar17 * dVar14);
            dVar18 = (double)(float)(dVar18 * dVar14);
            dVar19 = (double)(float)(dVar19 * dVar14);
          }
          if (dVar15 < (double)(-(float)(dVar19 * (double)*pfVar10 +
                                        (double)(float)(dVar17 * (double)*pfVar12 +
                                                       (double)(float)(dVar18 * (double)*pfVar11)))
                               + (float)(dVar19 * param_2 +
                                        (double)(float)(dVar17 * dVar16 +
                                                       (double)(float)(dVar18 * (double)local_164)))
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
          if ('\"' < DAT_803ddbe0) break;
          if ((float)*param_5 != 0.0) {
            FUN_80022790(dVar16,(double)local_164,param_2,(float *)((float *)param_5)[3],&fStack_160
                         ,&local_164,&fStack_168);
            FUN_80022714((float *)((float *)param_5)[3],&local_15c,&local_15c);
          }
          *DAT_803ddbe8 = local_164;
          *(undefined *)(DAT_803ddbe8 + 5) = *(undefined *)(pfVar13 + 0x12);
          DAT_803ddbe8[1] = local_15c;
          DAT_803ddbe8[2] = local_158;
          DAT_803ddbe8[3] = local_154;
          DAT_803ddbe8[4] = (float)*param_5;
          DAT_803ddbe8 = DAT_803ddbe8 + 6;
          DAT_803ddbe0 = DAT_803ddbe0 + '\x01';
        }
      }
    }
  }
  FUN_80286870();
  return;
}

