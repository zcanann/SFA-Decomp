// Function: FUN_80063524
// Entry: 80063524
// Size: 3144 bytes

/* WARNING: Removing unreachable block (ram,0x8006414c) */
/* WARNING: Removing unreachable block (ram,0x80064144) */
/* WARNING: Removing unreachable block (ram,0x8006413c) */
/* WARNING: Removing unreachable block (ram,0x80064134) */
/* WARNING: Removing unreachable block (ram,0x8006412c) */
/* WARNING: Removing unreachable block (ram,0x80064124) */
/* WARNING: Removing unreachable block (ram,0x8006411c) */
/* WARNING: Removing unreachable block (ram,0x80064114) */
/* WARNING: Removing unreachable block (ram,0x8006410c) */
/* WARNING: Removing unreachable block (ram,0x80064104) */
/* WARNING: Removing unreachable block (ram,0x800640fc) */
/* WARNING: Removing unreachable block (ram,0x800640f4) */
/* WARNING: Removing unreachable block (ram,0x8006358c) */
/* WARNING: Removing unreachable block (ram,0x80063584) */
/* WARNING: Removing unreachable block (ram,0x8006357c) */
/* WARNING: Removing unreachable block (ram,0x80063574) */
/* WARNING: Removing unreachable block (ram,0x8006356c) */
/* WARNING: Removing unreachable block (ram,0x80063564) */
/* WARNING: Removing unreachable block (ram,0x8006355c) */
/* WARNING: Removing unreachable block (ram,0x80063554) */
/* WARNING: Removing unreachable block (ram,0x8006354c) */
/* WARNING: Removing unreachable block (ram,0x80063544) */
/* WARNING: Removing unreachable block (ram,0x8006353c) */
/* WARNING: Removing unreachable block (ram,0x80063534) */

void FUN_80063524(undefined4 param_1,undefined4 param_2,uint param_3,int *param_4,int param_5,
                 char param_6,char param_7,char param_8)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  byte bVar5;
  short sVar6;
  short sVar7;
  char cVar8;
  float fVar9;
  float fVar10;
  uint uVar11;
  ushort uVar12;
  float *pfVar13;
  float *pfVar14;
  short *psVar15;
  float *pfVar16;
  int iVar17;
  short *psVar18;
  float *pfVar19;
  float *pfVar20;
  float *pfVar21;
  ushort *puVar22;
  float *pfVar23;
  int iVar24;
  float *pfVar25;
  char unaff_r19;
  int iVar26;
  int iVar27;
  uint uVar28;
  int iVar29;
  int iVar30;
  float *pfVar31;
  short *psVar32;
  bool bVar33;
  bool bVar34;
  int iVar35;
  double in_f0;
  double extraout_f1;
  double dVar36;
  double dVar37;
  double dVar38;
  double dVar39;
  double dVar40;
  double dVar41;
  double dVar42;
  double dVar43;
  double in_f20;
  double in_f21;
  double in_f22;
  double in_f23;
  double in_f24;
  double dVar44;
  double in_f25;
  double dVar45;
  double dVar46;
  double in_f26;
  double dVar47;
  double dVar48;
  double in_f27;
  double in_f28;
  double dVar49;
  double in_f29;
  double dVar50;
  double in_f30;
  double dVar51;
  double in_f31;
  double in_ps20_1;
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
  undefined8 uVar52;
  ushort local_1ac [2];
  float local_1a8 [4];
  short local_198 [6];
  float local_18c [17];
  float local_148 [6];
  undefined4 local_130;
  uint uStack_12c;
  undefined4 local_128;
  uint uStack_124;
  uint local_120;
  short *local_11c;
  int local_118;
  int local_114;
  float local_b8;
  float fStack_b4;
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
  local_b8 = (float)in_f20;
  fStack_b4 = (float)in_ps20_1;
  uVar52 = FUN_8028680c();
  pfVar13 = (float *)((ulonglong)uVar52 >> 0x20);
  pfVar16 = (float *)uVar52;
  if (param_5 == 0) {
    iVar30 = (int)param_7;
    iVar26 = DAT_803ddbb8;
    iVar17 = DAT_803ddbb4;
    iVar27 = DAT_803ddbbc;
    if (iVar30 == -1) {
      local_120 = 0;
      uVar28 = (uint)DAT_803ddbde;
    }
    else {
      local_120 = (uint)(ushort)(&DAT_8038e4a0)[iVar30 * 2];
      uVar28 = (uint)(ushort)(&DAT_8038e4a2)[iVar30 * 2];
    }
  }
  else {
    if (param_7 == -1) {
      local_120 = 0;
      bVar5 = *(byte *)(*(int *)(param_5 + 0x50) + 0x5c);
    }
    else {
      iVar17 = *(int *)(*(int *)(param_5 + 0x50) + 0x38);
      iVar26 = param_7 * 2;
      local_120 = (uint)*(byte *)(iVar17 + iVar26);
      bVar5 = *(byte *)(iVar17 + iVar26 + 1);
    }
    uVar28 = (uint)bVar5;
    iVar17 = *(int *)(*(int *)(param_5 + 0x50) + 0x34);
    iVar26 = *(int *)(*(int *)(param_5 + 0x50) + 0x3c);
    iVar27 = 0;
    if ((*(ushort *)(param_5 + 0xb0) & 0x100) != 0) {
      uVar28 = 0;
    }
  }
  uVar11 = countLeadingZeros(param_3 & 1);
  cVar8 = (char)(uVar11 >> 5);
  local_1a8[2] = *pfVar13;
  dVar41 = (double)local_1a8[2];
  local_1a8[0] = pfVar13[2];
  local_1a8[3] = *pfVar16;
  dVar39 = (double)local_1a8[3];
  local_1a8[1] = pfVar16[2];
  dVar38 = dVar41;
  if (dVar41 < dVar39) {
    dVar38 = dVar39;
    dVar39 = dVar41;
  }
  dVar36 = (double)local_1a8[0];
  dVar40 = (double)local_1a8[1];
  dVar41 = dVar36;
  if (dVar36 < dVar40) {
    dVar41 = dVar40;
    dVar40 = dVar36;
  }
  dVar44 = (double)((float)(dVar39 - extraout_f1) - FLOAT_803df94c);
  dVar36 = (double)((float)(dVar38 + extraout_f1) + FLOAT_803df94c);
  dVar40 = (double)((float)(dVar40 - extraout_f1) - FLOAT_803df94c);
  dVar39 = (double)((float)(dVar41 + extraout_f1) + FLOAT_803df94c);
  iVar29 = 0;
  iVar30 = 1;
  local_11c = local_198;
  pfVar25 = local_148;
  pfVar31 = local_18c + 0xc;
  local_118 = local_120 << 1;
  local_114 = local_120 << 4;
  dVar38 = extraout_f1;
  do {
    if (iVar30 == 0) {
      if ((iVar29 != 0) && (param_4 != (int *)0x0)) {
        iVar30 = iVar29 + -1;
        if (cVar8 == '\0') {
          iVar30 = 0;
        }
        dVar38 = FUN_80293900((double)((*pfVar16 - local_1a8[2]) * (*pfVar16 - local_1a8[2]) +
                                      (pfVar16[2] - local_1a8[0]) * (pfVar16[2] - local_1a8[0])));
        param_4[0x11] = (int)(float)((double)local_148[0] * dVar38);
        param_4[0x12] = (int)local_18c[iVar30 + 0xc];
        iVar30 = (int)local_198[iVar30];
        if (iVar27 != 0) {
          iVar30 = (int)*(short *)(iVar27 + iVar30 * 2);
        }
        psVar15 = (short *)(iVar17 + iVar30 * 0x10);
        sVar6 = psVar15[2];
        sVar7 = psVar15[3];
        if (((int)*(char *)(psVar15 + 1) & 0x80U) == 0) {
          uStack_124 = (int)*(char *)psVar15 ^ 0x80000000;
          fVar3 = (float)((double)CONCAT44(0x43300000,uStack_124) - DOUBLE_803df958);
          uStack_12c = (int)*(char *)((int)psVar15 + 1) ^ 0x80000000;
          local_130 = 0x43300000;
          fVar4 = (float)((double)CONCAT44(0x43300000,uStack_12c) - DOUBLE_803df958);
        }
        else {
          uStack_124 = (int)*psVar15 ^ 0x80000000;
          fVar3 = (float)((double)CONCAT44(0x43300000,uStack_124) - DOUBLE_803df958);
          fVar4 = fVar3;
        }
        local_128 = 0x43300000;
        param_4[1] = *(int *)(iVar26 + sVar6 * 0xc);
        iVar17 = iVar26 + sVar6 * 0xc;
        param_4[3] = *(int *)(iVar17 + 4);
        param_4[0xf] = (int)((float)param_4[3] + fVar3);
        param_4[5] = *(int *)(iVar17 + 8);
        param_4[2] = *(int *)(iVar26 + sVar7 * 0xc);
        iVar26 = iVar26 + sVar7 * 0xc;
        param_4[4] = *(int *)(iVar26 + 4);
        param_4[0x10] = (int)((float)param_4[4] + fVar4);
        param_4[6] = *(int *)(iVar26 + 8);
        *(byte *)(param_4 + 0x14) = *(byte *)((int)psVar15 + 3) & 0x3f;
        *(char *)((int)param_4 + 0x52) = *(char *)(psVar15 + 1);
        *(char *)((int)param_4 + 0x51) = (char)psVar15[6];
        *param_4 = param_5;
        *(short *)(param_4 + 0x13) = psVar15[4];
        *(short *)((int)param_4 + 0x4e) = psVar15[5];
      }
      if (iVar29 != 0) {
        DAT_803ddbcc = DAT_803ddbcc + '\x01';
        *pfVar16 = local_1a8[3];
        pfVar16[2] = local_1a8[1];
      }
      FUN_80286858();
      return;
    }
    iVar30 = 0;
    psVar32 = (short *)(iVar27 + local_118);
    psVar15 = (short *)(iVar17 + local_114);
    for (uVar11 = local_120; (int)uVar11 < (int)uVar28; uVar11 = uVar11 + 1) {
      in_f0 = (double)FLOAT_803df950;
      psVar18 = psVar15;
      if (iVar27 != 0) {
        psVar18 = (short *)(iVar17 + *psVar32 * 0x10);
      }
      if ((((int)param_6 & ~(int)*(char *)(psVar18 + 1)) != 0) &&
         (((int)*(char *)((int)psVar18 + 3) & 0x40U) == 0)) {
        if (((int)*(char *)((int)psVar18 + 3) & 0x80U) == 0) {
          unaff_r19 = '\x01';
        }
        else {
          if ((param_3 & 4) != 0) goto LAB_80063e8c;
          unaff_r19 = '\0';
        }
        if ((param_3 & 2) != 0) {
          unaff_r19 = '\x01';
        }
        pfVar20 = (float *)(iVar26 + psVar18[2] * 0xc);
        dVar51 = (double)*pfVar20;
        fVar3 = pfVar20[1];
        dVar50 = (double)pfVar20[2];
        pfVar20 = (float *)(iVar26 + psVar18[3] * 0xc);
        dVar49 = (double)*pfVar20;
        fVar4 = pfVar20[1];
        dVar41 = (double)pfVar20[2];
        if (((((dVar44 <= dVar51) || (dVar44 <= dVar49)) &&
             ((dVar51 <= dVar36 || (dVar49 <= dVar36)))) &&
            ((dVar40 <= dVar50 || (dVar40 <= dVar41)))) &&
           ((dVar50 <= dVar39 || (dVar41 <= dVar39)))) {
          fVar9 = fVar3;
          if (fVar4 < fVar3) {
            fVar9 = fVar4;
          }
          if (((int)*(char *)(psVar18 + 1) & 0x80U) == 0) {
            uStack_12c = (int)*(char *)psVar18 ^ 0x80000000;
            fVar1 = (float)((double)CONCAT44(0x43300000,uStack_12c) - DOUBLE_803df958);
            fVar2 = (float)((double)CONCAT44(0x43300000,
                                             (int)*(char *)((int)psVar18 + 1) ^ 0x80000000) -
                           DOUBLE_803df958);
          }
          else {
            uStack_12c = (int)*psVar18 ^ 0x80000000;
            fVar1 = (float)((double)CONCAT44(0x43300000,uStack_12c) - DOUBLE_803df958);
            fVar2 = fVar1;
          }
          local_130 = 0x43300000;
          fVar10 = fVar3 + fVar1;
          if (fVar3 + fVar1 < fVar4 + fVar2) {
            fVar10 = fVar4 + fVar2;
          }
          uStack_124 = (int)param_8 ^ 0x80000000;
          local_128 = 0x43300000;
          if ((fVar9 - (float)((double)CONCAT44(0x43300000,(int)param_8 ^ 0x80000000) -
                              DOUBLE_803df958) <= pfVar13[1]) &&
             (pfVar13[1] <=
              fVar10 + (float)((double)CONCAT44(0x43300000,uStack_124) - DOUBLE_803df958))) {
            dVar47 = (double)(float)(dVar49 - dVar51);
            dVar45 = (double)(float)(dVar41 - dVar50);
            dVar37 = (double)(float)(dVar47 * dVar47 + (double)(float)(dVar45 * dVar45));
            if ((double)FLOAT_803df934 != dVar37) {
              dVar37 = FUN_80293900(dVar37);
              local_18c[8] = (float)(dVar47 / dVar37);
              dVar48 = (double)local_18c[8];
              local_18c[4] = (float)(dVar45 / dVar37);
              dVar46 = (double)local_18c[4];
              local_18c[0] = -(float)(dVar48 * dVar51 + (double)(float)(dVar46 * dVar50));
              dVar43 = -dVar48;
              local_18c[9] = (float)dVar43;
              dVar47 = -dVar46;
              local_18c[5] = (float)dVar47;
              dVar42 = (double)(float)dVar43;
              dVar45 = (double)(float)dVar47;
              local_18c[1] = -(float)(dVar42 * dVar49 + (double)(float)(dVar45 * dVar41));
              local_18c[10] = (float)dVar47;
              local_18c[6] = local_18c[8];
              local_18c[2] = -((float)(dVar45 * (double)(float)((double)FLOAT_803df938 * dVar45 +
                                                               dVar51)) +
                              (float)(dVar48 * (double)(float)((double)FLOAT_803df938 * dVar48 +
                                                              dVar50)));
              local_18c[0xb] = local_18c[4];
              local_18c[7] = (float)dVar43;
              local_18c[3] = -((float)(dVar46 * (double)(float)(dVar38 * dVar46 + dVar51)) +
                              (float)(dVar42 * (double)(float)(dVar38 * dVar42 + dVar50)));
              FLOAT_803ddbd4 = FLOAT_803df954 * (float)(dVar46 * dVar38);
              FLOAT_803ddbd0 = FLOAT_803df954 * (float)(dVar42 * dVar38);
              iVar24 = 0;
              puVar22 = local_1ac;
              pfVar20 = local_1a8;
              pfVar23 = local_1a8 + 2;
              do {
                uVar12 = 1;
                *puVar22 = 0;
                fVar3 = *pfVar20;
                fVar4 = *pfVar23;
                pfVar14 = local_18c + 4;
                pfVar19 = local_18c + 8;
                pfVar21 = local_18c;
                iVar35 = 2;
                do {
                  if (*pfVar21 + fVar4 * *pfVar19 + fVar3 * *pfVar14 < FLOAT_803df934) {
                    *puVar22 = *puVar22 | uVar12;
                  }
                  uVar12 = (ushort)((int)(short)uVar12 << 1);
                  if (pfVar21[1] + fVar4 * pfVar19[1] + fVar3 * pfVar14[1] < FLOAT_803df934) {
                    *puVar22 = *puVar22 | uVar12;
                  }
                  uVar12 = (ushort)((int)(short)uVar12 << 1);
                  pfVar14 = pfVar14 + 2;
                  pfVar19 = pfVar19 + 2;
                  pfVar21 = pfVar21 + 2;
                  iVar35 = iVar35 + -1;
                } while (iVar35 != 0);
                *pfVar23 = fVar4;
                *pfVar20 = fVar3;
                puVar22 = puVar22 + 1;
                pfVar20 = pfVar20 + 1;
                pfVar23 = pfVar23 + 1;
                iVar24 = iVar24 + 1;
              } while (iVar24 < 2);
              in_f0 = (double)FLOAT_803df944;
              if ((local_1ac[0] & 0xc) == 0xc) {
                if ((local_1ac[0] & 1) == 0) {
                  if ((local_1ac[0] & 2) == 0) {
                    if (unaff_r19 != '\0') {
                      local_1a8[3] = local_1a8[3] + FLOAT_803ddbd4;
                      local_1a8[1] = local_1a8[1] + FLOAT_803ddbd0;
                    }
                  }
                  else {
                    iVar30 = FUN_80063254(dVar49,dVar41,dVar38,local_1a8 + 2,local_1a8,unaff_r19);
                    in_f0 = (double)FLOAT_803df944;
                  }
                }
                else {
                  iVar30 = FUN_80063254(dVar51,dVar50,dVar38,local_1a8 + 2,local_1a8,unaff_r19);
                  in_f0 = (double)FLOAT_803df934;
                }
              }
              else if (((local_1ac[0] ^ local_1ac[1]) & 0xc) != 0) {
                if ((local_1ac[0] & local_1ac[1] & 1) == 0) {
                  if ((local_1ac[0] & local_1ac[1] & 2) == 0) {
                    if ((local_1ac[0] & 4) != 0) {
                      fVar3 = local_18c[3] +
                              local_1a8[2] * local_18c[0xb] + local_1a8[0] * local_18c[7];
                      fVar4 = local_18c[3] +
                              local_1a8[3] * local_18c[0xb] + local_1a8[1] * local_18c[7];
                      FLOAT_803ddbd8 = FLOAT_803df934;
                      if (fVar3 != fVar4) {
                        FLOAT_803ddbd8 = fVar3 / (fVar3 - fVar4);
                      }
                      dVar45 = (double)((local_1a8[3] - local_1a8[2]) * FLOAT_803ddbd8 +
                                       local_1a8[2]);
                      dVar47 = (double)((local_1a8[1] - local_1a8[0]) * FLOAT_803ddbd8 +
                                       local_1a8[0]);
                      bVar33 = local_18c[0] +
                               (float)(dVar45 * (double)local_18c[8] +
                                      (double)(float)(dVar47 * (double)local_18c[4])) <
                               FLOAT_803df934;
                      if (bVar33) {
                        iVar30 = FUN_80063254(dVar51,dVar50,dVar38,local_1a8 + 2,local_1a8,unaff_r19
                                             );
                        in_f0 = (double)FLOAT_803df934;
                      }
                      bVar34 = local_18c[1] +
                               (float)(dVar45 * (double)local_18c[9] +
                                      (double)(float)(dVar47 * (double)local_18c[5])) <
                               FLOAT_803df934;
                      if (bVar34) {
                        iVar30 = FUN_80063254(dVar49,dVar41,dVar38,local_1a8 + 2,local_1a8,unaff_r19
                                             );
                        in_f0 = (double)FLOAT_803df944;
                      }
                      if ((!bVar34 && !bVar33) && (iVar30 = 1, unaff_r19 != '\0')) {
                        if (cVar8 == '\0') {
                          local_1a8[3] = (float)dVar45;
                          local_1a8[1] = (float)dVar47;
                          iVar24 = 0;
                          do {
                            if (FLOAT_803dc2c0 <=
                                local_18c[3] +
                                local_1a8[3] * local_18c[0xb] + local_1a8[1] * local_18c[7])
                            goto LAB_80063e64;
                            local_1a8[3] = local_1a8[3] + FLOAT_803dc2c0 * local_18c[0xb];
                            local_1a8[1] = local_1a8[1] + FLOAT_803dc2c0 * local_18c[7];
                            iVar24 = iVar24 + 1;
                          } while (iVar24 < 0xb);
                          local_1a8[3] = local_1a8[2];
                          local_1a8[1] = local_1a8[0];
                        }
                        else {
                          fVar3 = local_18c[3] +
                                  local_1a8[3] * local_18c[0xb] + local_1a8[1] * local_18c[7];
                          local_1a8[3] = -(fVar3 * local_18c[0xb] - local_1a8[3]);
                          local_1a8[1] = -(fVar3 * local_18c[7] - local_1a8[1]);
                          iVar24 = 0;
                          do {
                            if (FLOAT_803dc2c0 <=
                                local_18c[3] +
                                local_1a8[3] * local_18c[0xb] + local_1a8[1] * local_18c[7])
                            goto LAB_80063e64;
                            local_1a8[3] = local_1a8[3] + FLOAT_803dc2c0 * local_18c[0xb];
                            local_1a8[1] = local_1a8[1] + FLOAT_803dc2c0 * local_18c[7];
                            iVar24 = iVar24 + 1;
                          } while (iVar24 < 0xb);
                          local_1a8[3] = local_1a8[2];
                          local_1a8[1] = local_1a8[0];
                        }
LAB_80063e64:
                        dVar41 = FUN_80293900((double)((float)((double)local_1a8[3] - dVar51) *
                                                       (float)((double)local_1a8[3] - dVar51) +
                                                      (float)((double)local_1a8[1] - dVar50) *
                                                      (float)((double)local_1a8[1] - dVar50)));
                        in_f0 = (double)(float)(dVar41 / dVar37);
                      }
                    }
                  }
                  else {
                    iVar30 = FUN_80063254(dVar49,dVar41,dVar38,local_1a8 + 2,local_1a8,unaff_r19);
                    in_f0 = (double)FLOAT_803df944;
                  }
                }
                else {
                  iVar30 = FUN_80063254(dVar51,dVar50,dVar38,local_1a8 + 2,local_1a8,unaff_r19);
                  in_f0 = (double)FLOAT_803df934;
                }
              }
              if (iVar30 != 0) break;
            }
          }
        }
      }
LAB_80063e8c:
      psVar32 = psVar32 + 1;
      psVar15 = psVar15 + 8;
    }
    if (iVar30 != 0) {
      *local_11c = (short)uVar11;
      *pfVar25 = FLOAT_803ddbd8;
      *pfVar31 = (float)in_f0;
      local_11c = local_11c + 1;
      pfVar25 = pfVar25 + 1;
      pfVar31 = pfVar31 + 1;
      iVar29 = iVar29 + 1;
      if ((4 < iVar29) && (iVar30 = 0, unaff_r19 != '\0')) {
        local_1a8[3] = local_1a8[2];
        local_1a8[1] = local_1a8[0];
      }
    }
  } while( true );
}

