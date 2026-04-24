// Function: FUN_800633a8
// Entry: 800633a8
// Size: 3144 bytes

/* WARNING: Removing unreachable block (ram,0x80063fc8) */
/* WARNING: Removing unreachable block (ram,0x80063fb8) */
/* WARNING: Removing unreachable block (ram,0x80063fa8) */
/* WARNING: Removing unreachable block (ram,0x80063f98) */
/* WARNING: Removing unreachable block (ram,0x80063f88) */
/* WARNING: Removing unreachable block (ram,0x80063f78) */
/* WARNING: Removing unreachable block (ram,0x80063f80) */
/* WARNING: Removing unreachable block (ram,0x80063f90) */
/* WARNING: Removing unreachable block (ram,0x80063fa0) */
/* WARNING: Removing unreachable block (ram,0x80063fb0) */
/* WARNING: Removing unreachable block (ram,0x80063fc0) */
/* WARNING: Removing unreachable block (ram,0x80063fd0) */

void FUN_800633a8(undefined4 param_1,undefined4 param_2,uint param_3,int *param_4,int param_5,
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
  undefined4 uVar36;
  double in_f0;
  double extraout_f1;
  double dVar37;
  double dVar38;
  double dVar39;
  double dVar40;
  double dVar41;
  double dVar42;
  double dVar43;
  double dVar44;
  undefined8 in_f20;
  undefined8 in_f21;
  undefined8 in_f22;
  undefined8 in_f23;
  undefined8 in_f24;
  double dVar45;
  undefined8 in_f25;
  double dVar46;
  double dVar47;
  undefined8 in_f26;
  double dVar48;
  double dVar49;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar50;
  undefined8 in_f29;
  double dVar51;
  undefined8 in_f30;
  double dVar52;
  undefined8 in_f31;
  undefined8 uVar53;
  ushort local_1ac [2];
  float local_1a8 [4];
  short local_198 [6];
  float local_18c [17];
  float local_148 [6];
  undefined4 local_130;
  uint uStack300;
  undefined4 local_128;
  uint uStack292;
  uint local_120;
  short *local_11c;
  int local_118;
  int local_114;
  undefined auStack184 [16];
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
  
  uVar36 = 0;
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
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  __psq_st0(auStack152,(int)((ulonglong)in_f22 >> 0x20),0);
  __psq_st1(auStack152,(int)in_f22,0);
  __psq_st0(auStack168,(int)((ulonglong)in_f21 >> 0x20),0);
  __psq_st1(auStack168,(int)in_f21,0);
  __psq_st0(auStack184,(int)((ulonglong)in_f20 >> 0x20),0);
  __psq_st1(auStack184,(int)in_f20,0);
  uVar53 = FUN_802860a8();
  pfVar13 = (float *)((ulonglong)uVar53 >> 0x20);
  pfVar16 = (float *)uVar53;
  if (param_5 == 0) {
    iVar30 = (int)param_7;
    iVar26 = DAT_803dcf38;
    iVar17 = DAT_803dcf34;
    iVar27 = DAT_803dcf3c;
    if (iVar30 == -1) {
      local_120 = 0;
      uVar28 = (uint)DAT_803dcf5e;
    }
    else {
      local_120 = (uint)(ushort)(&DAT_8038d840)[iVar30 * 2];
      uVar28 = (uint)(ushort)(&DAT_8038d842)[iVar30 * 2];
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
  dVar42 = (double)local_1a8[2];
  local_1a8[0] = pfVar13[2];
  local_1a8[3] = *pfVar16;
  dVar40 = (double)local_1a8[3];
  local_1a8[1] = pfVar16[2];
  dVar39 = dVar42;
  if (dVar42 < dVar40) {
    dVar39 = dVar40;
    dVar40 = dVar42;
  }
  dVar37 = (double)local_1a8[0];
  dVar41 = (double)local_1a8[1];
  dVar42 = dVar37;
  if (dVar37 < dVar41) {
    dVar42 = dVar41;
    dVar41 = dVar37;
  }
  dVar45 = (double)((float)(dVar40 - extraout_f1) - FLOAT_803deccc);
  dVar37 = (double)((float)(dVar39 + extraout_f1) + FLOAT_803deccc);
  dVar41 = (double)((float)(dVar41 - extraout_f1) - FLOAT_803deccc);
  dVar40 = (double)((float)(dVar42 + extraout_f1) + FLOAT_803deccc);
  iVar29 = 0;
  iVar30 = 1;
  local_11c = local_198;
  pfVar25 = local_148;
  pfVar31 = local_18c + 0xc;
  local_118 = local_120 << 1;
  local_114 = local_120 << 4;
  dVar39 = extraout_f1;
  do {
    if (iVar30 == 0) {
      if ((iVar29 != 0) && (param_4 != (int *)0x0)) {
        iVar30 = iVar29 + -1;
        if (cVar8 == '\0') {
          iVar30 = 0;
        }
        dVar39 = (double)FUN_802931a0((double)((*pfVar16 - local_1a8[2]) * (*pfVar16 - local_1a8[2])
                                              + (pfVar16[2] - local_1a8[0]) *
                                                (pfVar16[2] - local_1a8[0])));
        param_4[0x11] = (int)(float)((double)local_148[0] * dVar39);
        param_4[0x12] = (int)local_18c[iVar30 + 0xc];
        iVar30 = (int)local_198[iVar30];
        if (iVar27 != 0) {
          iVar30 = (int)*(short *)(iVar27 + iVar30 * 2);
        }
        psVar15 = (short *)(iVar17 + iVar30 * 0x10);
        sVar6 = psVar15[2];
        sVar7 = psVar15[3];
        if (((int)*(char *)(psVar15 + 1) & 0x80U) == 0) {
          uStack292 = (int)*(char *)psVar15 ^ 0x80000000;
          fVar3 = (float)((double)CONCAT44(0x43300000,uStack292) - DOUBLE_803decd8);
          uStack300 = (int)*(char *)((int)psVar15 + 1) ^ 0x80000000;
          local_130 = 0x43300000;
          fVar4 = (float)((double)CONCAT44(0x43300000,uStack300) - DOUBLE_803decd8);
        }
        else {
          uStack292 = (int)*psVar15 ^ 0x80000000;
          fVar3 = (float)((double)CONCAT44(0x43300000,uStack292) - DOUBLE_803decd8);
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
        DAT_803dcf4c = DAT_803dcf4c + '\x01';
        iVar29 = 1;
        *pfVar16 = local_1a8[3];
        pfVar16[2] = local_1a8[1];
      }
      __psq_l0(auStack8,uVar36);
      __psq_l1(auStack8,uVar36);
      __psq_l0(auStack24,uVar36);
      __psq_l1(auStack24,uVar36);
      __psq_l0(auStack40,uVar36);
      __psq_l1(auStack40,uVar36);
      __psq_l0(auStack56,uVar36);
      __psq_l1(auStack56,uVar36);
      __psq_l0(auStack72,uVar36);
      __psq_l1(auStack72,uVar36);
      __psq_l0(auStack88,uVar36);
      __psq_l1(auStack88,uVar36);
      __psq_l0(auStack104,uVar36);
      __psq_l1(auStack104,uVar36);
      __psq_l0(auStack120,uVar36);
      __psq_l1(auStack120,uVar36);
      __psq_l0(auStack136,uVar36);
      __psq_l1(auStack136,uVar36);
      __psq_l0(auStack152,uVar36);
      __psq_l1(auStack152,uVar36);
      __psq_l0(auStack168,uVar36);
      __psq_l1(auStack168,uVar36);
      __psq_l0(auStack184,uVar36);
      __psq_l1(auStack184,uVar36);
      FUN_802860f4(iVar29);
      return;
    }
    iVar30 = 0;
    psVar32 = (short *)(iVar27 + local_118);
    psVar15 = (short *)(iVar17 + local_114);
    for (uVar11 = local_120; (int)uVar11 < (int)uVar28; uVar11 = uVar11 + 1) {
      in_f0 = (double)FLOAT_803decd0;
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
          if ((param_3 & 4) != 0) goto LAB_80063d10;
          unaff_r19 = '\0';
        }
        if ((param_3 & 2) != 0) {
          unaff_r19 = '\x01';
        }
        pfVar20 = (float *)(iVar26 + psVar18[2] * 0xc);
        dVar52 = (double)*pfVar20;
        fVar3 = pfVar20[1];
        dVar51 = (double)pfVar20[2];
        pfVar20 = (float *)(iVar26 + psVar18[3] * 0xc);
        dVar50 = (double)*pfVar20;
        fVar4 = pfVar20[1];
        dVar42 = (double)pfVar20[2];
        if (((((dVar45 <= dVar52) || (dVar45 <= dVar50)) &&
             ((dVar52 <= dVar37 || (dVar50 <= dVar37)))) &&
            ((dVar41 <= dVar51 || (dVar41 <= dVar42)))) &&
           ((dVar51 <= dVar40 || (dVar42 <= dVar40)))) {
          fVar10 = fVar3;
          if (fVar4 < fVar3) {
            fVar10 = fVar4;
          }
          if (((int)*(char *)(psVar18 + 1) & 0x80U) == 0) {
            uStack300 = (int)*(char *)psVar18 ^ 0x80000000;
            fVar1 = (float)((double)CONCAT44(0x43300000,uStack300) - DOUBLE_803decd8);
            fVar2 = (float)((double)CONCAT44(0x43300000,
                                             (int)*(char *)((int)psVar18 + 1) ^ 0x80000000) -
                           DOUBLE_803decd8);
          }
          else {
            uStack300 = (int)*psVar18 ^ 0x80000000;
            fVar1 = (float)((double)CONCAT44(0x43300000,uStack300) - DOUBLE_803decd8);
            fVar2 = fVar1;
          }
          local_130 = 0x43300000;
          fVar9 = fVar3 + fVar1;
          if (fVar3 + fVar1 < fVar4 + fVar2) {
            fVar9 = fVar4 + fVar2;
          }
          uStack292 = (int)param_8 ^ 0x80000000;
          local_128 = 0x43300000;
          if ((fVar10 - (float)((double)CONCAT44(0x43300000,(int)param_8 ^ 0x80000000) -
                               DOUBLE_803decd8) <= pfVar13[1]) &&
             (pfVar13[1] <=
              fVar9 + (float)((double)CONCAT44(0x43300000,uStack292) - DOUBLE_803decd8))) {
            dVar48 = (double)(float)(dVar50 - dVar52);
            dVar46 = (double)(float)(dVar42 - dVar51);
            if (FLOAT_803decb4 != (float)(dVar48 * dVar48 + (double)(float)(dVar46 * dVar46))) {
              dVar38 = (double)FUN_802931a0();
              local_18c[8] = (float)(dVar48 / dVar38);
              dVar49 = (double)local_18c[8];
              local_18c[4] = (float)(dVar46 / dVar38);
              dVar47 = (double)local_18c[4];
              local_18c[0] = -(float)(dVar49 * dVar52 + (double)(float)(dVar47 * dVar51));
              dVar44 = -dVar49;
              local_18c[9] = (float)dVar44;
              dVar48 = -dVar47;
              local_18c[5] = (float)dVar48;
              dVar43 = (double)(float)dVar44;
              dVar46 = (double)(float)dVar48;
              local_18c[1] = -(float)(dVar43 * dVar50 + (double)(float)(dVar46 * dVar42));
              local_18c[10] = (float)dVar48;
              local_18c[6] = local_18c[8];
              local_18c[2] = -((float)(dVar46 * (double)(float)((double)FLOAT_803decb8 * dVar46 +
                                                               dVar52)) +
                              (float)(dVar49 * (double)(float)((double)FLOAT_803decb8 * dVar49 +
                                                              dVar51)));
              local_18c[11] = local_18c[4];
              local_18c[7] = (float)dVar44;
              local_18c[3] = -((float)(dVar47 * (double)(float)(dVar39 * dVar47 + dVar52)) +
                              (float)(dVar43 * (double)(float)(dVar39 * dVar43 + dVar51)));
              FLOAT_803dcf54 = FLOAT_803decd4 * (float)(dVar47 * dVar39);
              FLOAT_803dcf50 = FLOAT_803decd4 * (float)(dVar43 * dVar39);
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
                  if (*pfVar21 + fVar4 * *pfVar19 + fVar3 * *pfVar14 < FLOAT_803decb4) {
                    *puVar22 = *puVar22 | uVar12;
                  }
                  uVar12 = (ushort)((int)(short)uVar12 << 1);
                  if (pfVar21[1] + fVar4 * pfVar19[1] + fVar3 * pfVar14[1] < FLOAT_803decb4) {
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
              in_f0 = (double)FLOAT_803decc4;
              if ((local_1ac[0] & 0xc) == 0xc) {
                if ((local_1ac[0] & 1) == 0) {
                  if ((local_1ac[0] & 2) == 0) {
                    if (unaff_r19 != '\0') {
                      local_1a8[3] = local_1a8[3] + FLOAT_803dcf54;
                      local_1a8[1] = local_1a8[1] + FLOAT_803dcf50;
                    }
                  }
                  else {
                    iVar30 = FUN_800630d8(dVar50,dVar42,dVar39,local_1a8 + 2,local_1a8,unaff_r19);
                    in_f0 = (double)FLOAT_803decc4;
                  }
                }
                else {
                  iVar30 = FUN_800630d8(dVar52,dVar51,dVar39,local_1a8 + 2,local_1a8,unaff_r19);
                  in_f0 = (double)FLOAT_803decb4;
                }
              }
              else if (((local_1ac[0] ^ local_1ac[1]) & 0xc) != 0) {
                if ((local_1ac[0] & local_1ac[1] & 1) == 0) {
                  if ((local_1ac[0] & local_1ac[1] & 2) == 0) {
                    if ((local_1ac[0] & 4) != 0) {
                      fVar3 = local_18c[3] +
                              local_1a8[2] * local_18c[11] + local_1a8[0] * local_18c[7];
                      fVar4 = local_18c[3] +
                              local_1a8[3] * local_18c[11] + local_1a8[1] * local_18c[7];
                      FLOAT_803dcf58 = FLOAT_803decb4;
                      if (fVar3 != fVar4) {
                        FLOAT_803dcf58 = fVar3 / (fVar3 - fVar4);
                      }
                      dVar46 = (double)((local_1a8[3] - local_1a8[2]) * FLOAT_803dcf58 +
                                       local_1a8[2]);
                      dVar48 = (double)((local_1a8[1] - local_1a8[0]) * FLOAT_803dcf58 +
                                       local_1a8[0]);
                      bVar33 = local_18c[0] +
                               (float)(dVar46 * (double)local_18c[8] +
                                      (double)(float)(dVar48 * (double)local_18c[4])) <
                               FLOAT_803decb4;
                      if (bVar33) {
                        iVar30 = FUN_800630d8(dVar52,dVar51,dVar39,local_1a8 + 2,local_1a8,unaff_r19
                                             );
                        in_f0 = (double)FLOAT_803decb4;
                      }
                      bVar34 = local_18c[1] +
                               (float)(dVar46 * (double)local_18c[9] +
                                      (double)(float)(dVar48 * (double)local_18c[5])) <
                               FLOAT_803decb4;
                      if (bVar34) {
                        iVar30 = FUN_800630d8(dVar50,dVar42,dVar39,local_1a8 + 2,local_1a8,unaff_r19
                                             );
                        in_f0 = (double)FLOAT_803decc4;
                      }
                      if ((!bVar34 && !bVar33) && (iVar30 = 1, unaff_r19 != '\0')) {
                        if (cVar8 == '\0') {
                          local_1a8[3] = (float)dVar46;
                          local_1a8[1] = (float)dVar48;
                          iVar24 = 0;
                          do {
                            if (FLOAT_803db660 <=
                                local_18c[3] +
                                local_1a8[3] * local_18c[11] + local_1a8[1] * local_18c[7])
                            goto LAB_80063ce8;
                            local_1a8[3] = local_1a8[3] + FLOAT_803db660 * local_18c[11];
                            local_1a8[1] = local_1a8[1] + FLOAT_803db660 * local_18c[7];
                            iVar24 = iVar24 + 1;
                          } while (iVar24 < 0xb);
                          local_1a8[3] = local_1a8[2];
                          local_1a8[1] = local_1a8[0];
                        }
                        else {
                          fVar3 = local_18c[3] +
                                  local_1a8[3] * local_18c[11] + local_1a8[1] * local_18c[7];
                          local_1a8[3] = -(fVar3 * local_18c[11] - local_1a8[3]);
                          local_1a8[1] = -(fVar3 * local_18c[7] - local_1a8[1]);
                          iVar24 = 0;
                          do {
                            if (FLOAT_803db660 <=
                                local_18c[3] +
                                local_1a8[3] * local_18c[11] + local_1a8[1] * local_18c[7])
                            goto LAB_80063ce8;
                            local_1a8[3] = local_1a8[3] + FLOAT_803db660 * local_18c[11];
                            local_1a8[1] = local_1a8[1] + FLOAT_803db660 * local_18c[7];
                            iVar24 = iVar24 + 1;
                          } while (iVar24 < 0xb);
                          local_1a8[3] = local_1a8[2];
                          local_1a8[1] = local_1a8[0];
                        }
LAB_80063ce8:
                        dVar42 = (double)FUN_802931a0((double)((float)((double)local_1a8[3] - dVar52
                                                                      ) *
                                                               (float)((double)local_1a8[3] - dVar52
                                                                      ) +
                                                              (float)((double)local_1a8[1] - dVar51)
                                                              * (float)((double)local_1a8[1] -
                                                                       dVar51)));
                        in_f0 = (double)(float)(dVar42 / dVar38);
                      }
                    }
                  }
                  else {
                    iVar30 = FUN_800630d8(dVar50,dVar42,dVar39,local_1a8 + 2,local_1a8,unaff_r19);
                    in_f0 = (double)FLOAT_803decc4;
                  }
                }
                else {
                  iVar30 = FUN_800630d8(dVar52,dVar51,dVar39,local_1a8 + 2,local_1a8,unaff_r19);
                  in_f0 = (double)FLOAT_803decb4;
                }
              }
              if (iVar30 != 0) break;
            }
          }
        }
      }
LAB_80063d10:
      psVar32 = psVar32 + 1;
      psVar15 = psVar15 + 8;
    }
    if (iVar30 != 0) {
      *local_11c = (short)uVar11;
      *pfVar25 = FLOAT_803dcf58;
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

