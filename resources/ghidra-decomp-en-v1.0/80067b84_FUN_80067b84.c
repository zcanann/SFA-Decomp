// Function: FUN_80067b84
// Entry: 80067b84
// Size: 2632 bytes

/* WARNING: Removing unreachable block (ram,0x800685a4) */
/* WARNING: Removing unreachable block (ram,0x80068594) */
/* WARNING: Removing unreachable block (ram,0x80068584) */
/* WARNING: Removing unreachable block (ram,0x80068574) */
/* WARNING: Removing unreachable block (ram,0x80068564) */
/* WARNING: Removing unreachable block (ram,0x8006855c) */
/* WARNING: Removing unreachable block (ram,0x8006856c) */
/* WARNING: Removing unreachable block (ram,0x8006857c) */
/* WARNING: Removing unreachable block (ram,0x8006858c) */
/* WARNING: Removing unreachable block (ram,0x8006859c) */
/* WARNING: Removing unreachable block (ram,0x800685ac) */

void FUN_80067b84(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,double param_6,undefined8 param_7,undefined4 param_8,
                 undefined4 param_9,int *param_10,uint param_11)

{
  float fVar1;
  float fVar2;
  float fVar3;
  ushort uVar4;
  bool bVar5;
  ushort *puVar6;
  undefined2 *puVar7;
  short *psVar8;
  int iVar9;
  undefined uVar11;
  float *pfVar10;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  int iVar19;
  float *pfVar20;
  int iVar21;
  float *pfVar22;
  int unaff_r24;
  int unaff_r25;
  uint uVar23;
  float *pfVar24;
  short *psVar25;
  float *pfVar26;
  undefined4 uVar27;
  double dVar28;
  double dVar29;
  double extraout_f1;
  double dVar30;
  double dVar31;
  double dVar32;
  undefined8 in_f21;
  double dVar33;
  undefined8 in_f22;
  double dVar34;
  undefined8 in_f23;
  undefined8 in_f24;
  double dVar35;
  undefined8 in_f25;
  double dVar36;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar37;
  undefined8 in_f28;
  double dVar38;
  undefined8 in_f29;
  double dVar39;
  double dVar40;
  undefined8 in_f30;
  double dVar41;
  undefined8 in_f31;
  undefined8 uVar42;
  float local_1c8;
  float local_1c4;
  undefined auStack448 [4];
  float local_1bc;
  float local_1b8;
  float local_1b4;
  float local_1b0;
  float local_1ac;
  float local_1a8;
  float local_1a4;
  float local_1a0 [2];
  double local_198;
  double local_190;
  double local_188;
  undefined4 local_180;
  uint uStack380;
  undefined4 local_178;
  uint uStack372;
  undefined4 local_170;
  uint uStack364;
  undefined4 local_168;
  uint uStack356;
  undefined4 local_160;
  uint uStack348;
  undefined4 local_158;
  uint uStack340;
  undefined4 local_150;
  uint uStack332;
  undefined4 local_148;
  uint uStack324;
  undefined4 local_140;
  uint uStack316;
  undefined4 local_138;
  uint uStack308;
  undefined4 local_130;
  uint uStack300;
  undefined4 local_128;
  uint uStack292;
  undefined4 local_120;
  uint uStack284;
  undefined4 local_118;
  uint uStack276;
  undefined4 local_110;
  uint uStack268;
  uint local_108;
  int local_104;
  uint local_100;
  uint local_fc;
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
  
  uVar27 = 0;
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
  uVar42 = FUN_802860a8();
  pfVar10 = (float *)((ulonglong)uVar42 >> 0x20);
  iVar21 = (int)uVar42;
  local_1c8 = (float)param_3;
  local_1c4 = (float)param_6;
  iVar19 = *param_10;
  dVar33 = extraout_f1;
  FUN_800226cc(param_2,(double)(float)param_3,param_4,*(undefined4 *)(iVar21 + 8),&local_1ac,
               auStack448,&local_1bc);
  FUN_800226cc(param_2,(double)local_1c8,param_7,*(undefined4 *)(iVar21 + 8),&local_1a8,&local_1c8,
               &local_1b8);
  FUN_800226cc(param_5,(double)local_1c4,param_4,*(undefined4 *)(iVar21 + 8),&local_1a4,auStack448,
               &local_1b4);
  FUN_800226cc(param_5,(double)local_1c4,param_7,*(undefined4 *)(iVar21 + 8),local_1a0,&local_1c4,
               &local_1b0);
  dVar35 = (double)local_1ac;
  dVar36 = (double)local_1bc;
  dVar28 = (double)local_1a8;
  dVar34 = dVar35;
  if (dVar28 < dVar35) {
    dVar34 = dVar28;
  }
  if (dVar35 < dVar28) {
    dVar35 = dVar28;
  }
  dVar29 = (double)local_1b8;
  dVar28 = dVar36;
  if (dVar29 < dVar36) {
    dVar28 = dVar29;
  }
  if (dVar36 < dVar29) {
    dVar36 = dVar29;
  }
  dVar29 = (double)local_1a4;
  if (dVar29 < dVar34) {
    dVar34 = dVar29;
  }
  if (dVar35 < dVar29) {
    dVar35 = dVar29;
  }
  dVar29 = (double)local_1b4;
  if (dVar29 < dVar28) {
    dVar28 = dVar29;
  }
  if (dVar36 < dVar29) {
    dVar36 = dVar29;
  }
  dVar29 = (double)local_1a0[0];
  if (dVar29 < dVar34) {
    dVar34 = dVar29;
  }
  if (dVar35 < dVar29) {
    dVar35 = dVar29;
  }
  dVar29 = (double)local_1b0;
  if (dVar29 < dVar28) {
    dVar28 = dVar29;
  }
  if (dVar36 < dVar29) {
    dVar36 = dVar29;
  }
  local_108 = (uint)*(ushort *)(iVar19 + 0xf0);
  local_fc = param_11 & 0x20;
  local_100 = param_11 & 8;
  for (local_104 = 0; local_104 < (int)local_108; local_104 = local_104 + 1) {
    puVar6 = (ushort *)FUN_80028364(iVar19,local_104);
    if (((((*(uint *)(puVar6 + 8) & 0x100000) == 0) &&
         (((((*(uint *)(puVar6 + 8) & 0x8000000) == 0 || (local_fc != 0)) &&
           (local_198 = (double)CONCAT44(0x43300000,(int)(short)puVar6[2] ^ 0x80000000),
           dVar34 <= (double)(float)((double)(float)(local_198 - DOUBLE_803decd8) * dVar33))) &&
          ((local_198 = (double)CONCAT44(0x43300000,(int)(short)puVar6[1] ^ 0x80000000),
           (double)(float)((double)(float)(local_198 - DOUBLE_803decd8) * dVar33) <= dVar35 &&
           (local_198 = (double)CONCAT44(0x43300000,(int)(short)puVar6[4] ^ 0x80000000),
           local_1c8 <= (float)((double)(float)(local_198 - DOUBLE_803decd8) * dVar33))))))) &&
        (local_198 = (double)CONCAT44(0x43300000,(int)(short)puVar6[3] ^ 0x80000000),
        (float)((double)(float)(local_198 - DOUBLE_803decd8) * dVar33) <= local_1c4)) &&
       ((local_198 = (double)CONCAT44(0x43300000,(int)(short)puVar6[6] ^ 0x80000000),
        dVar28 <= (double)(float)((double)(float)(local_198 - DOUBLE_803decd8) * dVar33) &&
        (local_198 = (double)CONCAT44(0x43300000,(int)(short)puVar6[5] ^ 0x80000000),
        (double)(float)((double)(float)(local_198 - DOUBLE_803decd8) * dVar33) <= dVar36)))) {
      uVar4 = puVar6[10];
      for (uVar23 = (uint)*puVar6; (int)uVar23 < (int)(uint)uVar4; uVar23 = uVar23 + 1) {
        puVar7 = (undefined2 *)FUN_80028354(iVar19,uVar23);
        dVar39 = (double)FLOAT_803decf0;
        dVar29 = (double)FLOAT_803decf4;
        iVar21 = 0;
        pfVar20 = pfVar10;
        dVar37 = dVar29;
        dVar38 = dVar39;
        dVar40 = dVar29;
        dVar41 = dVar39;
        do {
          psVar8 = (short *)FUN_80028414(iVar19,*puVar7);
          if ((*(ushort *)(iVar19 + 2) & 0x800) == 0) {
            local_188 = (double)CONCAT44(0x43300000,(int)*psVar8 ^ 0x80000000);
            fVar1 = (float)((double)(float)(local_188 - DOUBLE_803decd8) * dVar33) * FLOAT_803decf8;
            local_190 = (double)CONCAT44(0x43300000,(int)psVar8[1] ^ 0x80000000);
            fVar2 = (float)((double)(float)(local_190 - DOUBLE_803decd8) * dVar33) * FLOAT_803decf8;
            local_198 = (double)CONCAT44(0x43300000,(int)psVar8[2] ^ 0x80000000);
            fVar3 = (float)((double)(float)(local_198 - DOUBLE_803decd8) * dVar33) * FLOAT_803decf8;
          }
          else {
            local_198 = (double)CONCAT44(0x43300000,(int)*psVar8 ^ 0x80000000);
            fVar1 = (float)((double)(float)(local_198 - DOUBLE_803decd8) * dVar33);
            local_190 = (double)CONCAT44(0x43300000,(int)psVar8[1] ^ 0x80000000);
            fVar2 = (float)((double)(float)(local_190 - DOUBLE_803decd8) * dVar33);
            local_188 = (double)CONCAT44(0x43300000,(int)psVar8[2] ^ 0x80000000);
            fVar3 = (float)((double)(float)(local_188 - DOUBLE_803decd8) * dVar33);
          }
          dVar32 = (double)fVar2;
          dVar31 = (double)fVar1;
          dVar30 = (double)fVar3;
          if (dVar40 < dVar31) {
            dVar40 = dVar31;
          }
          if (dVar31 < dVar38) {
            dVar38 = dVar31;
          }
          if (dVar37 < dVar32) {
            unaff_r24 = iVar21;
            dVar37 = dVar32;
          }
          if (dVar32 < dVar41) {
            unaff_r25 = iVar21;
            dVar41 = dVar32;
          }
          if (dVar29 < dVar30) {
            dVar29 = dVar30;
          }
          if (dVar30 < dVar39) {
            dVar39 = dVar30;
          }
          local_188 = (double)(longlong)(int)fVar1;
          *(short *)(pfVar20 + 4) = (short)(int)fVar1;
          local_190 = (double)(longlong)(int)fVar2;
          *(short *)((int)pfVar20 + 0x16) = (short)(int)fVar2;
          local_198 = (double)(longlong)(int)fVar3;
          *(short *)(pfVar20 + 7) = (short)(int)fVar3;
          puVar7 = puVar7 + 1;
          pfVar20 = (float *)((int)pfVar20 + 2);
          iVar21 = iVar21 + 1;
        } while (iVar21 < 3);
        if ((((dVar41 <= (double)local_1c4) && ((double)local_1c8 <= dVar37)) && (dVar38 <= dVar35))
           && (((dVar34 <= dVar40 && (dVar39 <= dVar36)) && (dVar28 <= dVar29)))) {
          pfVar22 = pfVar10 + 4;
          psVar8 = (short *)((int)pfVar10 + 0x16);
          pfVar20 = pfVar10 + 7;
          iVar12 = (int)*(short *)((int)pfVar10 + 0x1e);
          iVar13 = (int)*(short *)pfVar20;
          iVar17 = (int)*(short *)((int)pfVar10 + 0x1a);
          iVar21 = (int)*(short *)(pfVar10 + 8);
          iVar16 = (int)*psVar8;
          iVar18 = (int)*(short *)(pfVar10 + 6);
          local_188 = (double)CONCAT44(0x43300000,
                                       iVar16 * (iVar12 - iVar21) +
                                       iVar18 * (iVar21 - iVar13) + iVar17 * (iVar13 - iVar12) ^
                                       0x80000000);
          dVar39 = (double)(float)(local_188 - DOUBLE_803decd8);
          iVar14 = (int)*(short *)((int)pfVar10 + 0x12);
          iVar15 = (int)*(short *)pfVar22;
          iVar9 = (int)*(short *)(pfVar10 + 5);
          local_190 = (double)CONCAT44(0x43300000,
                                       iVar13 * (iVar14 - iVar9) +
                                       iVar12 * (iVar9 - iVar15) + iVar21 * (iVar15 - iVar14) ^
                                       0x80000000);
          dVar37 = (double)(float)(local_190 - DOUBLE_803decd8);
          local_198 = (double)CONCAT44(0x43300000,
                                       iVar15 * (iVar18 - iVar17) +
                                       iVar14 * (iVar17 - iVar16) + iVar9 * (iVar16 - iVar18) ^
                                       0x80000000);
          dVar38 = (double)(float)(local_198 - DOUBLE_803decd8);
          dVar29 = (double)FUN_802931a0((double)(float)(dVar38 * dVar38 +
                                                       (double)(float)(dVar39 * dVar39 +
                                                                      (double)(float)(dVar37 * 
                                                  dVar37))));
          if ((double)FLOAT_803decb4 < dVar29) {
            dVar29 = (double)(float)((double)FLOAT_803decc4 / dVar29);
            pfVar10[1] = (float)(dVar39 * dVar29);
            pfVar10[2] = (float)(dVar37 * dVar29);
            pfVar10[3] = (float)(dVar38 * dVar29);
            dVar29 = DOUBLE_803decd8;
            if (((local_100 == 0) ||
                ((pfVar10[2] < FLOAT_803decb0 && (FLOAT_803decec < pfVar10[2])))) &&
               (((param_11 & 4) == 0 ||
                ((FLOAT_803decb0 <= pfVar10[2] || (pfVar10[2] <= FLOAT_803decec)))))) {
              local_188 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar10 + 7) ^ 0x80000000);
              local_190 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar10 + 4) ^ 0x80000000);
              local_198 = (double)CONCAT44(0x43300000,
                                           (int)*(short *)((int)pfVar10 + 0x16) ^ 0x80000000);
              *pfVar10 = -(pfVar10[3] * (float)(local_188 - DOUBLE_803decd8) +
                          pfVar10[1] * (float)(local_190 - DOUBLE_803decd8) +
                          pfVar10[2] * (float)(local_198 - DOUBLE_803decd8));
              bVar5 = false;
              iVar9 = 0;
              dVar39 = (double)FLOAT_803decb4;
              iVar21 = 0;
              pfVar24 = pfVar20;
              psVar25 = psVar8;
              pfVar26 = pfVar22;
              do {
                iVar12 = iVar9 + 1;
                if (2 < iVar12) {
                  iVar12 = 0;
                }
                uStack308 = (int)*(short *)pfVar26 ^ 0x80000000;
                local_188 = (double)CONCAT44(0x43300000,uStack308);
                fVar1 = pfVar10[1] + (float)(local_188 - dVar29);
                uStack372 = (int)*psVar25 ^ 0x80000000;
                local_190 = (double)CONCAT44(0x43300000,uStack372);
                fVar2 = pfVar10[2] + (float)(local_190 - dVar29);
                uStack348 = (int)*(short *)pfVar24 ^ 0x80000000;
                local_198 = (double)CONCAT44(0x43300000,uStack348);
                fVar3 = pfVar10[3] + (float)(local_198 - dVar29);
                uStack364 = (uint)*(short *)((int)pfVar20 + iVar12 * 2);
                uStack380 = (int)*(short *)pfVar24 - uStack364 ^ 0x80000000;
                local_180 = 0x43300000;
                local_178 = 0x43300000;
                uStack364 = uStack364 ^ 0x80000000;
                local_170 = 0x43300000;
                uStack356 = (int)psVar8[iVar12] ^ 0x80000000;
                local_168 = 0x43300000;
                local_160 = 0x43300000;
                dVar41 = (double)(fVar2 * (float)((double)CONCAT44(0x43300000,uStack380) - dVar29) +
                                 (float)((double)CONCAT44(0x43300000,uStack372) - dVar29) *
                                 ((float)((double)CONCAT44(0x43300000,uStack364) - dVar29) - fVar3)
                                 + (float)((double)CONCAT44(0x43300000,uStack356) - dVar29) *
                                   (fVar3 - (float)((double)CONCAT44(0x43300000,uStack348) - dVar29)
                                   ));
                uStack324 = (uint)*(short *)((int)pfVar22 + iVar12 * 2);
                uStack340 = (int)*(short *)pfVar26 - uStack324 ^ 0x80000000;
                local_158 = 0x43300000;
                local_150 = 0x43300000;
                uStack324 = uStack324 ^ 0x80000000;
                local_148 = 0x43300000;
                local_140 = 0x43300000;
                local_138 = 0x43300000;
                dVar40 = (double)(fVar3 * (float)((double)CONCAT44(0x43300000,uStack340) - dVar29) +
                                 (float)((double)CONCAT44(0x43300000,uStack348) - dVar29) *
                                 ((float)((double)CONCAT44(0x43300000,uStack324) - dVar29) - fVar1)
                                 + (float)((double)CONCAT44(0x43300000,uStack364) - dVar29) *
                                   (fVar1 - (float)((double)CONCAT44(0x43300000,uStack308) - dVar29)
                                   ));
                uStack300 = (int)*psVar25 - (int)psVar8[iVar12] ^ 0x80000000;
                local_130 = 0x43300000;
                local_128 = 0x43300000;
                local_120 = 0x43300000;
                local_118 = 0x43300000;
                local_110 = 0x43300000;
                dVar38 = (double)(fVar1 * (float)((double)CONCAT44(0x43300000,uStack300) - dVar29) +
                                 (float)((double)CONCAT44(0x43300000,uStack308) - dVar29) *
                                 ((float)((double)CONCAT44(0x43300000,uStack356) - dVar29) - fVar2)
                                 + (float)((double)CONCAT44(0x43300000,uStack324) - dVar29) *
                                   (fVar2 - (float)((double)CONCAT44(0x43300000,uStack372) - dVar29)
                                   ));
                uStack332 = uStack348;
                uStack316 = uStack364;
                uStack292 = uStack308;
                uStack284 = uStack356;
                uStack276 = uStack324;
                uStack268 = uStack372;
                dVar37 = (double)FUN_802931a0((double)(float)(dVar38 * dVar38 +
                                                             (double)(float)(dVar41 * dVar41 +
                                                                            (double)(float)(dVar40 *
                                                                                           dVar40)))
                                             );
                if (dVar37 <= dVar39) {
                  bVar5 = true;
                }
                else {
                  dVar37 = (double)(float)((double)FLOAT_803decc4 / dVar37);
                  dVar41 = (double)(float)(dVar41 * dVar37);
                  dVar40 = (double)(float)(dVar40 * dVar37);
                  dVar38 = (double)(float)(dVar38 * dVar37);
                }
                pfVar10[iVar21 + 9] = (float)dVar41;
                pfVar10[iVar21 + 10] = (float)dVar40;
                pfVar10[iVar21 + 0xb] = (float)dVar38;
                pfVar26 = (float *)((int)pfVar26 + 2);
                psVar25 = psVar25 + 1;
                pfVar24 = (float *)((int)pfVar24 + 2);
                iVar9 = iVar9 + 1;
                iVar21 = iVar21 + 3;
              } while (iVar9 < 3);
              if (!bVar5) {
                uVar11 = FUN_80060668(puVar6);
                *(undefined *)(pfVar10 + 0x12) = uVar11;
                *(byte *)((int)pfVar10 + 0x4a) = (byte)(unaff_r24 << 4) | (byte)unaff_r25;
                *(undefined *)((int)pfVar10 + 0x49) = 10;
                *(byte *)((int)pfVar10 + 0x49) = *(byte *)((int)pfVar10 + 0x49) | 8;
                pfVar10 = pfVar10 + 0x13;
                if (DAT_803dcf70 <= pfVar10) goto LAB_8006855c;
              }
            }
          }
        }
      }
    }
  }
LAB_8006855c:
  __psq_l0(auStack8,uVar27);
  __psq_l1(auStack8,uVar27);
  __psq_l0(auStack24,uVar27);
  __psq_l1(auStack24,uVar27);
  __psq_l0(auStack40,uVar27);
  __psq_l1(auStack40,uVar27);
  __psq_l0(auStack56,uVar27);
  __psq_l1(auStack56,uVar27);
  __psq_l0(auStack72,uVar27);
  __psq_l1(auStack72,uVar27);
  __psq_l0(auStack88,uVar27);
  __psq_l1(auStack88,uVar27);
  __psq_l0(auStack104,uVar27);
  __psq_l1(auStack104,uVar27);
  __psq_l0(auStack120,uVar27);
  __psq_l1(auStack120,uVar27);
  __psq_l0(auStack136,uVar27);
  __psq_l1(auStack136,uVar27);
  __psq_l0(auStack152,uVar27);
  __psq_l1(auStack152,uVar27);
  __psq_l0(auStack168,uVar27);
  __psq_l1(auStack168,uVar27);
  FUN_802860f4(pfVar10);
  return;
}

