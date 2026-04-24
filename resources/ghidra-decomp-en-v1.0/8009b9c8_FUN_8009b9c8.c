// Function: FUN_8009b9c8
// Entry: 8009b9c8
// Size: 9252 bytes

/* WARNING: Removing unreachable block (ram,0x8009ddc4) */
/* WARNING: Removing unreachable block (ram,0x8009ddb4) */
/* WARNING: Removing unreachable block (ram,0x8009dda4) */
/* WARNING: Removing unreachable block (ram,0x8009dd94) */
/* WARNING: Removing unreachable block (ram,0x8009dd84) */
/* WARNING: Removing unreachable block (ram,0x8009dd8c) */
/* WARNING: Removing unreachable block (ram,0x8009dd9c) */
/* WARNING: Removing unreachable block (ram,0x8009ddac) */
/* WARNING: Removing unreachable block (ram,0x8009ddbc) */
/* WARNING: Removing unreachable block (ram,0x8009ddcc) */

void FUN_8009b9c8(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  uint uVar7;
  byte bVar8;
  short sVar9;
  short sVar10;
  short sVar11;
  int iVar12;
  int iVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  char *pcVar16;
  uint uVar17;
  short sVar18;
  int iVar19;
  int iVar20;
  float *pfVar21;
  ushort *puVar22;
  short sVar23;
  short sVar24;
  short sVar25;
  short *psVar26;
  short *psVar27;
  short *psVar28;
  short sVar29;
  float *pfVar30;
  float *pfVar31;
  float *pfVar32;
  float *pfVar33;
  int iVar34;
  int iVar35;
  undefined4 uVar36;
  double dVar37;
  double dVar38;
  double dVar39;
  double dVar40;
  undefined8 in_f22;
  double dVar41;
  undefined8 in_f23;
  undefined8 in_f24;
  double in_f25;
  double in_f26;
  double in_f27;
  undefined8 in_f28;
  double dVar42;
  undefined8 in_f29;
  double dVar43;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar44;
  byte local_248;
  byte local_247;
  byte local_246 [2];
  float local_244;
  float local_240;
  float local_23c;
  float local_238;
  float local_234;
  float local_230;
  undefined auStack556 [4];
  undefined auStack552 [4];
  float local_224;
  float local_220;
  float local_21c;
  float local_218;
  ushort local_214;
  ushort local_212;
  ushort local_210;
  float local_20c;
  float local_208;
  float local_204;
  float local_200;
  double local_1f8;
  double local_1f0;
  double local_1e8;
  double local_1e0;
  double local_1d8;
  double local_1d0;
  double local_1c8;
  double local_1c0;
  double local_1b8;
  double local_1b0;
  double local_1a8;
  double local_1a0;
  double local_198;
  longlong local_190;
  longlong local_188;
  undefined4 local_180;
  uint uStack380;
  undefined4 local_178;
  uint uStack372;
  undefined4 local_170;
  uint uStack364;
  longlong local_168;
  longlong local_160;
  longlong local_158;
  undefined4 local_150;
  uint uStack332;
  undefined4 local_148;
  uint uStack324;
  undefined4 local_140;
  uint uStack316;
  longlong local_138;
  longlong local_130;
  longlong local_128;
  byte local_120;
  int local_11c;
  int local_118;
  int local_114;
  int local_110;
  float *local_10c;
  int local_108;
  int local_104;
  int local_100;
  int local_fc;
  uint *local_f8;
  byte local_f4;
  byte local_f3;
  byte local_f2;
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
  __psq_st1(auStack72,SUB84(in_f27,0),0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,SUB84(in_f26,0),0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,SUB84(in_f25,0),0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  __psq_st0(auStack152,(int)((ulonglong)in_f22 >> 0x20),0);
  __psq_st1(auStack152,(int)in_f22,0);
  FUN_802860a8();
  dVar41 = (double)FLOAT_803df354;
  dVar44 = (double)FLOAT_803df35c;
  dVar37 = dVar44;
  iVar12 = FUN_8002b9ec();
  iVar13 = FUN_8002b9ac();
  local_11c = FUN_80022a48();
  local_1f8 = (double)(longlong)(int)(FLOAT_803df3c8 * FLOAT_803db414);
  DAT_803dd268 = DAT_803dd268 + (short)(int)(FLOAT_803df3c8 * FLOAT_803db414);
  local_1f0 = (double)(longlong)(int)(FLOAT_803df3cc * FLOAT_803db414);
  DAT_803dd26a = DAT_803dd26a + (short)(int)(FLOAT_803df3cc * FLOAT_803db414);
  uVar14 = FUN_80089030();
  FUN_800897d4(uVar14,auStack556,auStack552,&local_224);
  uVar15 = FUN_8000f534();
  FUN_80247494(uVar15,auStack556,auStack556);
  dVar42 = -(double)local_224;
  if (-(double)local_224 < (double)FLOAT_803df3d0) {
    dVar42 = (double)FLOAT_803df3d0;
  }
  FUN_800898c8(uVar14,&local_248,&local_247,local_246);
  local_1e8 = (double)CONCAT44(0x43300000,(uint)local_248);
  iVar19 = (int)((double)(float)(local_1e8 - DOUBLE_803df378) * dVar42);
  local_1e0 = (double)(longlong)iVar19;
  local_f2 = (byte)iVar19;
  local_1d8 = (double)CONCAT44(0x43300000,(uint)local_247);
  iVar19 = (int)((double)(float)(local_1d8 - DOUBLE_803df378) * dVar42);
  local_1d0 = (double)(longlong)iVar19;
  local_f3 = (byte)iVar19;
  local_1c8 = (double)CONCAT44(0x43300000,(uint)local_246[0]);
  iVar19 = (int)((double)(float)(local_1c8 - DOUBLE_803df378) * dVar42);
  local_1c0 = (double)(longlong)iVar19;
  local_f4 = (byte)iVar19;
  iVar19 = 0;
  pcVar16 = &DAT_8039bbc8;
  iVar35 = 8;
  do {
    iVar20 = iVar19;
    if ((((((*pcVar16 != '\0') || (iVar20 = iVar19 + 1, pcVar16[1] != '\0')) ||
          (iVar20 = iVar19 + 2, pcVar16[2] != '\0')) ||
         (((iVar20 = iVar19 + 3, pcVar16[3] != '\0' || (iVar20 = iVar19 + 4, pcVar16[4] != '\0')) ||
          ((iVar20 = iVar19 + 5, pcVar16[5] != '\0' ||
           ((iVar20 = iVar19 + 6, pcVar16[6] != '\0' || (iVar20 = iVar19 + 7, pcVar16[7] != '\0'))))
          )))) || (iVar20 = iVar19 + 8, pcVar16[8] != '\0')) ||
       (iVar20 = iVar19 + 9, pcVar16[9] != '\0')) goto LAB_8009bc84;
    pcVar16 = pcVar16 + 10;
    iVar19 = iVar19 + 10;
    iVar35 = iVar35 + -1;
  } while (iVar35 != 0);
  iVar20 = -1;
LAB_8009bc84:
  if (iVar20 != -1) {
    FUN_800229f8(local_11c,(&DAT_8039bd58)[iVar20],0x7e);
    local_120 = 1;
    local_118 = local_11c;
    FUN_8000faac();
    if (iVar13 != 0) {
      dVar37 = (double)FUN_80138f78(iVar13);
    }
    if (iVar12 != 0) {
      dVar44 = (double)FUN_8029610c(iVar12);
    }
    uVar14 = 0;
    local_fc = local_f2 + 1;
    local_100 = local_f3 + 1;
    local_104 = local_f4 + 1;
    dVar42 = (double)FLOAT_803df3d4;
    dVar43 = (double)FLOAT_803df3d8;
    while (iVar19 = local_118, -1 < iVar20) {
      pfVar33 = (float *)(&DAT_8039ad58 + iVar20 * 6);
      *pfVar33 = (float)dVar42;
      local_10c = (float *)(&DAT_8039ad5c + iVar20 * 6);
      *local_10c = (float)dVar43;
      pfVar21 = (float *)(&DAT_8039ad60 + iVar20 * 6);
      *pfVar21 = (float)dVar42;
      pfVar32 = (float *)(&DAT_8039ad64 + iVar20 * 6);
      *pfVar32 = (float)dVar43;
      pfVar31 = (float *)(&DAT_8039ad68 + iVar20 * 6);
      *pfVar31 = (float)dVar42;
      pfVar30 = (float *)(&DAT_8039ad6c + iVar20 * 6);
      *pfVar30 = (float)dVar43;
      iVar34 = iVar20 + 1;
      pcVar16 = &DAT_8039bbc9 + iVar20;
      iVar35 = 0x50 - iVar34;
      if (iVar34 < 0x50) {
        do {
          if (*pcVar16 != '\0') goto LAB_8009bda4;
          pcVar16 = pcVar16 + 1;
          iVar34 = iVar34 + 1;
          iVar35 = iVar35 + -1;
        } while (iVar35 != 0);
      }
      iVar34 = -1;
LAB_8009bda4:
      local_108 = iVar20;
      if (-1 < iVar34) {
        iVar35 = local_11c + (uint)local_120 * 0x1000;
        FUN_800229f8(iVar35,(&DAT_8039bd58)[iVar34],0x7e);
        uVar14 = 1;
        local_118 = iVar35;
      }
      local_120 = local_120 ^ 1;
      FUN_800229c4(uVar14);
      local_114 = iVar20 * 4;
      local_f8 = &DAT_8039bc18 + iVar20;
      local_110 = local_11c + (uint)local_120 * 0x1000;
      psVar28 = (short *)(iVar19 + -0xa0);
      for (sVar29 = 0; sVar29 < 0x19; sVar29 = sVar29 + 1) {
        psVar27 = psVar28 + 0x50;
        if (((1 << (int)sVar29 & *local_f8) != 0) && (psVar28[99] != -1)) {
          puVar22 = (ushort *)(&DAT_8039b4d8)[(uint)(*(byte *)(psVar28 + 0x95) >> 1) * 4];
          iVar19 = (&DAT_8039b4e0)[(uint)(*(byte *)(psVar28 + 0x95) >> 1) * 4];
          *(byte *)((int)psVar28 + 299) = *(byte *)((int)psVar28 + 299) & 0xfe;
          *(byte *)((int)psVar28 + 299) = *(byte *)((int)psVar28 + 299) & 0xfd | 2;
          if ((*(uint *)(psVar28 + 0x8e) & 0x800) == 0) {
            psVar28[0x53] = psVar28[0x53] - (ushort)DAT_803db410;
          }
          bVar8 = *(byte *)((int)psVar28 + 299) >> 2 & 3;
          if (bVar8 == 2) {
            *(byte *)((int)psVar28 + 299) = *(byte *)((int)psVar28 + 299) & 0xf3 | 4;
          }
          else if (bVar8 == 1) {
            FUN_8009b0e0(local_110,local_108,(int)sVar29,0,0);
          }
          else if ((psVar28[0x53] < 1) || (psVar28[0x5b] < psVar28[0x53])) {
            *(byte *)((int)psVar28 + 299) = *(byte *)((int)psVar28 + 299) & 0xf3 | 8;
          }
          else {
            if ((*(uint *)(psVar28 + 0x8e) & 0x8000000) == 0) {
              psVar26 = (short *)0x8030fa00;
            }
            else {
              psVar26 = &DAT_8030f9e8;
            }
            if (((*(uint *)(psVar28 + 0x8e) & 0x20000) != 0) &&
               ((*(uint *)(psVar28 + 0x90) & 0x30000000) == 0)) {
              local_208 = FLOAT_803df35c;
              local_204 = FLOAT_803df35c;
              local_200 = FLOAT_803df35c;
              local_20c = FLOAT_803df354;
              local_1c0 = (double)CONCAT44(0x43300000,(int)psVar28[0x72] ^ 0x80000000);
              iVar35 = (int)((float)(local_1c0 - DOUBLE_803df360) * FLOAT_803db414);
              local_1c8 = (double)(longlong)iVar35;
              local_210 = (ushort)iVar35;
              local_1d0 = (double)CONCAT44(0x43300000,(int)psVar28[0x71] ^ 0x80000000);
              iVar35 = (int)((float)(local_1d0 - DOUBLE_803df360) * FLOAT_803db414);
              local_1d8 = (double)(longlong)iVar35;
              local_212 = (ushort)iVar35;
              local_1e0 = (double)CONCAT44(0x43300000,(int)psVar28[0x70] ^ 0x80000000);
              iVar35 = (int)((float)(local_1e0 - DOUBLE_803df360) * FLOAT_803db414);
              local_1e8 = (double)(longlong)iVar35;
              local_214 = (ushort)iVar35;
              FUN_80021ac8(&local_214,psVar28 + 0x7c);
            }
            fVar4 = FLOAT_803df3f0;
            fVar3 = FLOAT_803df3ec;
            fVar2 = FLOAT_803df3e8;
            fVar1 = FLOAT_803df3e4;
            uVar17 = *(uint *)(psVar28 + 0x90);
            if ((uVar17 & 0x30000000) == 0) {
              if ((uVar17 & 0x10000) == 0) {
                if ((uVar17 & 0x20000) == 0) {
                  if ((uVar17 & 0x40000) == 0) {
                    if ((uVar17 & 0x80000) != 0) {
                      *(float *)(psVar28 + 0x88) = FLOAT_803df3f0 * *(float *)(psVar28 + 0x88);
                      *(float *)(psVar28 + 0x8a) = fVar4 * *(float *)(psVar28 + 0x8a);
                      *(float *)(psVar28 + 0x8c) = fVar4 * *(float *)(psVar28 + 0x8c);
                    }
                  }
                  else {
                    *(float *)(psVar28 + 0x88) =
                         FLOAT_803df3ec * *(float *)(psVar28 + 0x88) + *(float *)(psVar28 + 0x88);
                    *(float *)(psVar28 + 0x8a) =
                         fVar3 * *(float *)(psVar28 + 0x8a) + *(float *)(psVar28 + 0x8a);
                    *(float *)(psVar28 + 0x8c) =
                         fVar3 * *(float *)(psVar28 + 0x8c) + *(float *)(psVar28 + 0x8c);
                  }
                }
                else {
                  *(float *)(psVar28 + 0x88) =
                       FLOAT_803df3e8 * *(float *)(psVar28 + 0x88) + *(float *)(psVar28 + 0x88);
                  *(float *)(psVar28 + 0x8a) =
                       fVar2 * *(float *)(psVar28 + 0x8a) + *(float *)(psVar28 + 0x8a);
                  *(float *)(psVar28 + 0x8c) =
                       fVar2 * *(float *)(psVar28 + 0x8c) + *(float *)(psVar28 + 0x8c);
                }
              }
              else {
                *(float *)(psVar28 + 0x88) =
                     FLOAT_803df3e4 * *(float *)(psVar28 + 0x88) + *(float *)(psVar28 + 0x88);
                *(float *)(psVar28 + 0x8a) =
                     fVar1 * *(float *)(psVar28 + 0x8a) + *(float *)(psVar28 + 0x8a);
                *(float *)(psVar28 + 0x8c) =
                     fVar1 * *(float *)(psVar28 + 0x8c) + *(float *)(psVar28 + 0x8c);
              }
              uVar17 = *(uint *)(psVar28 + 0x8e);
              if (((uVar17 & 0x40000000) == 0) ||
                 (fVar1 = *(float *)(psVar28 + 0x8a), FLOAT_803df3b4 <= fVar1)) {
                if (((uVar17 & 0x1000000) == 0) || (*(float *)(psVar28 + 0x8a) <= FLOAT_803df3c0)) {
                  if (((uVar17 & 8) != 0) && (FLOAT_803df3c0 < *(float *)(psVar28 + 0x8a))) {
                    *(float *)(psVar28 + 0x8a) =
                         FLOAT_803df3bc * FLOAT_803db414 + *(float *)(psVar28 + 0x8a);
                  }
                }
                else {
                  *(float *)(psVar28 + 0x8a) =
                       FLOAT_803df3b8 * FLOAT_803db414 + *(float *)(psVar28 + 0x8a);
                }
              }
              else if (((uVar17 & 0x1000000) == 0) || (FLOAT_803df3b4 <= fVar1)) {
                *(float *)(psVar28 + 0x8a) =
                     -(FLOAT_803df3bc * FLOAT_803db414 - *(float *)(psVar28 + 0x8a));
              }
              else {
                *(float *)(psVar28 + 0x8a) = -(FLOAT_803df3b8 * FLOAT_803db414 - fVar1);
              }
              fVar1 = FLOAT_803df35c;
              if (((*(uint *)(psVar28 + 0x90) & 0x40000000) != 0) &&
                 (*(float *)(psVar28 + 0x8a) * FLOAT_803db414 + *(float *)(psVar28 + 0x7e) <
                  FLOAT_803df35c)) {
                *(float *)(psVar28 + 0x88) = FLOAT_803df35c;
                *(float *)(psVar28 + 0x8a) = fVar1;
                *(float *)(psVar28 + 0x8c) = fVar1;
                psVar28[0x70] = 0;
                psVar28[0x71] = 0;
                psVar28[0x72] = 0;
                if ((*(uint *)(psVar28 + 0x8e) & 0x4000000) != 0) {
                  *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) ^ 0x4000000;
                }
                if ((*(uint *)(psVar28 + 0x8e) & 0x20000) != 0) {
                  *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) ^ 0x20000;
                }
                *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) | 0x8000000;
                if ((*(uint *)(psVar28 + 0x8e) & 0x1000000) != 0) {
                  *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) ^ 0x1000000;
                }
                if ((*(uint *)(psVar28 + 0x8e) & 8) != 0) {
                  *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) ^ 8;
                }
                if ((*(uint *)(psVar28 + 0x8e) & 0x80000000) != 0) {
                  *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) ^ 0x80000000;
                }
                *(uint *)(psVar28 + 0x90) = *(uint *)(psVar28 + 0x90) ^ 0x40000000;
              }
              uVar17 = *(uint *)(psVar28 + 0x8e) & 0xf020;
              if ((uVar17 == 0) ||
                 (FLOAT_803df35c <=
                  *(float *)(psVar28 + 0x8a) * FLOAT_803db414 + *(float *)(psVar28 + 0x7e))) {
                uVar7 = *(uint *)(psVar28 + 0x8e) & 0x10000000;
                if ((uVar7 == 0) ||
                   (FLOAT_803df35c <=
                    *(float *)(psVar28 + 0x8a) * FLOAT_803db414 + *(float *)(psVar28 + 0x7e))) {
                  if (((uVar17 == 0) && (uVar7 == 0)) && (psVar28[0x6b] != -1)) {
                    local_20c = FLOAT_803df354;
                    local_210 = 0;
                    local_212 = 0;
                    local_214 = 0;
                    if ((*(uint *)(psVar28 + 0x8e) & 1) == 0) {
                      if (puVar22 == (ushort *)0x0) {
                        local_208 = *(float *)(psVar28 + 0x7c);
                        local_204 = *(float *)(psVar28 + 0x7e);
                        local_200 = *(float *)(psVar28 + 0x80);
                      }
                      else {
                        local_208 = *(float *)(psVar28 + 0x7c) + *(float *)(puVar22 + 0xc);
                        local_204 = *(float *)(psVar28 + 0x7e) + *(float *)(puVar22 + 0xe);
                        local_200 = *(float *)(psVar28 + 0x80) + *(float *)(puVar22 + 0x10);
                      }
                    }
                    else {
                      local_208 = *(float *)(psVar28 + 0x7c);
                      local_204 = *(float *)(psVar28 + 0x7e);
                      local_200 = *(float *)(psVar28 + 0x80);
                    }
                    DAT_803dd252 = 1;
                    (**(code **)(*DAT_803dca88 + 8))
                              (puVar22,(int)psVar28[0x6b],&local_214,0x200001,0xffffffff,0);
                    DAT_803dd252 = 0;
                  }
                }
                else if (psVar28[0x6b] != -1) {
                  local_20c = FLOAT_803df354;
                  local_210 = 0;
                  local_212 = 0;
                  local_214 = 0;
                  if ((*(uint *)(psVar28 + 0x8e) & 1) == 0) {
                    if (puVar22 == (ushort *)0x0) {
                      local_208 = *(float *)(psVar28 + 0x7c);
                      local_204 = FLOAT_803df35c;
                      local_200 = *(float *)(psVar28 + 0x80);
                    }
                    else {
                      local_208 = *(float *)(psVar28 + 0x7c) + *(float *)(puVar22 + 0xc);
                      local_204 = *(float *)(puVar22 + 0xe);
                      local_200 = *(float *)(psVar28 + 0x80) + *(float *)(puVar22 + 0x10);
                    }
                  }
                  else {
                    local_208 = *(float *)(psVar28 + 0x7c);
                    local_204 = FLOAT_803df35c;
                    local_200 = *(float *)(psVar28 + 0x80);
                  }
                  DAT_803dd252 = 1;
                  (**(code **)(*DAT_803dca98 + 0x14))
                            ((double)local_208,(double)local_204,(double)local_200,
                             (double)FLOAT_803df35c,0,4);
                  (**(code **)(*DAT_803dca98 + 0x10))
                            ((double)local_208,(double)local_204,(double)local_200,
                             (double)FLOAT_803df3c4,0);
                  if ((puVar22 != (ushort *)0x0) &&
                     (iVar35 = FUN_8005afac((double)*(float *)(puVar22 + 6),
                                            (double)*(float *)(puVar22 + 10)), iVar35 == 0x10)) {
                    FUN_8000bb18(puVar22,0x285);
                  }
                  psVar28[0x6b] = -1;
                  *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) | 0x10000000;
                  psVar28[0x53] = 0;
                  DAT_803dd252 = 0;
                }
              }
              else {
                uVar17 = FUN_800221a0(0,5);
                local_1c0 = (double)CONCAT44(0x43300000,uVar17 ^ 0x80000000);
                *(float *)(psVar28 + 0x8a) =
                     *(float *)(psVar28 + 0x8a) *
                     -(FLOAT_803df3e4 * (float)(local_1c0 - DOUBLE_803df360) + FLOAT_803df38c);
                if (FLOAT_803df390 < *(float *)(psVar28 + 0x8a)) {
                  *(float *)(psVar28 + 0x8a) = FLOAT_803df390;
                }
                fVar2 = FLOAT_803df3c4;
                fVar1 = FLOAT_803df358;
                local_20c = FLOAT_803df354;
                local_210 = 0;
                local_212 = 0;
                local_214 = 0;
                if (puVar22 == (ushort *)0x0) {
                  local_208 = *(float *)(psVar28 + 0x7c) + *(float *)(psVar28 + 0x76);
                  local_204 = *(float *)(psVar28 + 0x7e) + *(float *)(psVar28 + 0x78);
                  local_200 = *(float *)(psVar28 + 0x80) + *(float *)(psVar28 + 0x7a);
                }
                else {
                  local_208 = *(float *)(psVar28 + 0x7c) + *(float *)(puVar22 + 6);
                  local_204 = *(float *)(psVar28 + 0x7e) + *(float *)(puVar22 + 8);
                  local_200 = *(float *)(psVar28 + 0x80) + *(float *)(puVar22 + 10);
                }
                DAT_803dd252 = 1;
                uVar17 = *(uint *)(psVar28 + 0x8e);
                if (((uVar17 & 0x20) == 0) || ((*(uint *)(psVar28 + 0x90) & 0x40000000) != 0)) {
                  if ((uVar17 & 0x1000) == 0) {
                    if ((uVar17 & 0x2000) == 0) {
                      if ((uVar17 & 0x4000) == 0) {
                        if ((uVar17 & 0x8000) != 0) {
                          *(float *)(psVar28 + 0x88) =
                               *(float *)(psVar28 + 0x88) *
                               (FLOAT_803df3c4 - *(float *)(psVar28 + 0x88));
                          *(float *)(psVar28 + 0x8c) =
                               *(float *)(psVar28 + 0x8c) * (fVar2 - *(float *)(psVar28 + 0x8c));
                          local_1c0 = (double)CONCAT44(0x43300000,(uint)(ushort)psVar28[0x92]);
                          iVar35 = (int)((float)(local_1c0 - DOUBLE_803df378) * FLOAT_803df3f4);
                          local_1c8 = (double)(longlong)iVar35;
                          psVar28[0x92] = (short)iVar35;
                          *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) ^ 0x8000;
                          *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) | 0x4000;
                          if (psVar28[0x6b] != -1) {
                            (**(code **)(*DAT_803dca88 + 8))
                                      (puVar22,(int)psVar28[0x6b],&local_214,0x200001,0xffffffff,0);
                          }
                        }
                      }
                      else {
                        *(float *)(psVar28 + 0x88) = *(float *)(psVar28 + 0x88) * FLOAT_803df358;
                        *(float *)(psVar28 + 0x8c) = *(float *)(psVar28 + 0x8c) * fVar1;
                        local_1c0 = (double)CONCAT44(0x43300000,(uint)(ushort)psVar28[0x92]);
                        iVar35 = (int)((float)(local_1c0 - DOUBLE_803df378) * FLOAT_803df3f4);
                        local_1c8 = (double)(longlong)iVar35;
                        psVar28[0x92] = (short)iVar35;
                        *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) ^ 0x4000;
                        *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) | 0x2000;
                        if (psVar28[0x6b] != -1) {
                          (**(code **)(*DAT_803dca88 + 8))
                                    (puVar22,(int)psVar28[0x6b],&local_214,0x200001,0xffffffff,0);
                        }
                        psVar28[0x6b] = -1;
                      }
                    }
                    else {
                      *(float *)(psVar28 + 0x88) = *(float *)(psVar28 + 0x88) * FLOAT_803df358;
                      *(float *)(psVar28 + 0x8c) = *(float *)(psVar28 + 0x8c) * fVar1;
                      local_1c0 = (double)CONCAT44(0x43300000,(uint)(ushort)psVar28[0x92]);
                      iVar35 = (int)((float)(local_1c0 - DOUBLE_803df378) * FLOAT_803df3f4);
                      local_1c8 = (double)(longlong)iVar35;
                      psVar28[0x92] = (short)iVar35;
                      *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) ^ 0x2000;
                      *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) | 0x1000;
                    }
                  }
                  else {
                    *(float *)(psVar28 + 0x88) = *(float *)(psVar28 + 0x88) * FLOAT_803df358;
                    *(float *)(psVar28 + 0x8c) = *(float *)(psVar28 + 0x8c) * fVar1;
                    local_1c0 = (double)CONCAT44(0x43300000,(uint)(ushort)psVar28[0x92]);
                    iVar35 = (int)((float)(local_1c0 - DOUBLE_803df378) * FLOAT_803df3f4);
                    local_1c8 = (double)(longlong)iVar35;
                    psVar28[0x92] = (short)iVar35;
                    *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) ^ 0x1000;
                  }
                }
                else {
                  *(float *)(psVar28 + 0x88) = *(float *)(psVar28 + 0x88) * FLOAT_803df3c4;
                  *(float *)(psVar28 + 0x8c) = *(float *)(psVar28 + 0x8c) * fVar2;
                  *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) ^ 0x20;
                  if (psVar28[0x6b] != -1) {
                    (**(code **)(*DAT_803dca88 + 8))
                              (puVar22,(int)psVar28[0x6b],&local_214,0x200001,0xffffffff,0);
                    psVar28[0x6b] = -1;
                  }
                }
                DAT_803dd252 = 0;
              }
              if (((*(uint *)(psVar28 + 0x8e) & 0x80000000) != 0) &&
                 (iVar35 = FUN_800221a0(0,4), iVar35 == 1)) {
                uVar17 = FUN_800221a0(0,9);
                local_1c0 = (double)CONCAT44(0x43300000,uVar17 ^ 0x80000000);
                *(float *)(psVar28 + 0x88) =
                     *(float *)(psVar28 + 0x88) +
                     (FLOAT_803df3f8 - (float)(local_1c0 - DOUBLE_803df360) / FLOAT_803df3fc);
                uVar17 = FUN_800221a0(0,9);
                local_1c8 = (double)CONCAT44(0x43300000,uVar17 ^ 0x80000000);
                *(float *)(psVar28 + 0x8c) =
                     *(float *)(psVar28 + 0x8c) +
                     (FLOAT_803df3f8 - (float)(local_1c8 - DOUBLE_803df360) / FLOAT_803df3fc);
              }
              if (((*(uint *)(psVar28 + 0x90) & 0x100000) != 0) &&
                 (iVar35 = FUN_800221a0(0,10), iVar35 == 1)) {
                local_1c0 = (double)CONCAT44(0x43300000,(int)psVar28[0x5b] ^ 0x80000000);
                local_1c8 = (double)CONCAT44(0x43300000,(int)psVar28[0x53] ^ 0x80000000);
                if ((float)(local_1c8 - DOUBLE_803df360) < (float)(local_1c0 - DOUBLE_803df360)) {
                  uVar17 = FUN_800221a0(0xfffffce0,800);
                  local_1c0 = (double)CONCAT44(0x43300000,uVar17 ^ 0x80000000);
                  *(float *)(psVar28 + 0x88) =
                       *(float *)(psVar28 + 0x88) +
                       FLOAT_803df400 * (float)(local_1c0 - DOUBLE_803df360) + FLOAT_803df3e8;
                  uVar17 = FUN_800221a0(0xfffffce0,800);
                  local_1c8 = (double)CONCAT44(0x43300000,uVar17 ^ 0x80000000);
                  *(float *)(psVar28 + 0x8a) =
                       *(float *)(psVar28 + 0x8a) +
                       FLOAT_803df400 * (float)(local_1c8 - DOUBLE_803df360) + FLOAT_803df3e8;
                  uVar17 = FUN_800221a0(0xfffffce0,800);
                  local_1d0 = (double)CONCAT44(0x43300000,uVar17 ^ 0x80000000);
                  *(float *)(psVar28 + 0x8c) =
                       *(float *)(psVar28 + 0x8c) +
                       FLOAT_803df400 * (float)(local_1d0 - DOUBLE_803df360) + FLOAT_803df3e8;
                }
              }
              if ((*(uint *)(psVar28 + 0x8e) & 0x400) != 0) {
                local_1c0 = (double)CONCAT44(0x43300000,(int)psVar28[0x5b] ^ 0x80000000);
                local_1c8 = (double)CONCAT44(0x43300000,(int)psVar28[0x53] ^ 0x80000000);
                if ((float)(local_1c8 - DOUBLE_803df360) <
                    FLOAT_803df38c * (float)(local_1c0 - DOUBLE_803df360)) {
                  *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) ^ 0x400;
                  fVar1 = FLOAT_803df404;
                  *(float *)(psVar28 + 0x88) = *(float *)(psVar28 + 0x88) * FLOAT_803df404;
                  *(float *)(psVar28 + 0x8a) = *(float *)(psVar28 + 0x8a) * fVar1;
                  *(float *)(psVar28 + 0x8c) = *(float *)(psVar28 + 0x8c) * fVar1;
                }
              }
              if ((*(uint *)(psVar28 + 0x90) & 0x200000) != 0) {
                in_f27 = (double)*(float *)(psVar28 + 0x7c);
                in_f26 = (double)*(float *)(psVar28 + 0x7e);
                in_f25 = (double)*(float *)(psVar28 + 0x80);
              }
              *(float *)(psVar28 + 0x7c) =
                   *(float *)(psVar28 + 0x88) * FLOAT_803db414 + *(float *)(psVar28 + 0x7c);
              *(float *)(psVar28 + 0x7e) =
                   *(float *)(psVar28 + 0x8a) * FLOAT_803db414 + *(float *)(psVar28 + 0x7e);
              *(float *)(psVar28 + 0x80) =
                   *(float *)(psVar28 + 0x8c) * FLOAT_803db414 + *(float *)(psVar28 + 0x80);
              if ((*(uint *)(psVar28 + 0x8e) & 0x100000) == 0) {
                if ((*(uint *)(psVar28 + 0x90) & 0x2000) != 0) {
                  psVar28[0x92] = psVar28[0x92] - psVar28[0x94] * (ushort)DAT_803db410;
                }
              }
              else {
                local_1c0 = (double)CONCAT44(0x43300000,(uint)(ushort)psVar28[0x94]);
                local_1c8 = (double)CONCAT44(0x43300000,(uint)(ushort)psVar28[0x92]);
                iVar35 = (int)((float)(local_1c0 - DOUBLE_803df378) * FLOAT_803db414 +
                              (float)(local_1c8 - DOUBLE_803df378));
                local_1d0 = (double)(longlong)iVar35;
                psVar28[0x92] = (short)iVar35;
              }
            }
            else {
              dVar39 = (double)FLOAT_803df3dc;
              dVar40 = dVar39;
              if (((((uVar17 & 0x10000000) != 0) && (iVar12 != 0)) && (puVar22 != (ushort *)0x0)) &&
                 ((double)FLOAT_803df3e0 < dVar44)) {
                local_220 = *(float *)(iVar12 + 0x18) -
                            (*(float *)(psVar28 + 0x82) + *(float *)(puVar22 + 6));
                local_218 = *(float *)(iVar12 + 0x20) -
                            (*(float *)(psVar28 + 0x86) + *(float *)(puVar22 + 10));
                dVar40 = (double)(local_220 * local_220 + local_218 * local_218);
                dVar41 = (double)(float)(dVar44 / dVar40);
              }
              if ((((double)FLOAT_803df3b0 < dVar40) &&
                  ((*(uint *)(psVar28 + 0x90) & 0x20000000) != 0)) &&
                 ((iVar13 != 0 && ((puVar22 != (ushort *)0x0 && ((double)FLOAT_803df3e0 < dVar37))))
                 )) {
                local_220 = *(float *)(iVar13 + 0x18) -
                            (*(float *)(psVar28 + 0x82) + *(float *)(puVar22 + 6));
                local_218 = *(float *)(iVar13 + 0x20) -
                            (*(float *)(psVar28 + 0x86) + *(float *)(puVar22 + 10));
                dVar39 = (double)(local_220 * local_220 + local_218 * local_218);
                dVar41 = (double)(float)(dVar37 / dVar40);
              }
              if (dVar39 < dVar40) {
                dVar40 = dVar39;
              }
              if (dVar40 < (double)FLOAT_803df3b0) {
                if ((*(uint *)(psVar28 + 0x90) & 0x10000000) != 0) {
                  *(uint *)(psVar28 + 0x90) = *(uint *)(psVar28 + 0x90) ^ 0x10000000;
                }
                if ((*(uint *)(psVar28 + 0x90) & 0x20000000) != 0) {
                  *(uint *)(psVar28 + 0x90) = *(uint *)(psVar28 + 0x90) ^ 0x20000000;
                }
                if ((*(uint *)(psVar28 + 0x8e) & 0x8000000) != 0) {
                  *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) ^ 0x8000000;
                }
                sVar18 = FUN_800221a0(0,0x28);
                psVar28[0x53] = sVar18 + 0xdc;
                sVar18 = FUN_800221a0(0,0x28);
                psVar28[0x5b] = sVar18 + 0xdc;
                *(uint *)(psVar28 + 0x8e) = *(uint *)(psVar28 + 0x8e) | 0x1000;
                *(uint *)(psVar28 + 0x90) = *(uint *)(psVar28 + 0x90) | 0x40000000;
                *(float *)(psVar28 + 0x88) = (float)(-(double)local_220 * dVar41);
                *(float *)(psVar28 + 0x8c) = (float)(-(double)local_218 * dVar41);
              }
            }
            if (iVar19 != 0) {
              sVar24 = 0;
              sVar25 = 0;
              sVar23 = 0;
              sVar18 = 0;
              if (iVar19 != 0) {
                sVar23 = 0x80;
                sVar24 = 0x80;
                sVar18 = 0;
                if ((*(uint *)(psVar28 + 0x8e) & 0x80) != 0) {
                  sVar18 = 0x80;
                  sVar23 = 0;
                }
                if ((*(uint *)(psVar28 + 0x8e) & 0x40) != 0) {
                  sVar25 = 0x80;
                  sVar24 = 0;
                }
              }
              uVar17 = *(uint *)(psVar28 + 0x90);
              if ((uVar17 & 0x20) == 0) {
                if ((uVar17 & 0x1000000) == 0) {
                  if ((uVar17 & 0x800000) != 0) {
                    *(byte *)(psVar28 + 0x56) = local_f2;
                    *(byte *)((int)psVar28 + 0xad) = local_f3;
                    *(byte *)(psVar28 + 0x57) = local_f4;
                  }
                }
                else {
                  *(byte *)(psVar28 + 0x56) = local_248;
                  *(byte *)((int)psVar28 + 0xad) = local_247;
                  *(byte *)(psVar28 + 0x57) = local_246[0];
                }
              }
              else {
                local_1c0 = (double)CONCAT44(0x43300000,(int)psVar28[0x53] ^ 0x80000000);
                local_1c8 = (double)CONCAT44(0x43300000,(int)psVar28[0x5b] ^ 0x80000000);
                fVar1 = (float)(local_1c0 - DOUBLE_803df360) / (float)(local_1c8 - DOUBLE_803df360);
                local_1d0 = (double)CONCAT44(0x43300000,
                                             (uint)*(byte *)((int)psVar28 + 0xbf) -
                                             (uint)*(byte *)(psVar28 + 0x96) ^ 0x80000000);
                local_1d8 = (double)CONCAT44(0x43300000,(uint)*(byte *)(psVar28 + 0x96));
                iVar19 = (int)(fVar1 * (float)(local_1d0 - DOUBLE_803df360) +
                              (float)(local_1d8 - DOUBLE_803df378));
                local_1e0 = (double)(longlong)iVar19;
                local_1e8 = (double)CONCAT44(0x43300000,
                                             (uint)*(byte *)((int)psVar28 + 0xcf) -
                                             (uint)*(byte *)((int)psVar28 + 0x12d) ^ 0x80000000);
                local_1f0 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)psVar28 + 0x12d));
                iVar35 = (int)(fVar1 * (float)(local_1e8 - DOUBLE_803df360) +
                              (float)(local_1f0 - DOUBLE_803df378));
                local_1f8 = (double)(longlong)iVar35;
                local_1b8 = (double)CONCAT44(0x43300000,
                                             (uint)*(byte *)((int)psVar28 + 0xdf) -
                                             (uint)*(byte *)(psVar28 + 0x97) ^ 0x80000000);
                local_1b0 = (double)CONCAT44(0x43300000,(uint)*(byte *)(psVar28 + 0x97));
                iVar20 = (int)(fVar1 * (float)(local_1b8 - DOUBLE_803df360) +
                              (float)(local_1b0 - DOUBLE_803df378));
                local_1a8 = (double)(longlong)iVar20;
                if ((uVar17 & 0x1000000) == 0) {
                  if ((uVar17 & 0x800000) == 0) {
                    *(char *)(psVar28 + 0x56) = (char)iVar19;
                    *(char *)((int)psVar28 + 0xad) = (char)iVar35;
                    *(char *)(psVar28 + 0x57) = (char)iVar20;
                  }
                  else {
                    *(char *)(psVar28 + 0x56) = (char)((uint)((short)iVar19 * local_fc) >> 8);
                    *(char *)((int)psVar28 + 0xad) = (char)((uint)((short)iVar35 * local_100) >> 8);
                    *(char *)(psVar28 + 0x57) = (char)((uint)((short)iVar20 * local_104) >> 8);
                  }
                }
                else {
                  *(char *)(psVar28 + 0x56) = (char)((int)(short)iVar19 * (local_248 + 1) >> 8);
                  *(char *)((int)psVar28 + 0xad) = (char)((int)(short)iVar35 * (local_247 + 1) >> 8)
                  ;
                  *(char *)(psVar28 + 0x57) = (char)((int)(short)iVar20 * (local_246[0] + 1) >> 8);
                }
              }
              uVar17 = *(uint *)(psVar28 + 0x90);
              if ((uVar17 & 0x200000) == 0) {
                if (((*(uint *)(psVar28 + 0x8e) & 0x4000000) == 0) || ((uVar17 & 0x30000000) != 0))
                {
                  if ((uVar17 & 0x20) == 0) {
                    if ((uVar17 & 0x100) == 0) {
                      if ((uVar17 & 0x400) == 0) {
                        if ((uVar17 & 0x200) == 0) {
                          *psVar27 = *psVar26;
                          psVar28[0x51] = psVar26[1];
                          psVar28[0x52] = psVar26[2];
                          psVar28[0x54] = sVar23;
                          psVar28[0x55] = sVar24;
                          psVar28[0x58] = psVar26[3];
                          psVar28[0x59] = psVar26[4];
                          psVar28[0x5a] = psVar26[5];
                          psVar28[0x5c] = sVar18;
                          psVar28[0x5d] = sVar24;
                          psVar28[0x60] = psVar26[6];
                          psVar28[0x61] = psVar26[7];
                          psVar28[0x62] = psVar26[8];
                          psVar28[100] = sVar18;
                          psVar28[0x65] = sVar25;
                          psVar28[0x68] = psVar26[9];
                          psVar28[0x69] = psVar26[10];
                          psVar28[0x6a] = psVar26[0xb];
                          psVar28[0x6c] = sVar23;
                          psVar28[0x6d] = sVar25;
                        }
                        else {
                          *psVar27 = *psVar26;
                          *psVar27 = (short)((int)*psVar27 << 5);
                          psVar28[0x51] = psVar26[1];
                          psVar28[0x52] = psVar26[2];
                          psVar28[0x54] = sVar23;
                          psVar28[0x55] = sVar24;
                          psVar28[0x58] = psVar26[3];
                          psVar28[0x58] = (short)((int)psVar28[0x58] << 5);
                          psVar28[0x59] = psVar26[4];
                          psVar28[0x5a] = psVar26[5];
                          psVar28[0x5c] = sVar18;
                          psVar28[0x5d] = sVar24;
                          psVar28[0x60] = psVar26[6];
                          psVar28[0x60] = (short)((int)psVar28[0x60] << 5);
                          psVar28[0x61] = psVar26[7];
                          psVar28[0x62] = psVar26[8];
                          psVar28[100] = sVar18;
                          psVar28[0x65] = sVar25;
                          psVar28[0x68] = psVar26[9];
                          psVar28[0x68] = (short)((int)psVar28[0x68] << 5);
                          psVar28[0x69] = psVar26[10];
                          psVar28[0x6a] = psVar26[0xb];
                          psVar28[0x6c] = sVar23;
                          psVar28[0x6d] = sVar25;
                        }
                      }
                      else {
                        psVar28[0x52] = *psVar26;
                        psVar28[0x52] = (short)((int)psVar28[0x52] << 5);
                        psVar28[0x51] = psVar26[1];
                        *psVar27 = psVar26[2];
                        psVar28[0x54] = sVar23;
                        psVar28[0x55] = sVar24;
                        psVar28[0x5a] = psVar26[3];
                        psVar28[0x5a] = (short)((int)psVar28[0x5a] << 5);
                        psVar28[0x59] = psVar26[4];
                        psVar28[0x58] = psVar26[5];
                        psVar28[0x5c] = sVar18;
                        psVar28[0x5d] = sVar24;
                        psVar28[0x62] = psVar26[6];
                        psVar28[0x62] = (short)((int)psVar28[0x62] << 5);
                        psVar28[0x61] = psVar26[7];
                        psVar28[0x60] = psVar26[8];
                        psVar28[100] = sVar18;
                        psVar28[0x65] = sVar25;
                        psVar28[0x6a] = psVar26[9];
                        psVar28[0x6a] = (short)((int)psVar28[0x6a] << 5);
                        psVar28[0x69] = psVar26[10];
                        psVar28[0x68] = psVar26[0xb];
                        psVar28[0x6c] = sVar23;
                        psVar28[0x6d] = sVar25;
                      }
                    }
                    else {
                      *psVar27 = *psVar26;
                      psVar28[0x51] = psVar26[1];
                      psVar28[0x51] = (short)((int)psVar28[0x51] << 3);
                      psVar28[0x52] = psVar26[2];
                      psVar28[0x54] = sVar23;
                      psVar28[0x55] = sVar24;
                      psVar28[0x58] = psVar26[3];
                      psVar28[0x59] = psVar26[4];
                      psVar28[0x59] = (short)((int)psVar28[0x59] << 3);
                      psVar28[0x5a] = psVar26[5];
                      psVar28[0x5c] = sVar18;
                      psVar28[0x5d] = sVar24;
                      psVar28[0x60] = psVar26[6];
                      psVar28[0x61] = psVar26[7];
                      psVar28[0x61] = (short)((int)psVar28[0x61] << 3);
                      psVar28[0x62] = psVar26[8];
                      psVar28[100] = sVar18;
                      psVar28[0x65] = sVar25;
                      psVar28[0x68] = psVar26[9];
                      psVar28[0x69] = psVar26[10];
                      psVar28[0x69] = (short)((int)psVar28[0x69] << 3);
                      psVar28[0x6a] = psVar26[0xb];
                      psVar28[0x6c] = sVar23;
                      psVar28[0x6d] = sVar25;
                    }
                  }
                  else {
                    *psVar27 = *psVar26;
                    psVar28[0x51] = psVar26[1];
                    psVar28[0x52] = psVar26[2];
                    psVar28[0x54] = sVar23;
                    psVar28[0x55] = sVar24;
                    psVar28[0x58] = psVar26[3];
                    psVar28[0x59] = psVar26[4];
                    psVar28[0x5a] = psVar26[5];
                    psVar28[0x5c] = sVar18;
                    psVar28[0x5d] = sVar24;
                    psVar28[0x60] = psVar26[6];
                    psVar28[0x61] = psVar26[7];
                    psVar28[0x62] = psVar26[8];
                    psVar28[100] = sVar18;
                    psVar28[0x65] = sVar25;
                    psVar28[0x68] = psVar26[9];
                    psVar28[0x69] = psVar26[10];
                    psVar28[0x6a] = psVar26[0xb];
                    psVar28[0x6c] = sVar23;
                    psVar28[0x6d] = sVar25;
                  }
                }
                else {
                  local_208 = FLOAT_803df35c;
                  local_204 = FLOAT_803df35c;
                  local_200 = FLOAT_803df35c;
                  local_198 = (double)(longlong)(int)*(float *)(psVar28 + 0x76);
                  psVar28[0x70] =
                       psVar28[0x70] + (ushort)DAT_803db410 * (short)(int)*(float *)(psVar28 + 0x76)
                  ;
                  local_1a0 = (double)(longlong)(int)*(float *)(psVar28 + 0x78);
                  psVar28[0x71] =
                       psVar28[0x71] + (ushort)DAT_803db410 * (short)(int)*(float *)(psVar28 + 0x78)
                  ;
                  local_1a8 = (double)(longlong)(int)*(float *)(psVar28 + 0x7a);
                  psVar28[0x72] =
                       psVar28[0x72] + (ushort)DAT_803db410 * (short)(int)*(float *)(psVar28 + 0x7a)
                  ;
                  local_20c = FLOAT_803df354;
                  local_1b0 = (double)CONCAT44(0x43300000,(int)*psVar26 ^ 0x80000000);
                  local_220 = (float)(local_1b0 - DOUBLE_803df360);
                  local_1b8 = (double)CONCAT44(0x43300000,(int)psVar26[1] ^ 0x80000000);
                  local_21c = (float)(local_1b8 - DOUBLE_803df360);
                  local_1c0 = (double)CONCAT44(0x43300000,(int)psVar26[2] ^ 0x80000000);
                  local_218 = (float)(local_1c0 - DOUBLE_803df360);
                  local_210 = 0;
                  local_212 = 0;
                  local_214 = psVar28[0x70];
                  FUN_80021ac8(&local_214,&local_220);
                  local_210 = psVar28[0x71];
                  local_212 = psVar28[0x72];
                  local_214 = 0;
                  FUN_80021ac8(&local_214,&local_220);
                  local_1c8 = (double)(longlong)(int)local_220;
                  *psVar27 = (short)(int)local_220;
                  local_1d0 = (double)(longlong)(int)local_21c;
                  psVar28[0x51] = (short)(int)local_21c;
                  local_1d8 = (double)(longlong)(int)local_218;
                  psVar28[0x52] = (short)(int)local_218;
                  psVar28[0x54] = sVar23;
                  psVar28[0x55] = sVar24;
                  local_1e0 = (double)CONCAT44(0x43300000,(int)psVar26[3] ^ 0x80000000);
                  local_220 = (float)(local_1e0 - DOUBLE_803df360);
                  local_1e8 = (double)CONCAT44(0x43300000,(int)psVar26[4] ^ 0x80000000);
                  local_21c = (float)(local_1e8 - DOUBLE_803df360);
                  local_1f0 = (double)CONCAT44(0x43300000,(int)psVar26[5] ^ 0x80000000);
                  local_218 = (float)(local_1f0 - DOUBLE_803df360);
                  local_210 = 0;
                  local_212 = 0;
                  local_214 = psVar28[0x70];
                  FUN_80021ac8(&local_214,&local_220);
                  local_210 = psVar28[0x71];
                  local_212 = psVar28[0x72];
                  local_214 = 0;
                  FUN_80021ac8(&local_214,&local_220);
                  local_1f8 = (double)(longlong)(int)local_220;
                  psVar28[0x58] = (short)(int)local_220;
                  local_190 = (longlong)(int)local_21c;
                  psVar28[0x59] = (short)(int)local_21c;
                  local_188 = (longlong)(int)local_218;
                  psVar28[0x5a] = (short)(int)local_218;
                  psVar28[0x5c] = sVar18;
                  psVar28[0x5d] = sVar24;
                  uStack380 = (int)psVar26[6] ^ 0x80000000;
                  local_180 = 0x43300000;
                  local_220 = (float)((double)CONCAT44(0x43300000,uStack380) - DOUBLE_803df360);
                  uStack372 = (int)psVar26[7] ^ 0x80000000;
                  local_178 = 0x43300000;
                  local_21c = (float)((double)CONCAT44(0x43300000,uStack372) - DOUBLE_803df360);
                  uStack364 = (int)psVar26[8] ^ 0x80000000;
                  local_170 = 0x43300000;
                  local_218 = (float)((double)CONCAT44(0x43300000,uStack364) - DOUBLE_803df360);
                  local_210 = 0;
                  local_212 = 0;
                  local_214 = psVar28[0x70];
                  FUN_80021ac8(&local_214,&local_220);
                  local_210 = psVar28[0x71];
                  local_212 = psVar28[0x72];
                  local_214 = 0;
                  FUN_80021ac8(&local_214,&local_220);
                  local_168 = (longlong)(int)local_220;
                  psVar28[0x60] = (short)(int)local_220;
                  local_160 = (longlong)(int)local_21c;
                  psVar28[0x61] = (short)(int)local_21c;
                  local_158 = (longlong)(int)local_218;
                  psVar28[0x62] = (short)(int)local_218;
                  psVar28[100] = sVar18;
                  psVar28[0x65] = sVar25;
                  uStack332 = (int)psVar26[9] ^ 0x80000000;
                  local_150 = 0x43300000;
                  local_220 = (float)((double)CONCAT44(0x43300000,uStack332) - DOUBLE_803df360);
                  uStack324 = (int)psVar26[10] ^ 0x80000000;
                  local_148 = 0x43300000;
                  local_21c = (float)((double)CONCAT44(0x43300000,uStack324) - DOUBLE_803df360);
                  uStack316 = (int)psVar26[0xb] ^ 0x80000000;
                  local_140 = 0x43300000;
                  local_218 = (float)((double)CONCAT44(0x43300000,uStack316) - DOUBLE_803df360);
                  local_210 = 0;
                  local_212 = 0;
                  local_214 = psVar28[0x70];
                  FUN_80021ac8(&local_214,&local_220);
                  local_210 = psVar28[0x71];
                  local_212 = psVar28[0x72];
                  local_214 = 0;
                  FUN_80021ac8(&local_214,&local_220);
                  local_138 = (longlong)(int)local_220;
                  psVar28[0x68] = (short)(int)local_220;
                  local_130 = (longlong)(int)local_21c;
                  psVar28[0x69] = (short)(int)local_21c;
                  local_128 = (longlong)(int)local_218;
                  psVar28[0x6a] = (short)(int)local_218;
                  psVar28[0x6c] = sVar23;
                  psVar28[0x6d] = sVar25;
                }
              }
              else {
                dVar39 = (double)FLOAT_803df35c;
                dVar41 = dVar39;
                dVar40 = dVar39;
                if ((*(uint *)(psVar28 + 0x8e) & 1) == 0) {
                  if (puVar22 == (ushort *)0x0) {
                    dVar39 = (double)*(float *)(psVar28 + 0x76);
                    dVar41 = (double)*(float *)(psVar28 + 0x78);
                    dVar40 = (double)*(float *)(psVar28 + 0x7a);
                  }
                  else {
                    dVar39 = (double)*(float *)(puVar22 + 0xc);
                    dVar41 = (double)*(float *)(puVar22 + 0xe);
                    dVar40 = (double)*(float *)(puVar22 + 0x10);
                  }
                }
                fVar1 = (float)(dVar39 - (double)*(float *)(psVar28 + 0x7c));
                fVar2 = (float)(dVar41 - (double)*(float *)(psVar28 + 0x7e));
                fVar3 = (float)(dVar40 - (double)*(float *)(psVar28 + 0x80));
                fVar4 = (float)(in_f27 - (double)*(float *)(psVar28 + 0x7c));
                fVar5 = (float)(in_f26 - (double)*(float *)(psVar28 + 0x7e));
                fVar6 = (float)(in_f25 - (double)*(float *)(psVar28 + 0x80));
                dVar39 = (double)(fVar5 * fVar3 - fVar6 * fVar2);
                dVar40 = -(double)(fVar4 * fVar3 - fVar6 * fVar1);
                dVar41 = (double)(fVar4 * fVar2 - fVar5 * fVar1);
                if (FLOAT_803df35c ==
                    (float)(dVar41 * dVar41 +
                           (double)(float)(dVar39 * dVar39 + (double)(float)(dVar40 * dVar40)))) {
                  dVar38 = (double)FLOAT_803df354;
                }
                else {
                  dVar38 = (double)FUN_802931a0();
                }
                fVar1 = FLOAT_803df408 * (float)(dVar39 / dVar38);
                dVar39 = (double)fVar1;
                fVar2 = FLOAT_803df408 * (float)(dVar40 / dVar38);
                dVar40 = (double)fVar2;
                fVar3 = FLOAT_803df408 * (float)(dVar41 / dVar38);
                dVar38 = (double)fVar3;
                local_1a8 = (double)CONCAT44(0x43300000,(uint)(ushort)psVar28[0x93]);
                dVar41 = (double)(FLOAT_803df40c /
                                 (FLOAT_803df410 * (float)(local_1a8 - DOUBLE_803df378)));
                iVar19 = (int)fVar1;
                local_1f8 = (double)(longlong)iVar19;
                sVar9 = (short)iVar19;
                *psVar27 = sVar9;
                iVar19 = (int)fVar2;
                local_1b8 = (double)(longlong)iVar19;
                sVar10 = (short)iVar19;
                psVar28[0x51] = sVar10;
                iVar19 = (int)fVar3;
                local_1c0 = (double)(longlong)iVar19;
                sVar11 = (short)iVar19;
                psVar28[0x52] = sVar11;
                psVar28[0x54] = sVar23;
                psVar28[0x55] = sVar24;
                iVar19 = (int)(dVar41 * (double)(float)((double)*(float *)(psVar28 + 0x7c) - in_f27)
                              + dVar39);
                local_1c8 = (double)(longlong)iVar19;
                psVar28[0x58] = (short)iVar19;
                iVar19 = (int)(dVar41 * (double)(float)((double)*(float *)(psVar28 + 0x7e) - in_f26)
                              + dVar40);
                local_1d0 = (double)(longlong)iVar19;
                psVar28[0x59] = (short)iVar19;
                iVar19 = (int)(dVar41 * (double)(float)((double)*(float *)(psVar28 + 0x80) - in_f25)
                              + dVar38);
                local_1d8 = (double)(longlong)iVar19;
                psVar28[0x5a] = (short)iVar19;
                psVar28[0x5c] = sVar18;
                psVar28[0x5d] = sVar24;
                iVar19 = (int)(dVar41 * (double)(float)((double)*(float *)(psVar28 + 0x7c) - in_f27)
                              - dVar39);
                local_1e0 = (double)(longlong)iVar19;
                psVar28[0x60] = (short)iVar19;
                iVar19 = (int)(dVar41 * (double)(float)((double)*(float *)(psVar28 + 0x7e) - in_f26)
                              - dVar40);
                local_1e8 = (double)(longlong)iVar19;
                psVar28[0x61] = (short)iVar19;
                iVar19 = (int)(dVar41 * (double)(float)((double)*(float *)(psVar28 + 0x80) - in_f25)
                              - dVar38);
                local_1f0 = (double)(longlong)iVar19;
                psVar28[0x62] = (short)iVar19;
                psVar28[100] = sVar18;
                psVar28[0x65] = sVar25;
                psVar28[0x68] = -sVar9;
                psVar28[0x69] = -sVar10;
                psVar28[0x6a] = -sVar11;
                psVar28[0x6c] = sVar23;
                psVar28[0x6d] = sVar25;
                local_1b0 = local_1f8;
                local_1a0 = local_1b8;
                local_198 = local_1c0;
              }
              iVar19 = (&DAT_8039b4dc)[(uint)(*(byte *)(psVar28 + 0x95) >> 1) * 4];
              local_208 = FLOAT_803df35c;
              local_204 = FLOAT_803df35c;
              local_200 = FLOAT_803df35c;
              local_20c = FLOAT_803df354;
              if (((*(uint *)(psVar28 + 0x8e) & 0x20000) != 0) &&
                 ((*(uint *)(psVar28 + 0x90) & 0x30000000) == 0)) {
                local_208 = *(float *)(psVar28 + 0x7c);
                local_204 = *(float *)(psVar28 + 0x7e);
                local_200 = *(float *)(psVar28 + 0x80);
              }
              local_210 = 0;
              local_212 = 0;
              local_214 = 0;
              if (((*(uint *)(psVar28 + 0x8e) & 0x4000000) == 0) &&
                 ((*(uint *)(psVar28 + 0x8e) & 4) != 0)) {
                if (puVar22 == (ushort *)0x0) {
                  local_214 = psVar28[0x70];
                  local_212 = psVar28[0x71];
                  local_210 = psVar28[0x72];
                }
                else {
                  local_214 = *puVar22;
                  local_212 = puVar22[1];
                  local_210 = puVar22[2];
                }
              }
              local_238 = *(float *)(psVar28 + 0x7c);
              local_234 = *(float *)(psVar28 + 0x7e);
              local_230 = *(float *)(psVar28 + 0x80);
              if ((ushort)(local_210 | local_214 | local_212) != 0) {
                FUN_80021ac8(&local_214,&local_238);
              }
              if ((*(uint *)(psVar28 + 0x8e) & 1) == 0) {
                if (puVar22 == (ushort *)0x0) {
                  local_244 = *(float *)(psVar28 + 0x76);
                  local_240 = *(float *)(psVar28 + 0x78);
                  local_23c = *(float *)(psVar28 + 0x7a);
                  if (iVar19 != 0) {
                    FUN_8000dd74(psVar28 + 0x76,&local_244,*(undefined *)(iVar19 + 0x35));
                  }
                }
                else {
                  local_244 = *(float *)(puVar22 + 0xc);
                  local_240 = *(float *)(puVar22 + 0xe);
                  local_23c = *(float *)(puVar22 + 0x10);
                }
              }
              else {
                local_244 = FLOAT_803df35c;
                local_240 = FLOAT_803df35c;
                local_23c = FLOAT_803df35c;
              }
              local_210 = 0;
              local_212 = 0;
              local_214 = 0;
              local_208 = local_244 + local_238;
              local_204 = local_240 + local_234;
              local_200 = local_23c + local_230;
              if ((((*(uint *)(psVar28 + 0x8e) & 0x20000) != 0) &&
                  ((*(uint *)(psVar28 + 0x8e) & 0x4000000) == 0)) &&
                 ((*(uint *)(psVar28 + 0x90) & 0x30000000) == 0)) {
                local_208 = local_208 + *(float *)(psVar28 + 0x76);
                local_204 = local_204 + *(float *)(psVar28 + 0x78);
                local_200 = local_200 + *(float *)(psVar28 + 0x7a);
              }
              *(float *)(psVar28 + 0x98) = local_208;
              *(float *)(psVar28 + 0x9a) = local_204;
              *(float *)(psVar28 + 0x9c) = local_200;
              if (local_208 < *pfVar33) {
                *pfVar33 = local_208;
              }
              if (*local_10c < local_208) {
                *local_10c = local_208;
              }
              if (local_204 < *pfVar21) {
                *pfVar21 = local_204;
              }
              if (*pfVar32 < local_204) {
                *pfVar32 = local_204;
              }
              if (local_200 < *pfVar31) {
                *pfVar31 = local_200;
              }
              if (*pfVar30 < local_200) {
                *pfVar30 = local_200;
              }
            }
            else {
              FUN_801378a8(s_notexture_8030fc1c);
            }
          }
        }
        psVar28 = psVar27;
      }
      FUN_80022948(*(undefined4 *)((int)&DAT_8039bd58 + local_114),local_110,0x7e);
      uVar14 = 1;
      iVar20 = iVar34;
    }
    FUN_800229c4(0);
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
  FUN_802860f4();
  return;
}

