// Function: FUN_8008f2c8
// Entry: 8008f2c8
// Size: 1596 bytes

/* WARNING: Removing unreachable block (ram,0x8008f8dc) */
/* WARNING: Removing unreachable block (ram,0x8008f8cc) */
/* WARNING: Removing unreachable block (ram,0x8008f8bc) */
/* WARNING: Removing unreachable block (ram,0x8008f8ac) */
/* WARNING: Removing unreachable block (ram,0x8008f89c) */
/* WARNING: Removing unreachable block (ram,0x8008f894) */
/* WARNING: Removing unreachable block (ram,0x8008f8a4) */
/* WARNING: Removing unreachable block (ram,0x8008f8b4) */
/* WARNING: Removing unreachable block (ram,0x8008f8c4) */
/* WARNING: Removing unreachable block (ram,0x8008f8d4) */
/* WARNING: Removing unreachable block (ram,0x8008f8e4) */

void FUN_8008f2c8(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,undefined4 param_6,uint param_7,uint param_8)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  int iVar4;
  float *pfVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  double extraout_f1;
  double dVar9;
  double dVar10;
  undefined8 in_f21;
  double dVar11;
  undefined8 in_f22;
  undefined8 in_f23;
  double dVar12;
  undefined8 in_f24;
  double dVar13;
  undefined8 in_f25;
  double dVar14;
  double in_f26;
  double in_f27;
  double in_f28;
  undefined8 in_f29;
  double dVar15;
  undefined8 in_f30;
  double dVar16;
  undefined8 in_f31;
  undefined8 uVar17;
  undefined auStack424 [12];
  float local_19c;
  float local_198;
  float local_194;
  float local_190;
  float local_18c;
  float local_188;
  float local_184;
  float local_180;
  float local_17c;
  undefined auStack376 [12];
  float local_16c;
  float local_168;
  float local_164;
  float local_160;
  float local_15c;
  float local_158;
  undefined auStack340 [12];
  undefined auStack328 [48];
  double local_118;
  undefined4 local_110;
  uint uStack268;
  undefined4 local_108;
  uint uStack260;
  undefined4 local_100;
  uint uStack252;
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
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,SUB84(in_f28,0),0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,SUB84(in_f27,0),0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,SUB84(in_f26,0),0);
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
  uVar17 = FUN_802860c8();
  pfVar3 = (float *)((ulonglong)uVar17 >> 0x20);
  pfVar5 = (float *)uVar17;
  if (param_7 < 3) {
    dVar11 = extraout_f1;
    FUN_80247754(pfVar5,pfVar3,auStack340);
    dVar9 = (double)FUN_802477f0(auStack340);
    FUN_80247778((double)(float)((double)FLOAT_803df1a4 / dVar9),auStack340,&local_160);
    if (FLOAT_803df1b8 <= ABS(local_160)) {
      local_16c = FLOAT_803df1a0;
      local_164 = FLOAT_803df1a4;
    }
    else {
      local_16c = FLOAT_803df1a4;
      local_164 = FLOAT_803df1a0;
    }
    local_168 = FLOAT_803df1a0;
    FUN_8024784c(&local_160,&local_16c,auStack376);
    FUN_8024784c(auStack376,&local_160,&local_16c);
    FUN_80247794(&local_16c,&local_16c);
    iVar6 = (int)(dVar9 * dVar11);
    local_118 = (double)(longlong)iVar6;
    if (10 < iVar6) {
      iVar6 = 10;
    }
    if (iVar6 != 0) {
      iVar4 = 0;
      fVar1 = FLOAT_803df1a0;
      if (0 < iVar6) {
        if ((8 < iVar6) && (uVar7 = iVar6 - 1U >> 3, 0 < iVar6 + -8)) {
          do {
            local_118 = (double)CONCAT44(0x43300000,iVar4 + 1U ^ 0x80000000);
            uStack268 = iVar4 + 2U ^ 0x80000000;
            local_110 = 0x43300000;
            uStack260 = iVar4 + 3U ^ 0x80000000;
            local_108 = 0x43300000;
            uStack252 = iVar4 + 4U ^ 0x80000000;
            local_100 = 0x43300000;
            uStack244 = iVar4 + 5U ^ 0x80000000;
            local_f8 = 0x43300000;
            uStack236 = iVar4 + 6U ^ 0x80000000;
            local_f0 = 0x43300000;
            uStack228 = iVar4 + 7U ^ 0x80000000;
            local_e8 = 0x43300000;
            uStack220 = iVar4 + 8U ^ 0x80000000;
            local_e0 = 0x43300000;
            fVar1 = fVar1 + (float)(local_118 - DOUBLE_803df1a8) +
                    (float)((double)CONCAT44(0x43300000,uStack268) - DOUBLE_803df1a8) +
                    (float)((double)CONCAT44(0x43300000,uStack260) - DOUBLE_803df1a8) +
                    (float)((double)CONCAT44(0x43300000,uStack252) - DOUBLE_803df1a8) +
                    (float)((double)CONCAT44(0x43300000,uStack244) - DOUBLE_803df1a8) +
                    (float)((double)CONCAT44(0x43300000,uStack236) - DOUBLE_803df1a8) +
                    (float)((double)CONCAT44(0x43300000,uStack228) - DOUBLE_803df1a8) +
                    (float)((double)CONCAT44(0x43300000,uStack220) - DOUBLE_803df1a8);
            iVar4 = iVar4 + 8;
            uVar7 = uVar7 - 1;
          } while (uVar7 != 0);
        }
        iVar2 = iVar6 - iVar4;
        if (iVar4 < iVar6) {
          do {
            uStack220 = iVar4 + 1U ^ 0x80000000;
            local_e0 = 0x43300000;
            fVar1 = fVar1 + (float)((double)CONCAT44(0x43300000,uStack220) - DOUBLE_803df1a8);
            iVar4 = iVar4 + 1;
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
        }
      }
      dVar13 = (double)(FLOAT_803df1a4 / fVar1);
      local_190 = *pfVar3;
      dVar14 = (double)local_190;
      local_18c = pfVar3[1];
      local_188 = pfVar3[2];
      dVar12 = (double)FLOAT_803df1a0;
      dVar15 = (double)local_188;
      dVar16 = (double)local_18c;
      for (iVar4 = 0; iVar4 <= iVar6; iVar4 = iVar4 + 1) {
        if (iVar4 < iVar6) {
          uStack220 = FUN_800221a0(1,100);
          uStack220 = uStack220 ^ 0x80000000;
          local_e0 = 0x43300000;
          FUN_80247778((double)(FLOAT_803df1bc *
                               FLOAT_803df1c0 *
                               (float)(dVar9 * (double)(float)((double)CONCAT44(0x43300000,uStack220
                                                                               ) - DOUBLE_803df1a8))
                               ),&local_16c,&local_184);
          uStack228 = FUN_800221a0(0,1000);
          uStack228 = uStack228 ^ 0x80000000;
          local_e8 = 0x43300000;
          FUN_802471e0((double)(FLOAT_803df1c4 *
                               FLOAT_803df1c8 *
                               FLOAT_803df1cc *
                               (float)((double)CONCAT44(0x43300000,uStack228) - DOUBLE_803df1a8)),
                       auStack328,&local_160);
          FUN_80247574(auStack328,&local_184,&local_184);
          uStack244 = iVar6 - iVar4 ^ 0x80000000;
          local_f0 = 0x43300000;
          dVar12 = (double)(float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack244) -
                                                           DOUBLE_803df1a8) + dVar12);
          local_f8 = 0x43300000;
          dVar10 = (double)(float)(dVar13 * (double)(float)(dVar9 * (double)(float)((double)CONCAT44
                                                  (0x43300000,uStack244) - DOUBLE_803df1a8)));
          dVar14 = (double)(float)((double)local_160 * dVar10 + dVar14);
          in_f27 = (double)(float)((double)local_15c * dVar10 + dVar16);
          in_f26 = (double)(float)((double)local_158 * dVar10 + dVar15);
          local_19c = (float)(dVar14 + (double)local_184);
          local_198 = (float)(in_f27 + (double)local_180);
          local_194 = (float)(in_f26 + (double)local_17c);
          uStack236 = uStack244;
          iVar2 = FUN_800221a0(1,3);
          if (((iVar2 == 1) && (0xb < (param_5 & 0xff))) && ((param_8 & 1) == 0)) {
            uStack220 = FUN_800221a0(0x32,100);
            uStack220 = uStack220 ^ 0x80000000;
            local_e0 = 0x43300000;
            FUN_80247778((double)(FLOAT_803df1bc *
                                 FLOAT_803df1d0 *
                                 (float)(dVar9 * (double)(float)((double)CONCAT44(0x43300000,
                                                                                  uStack220) -
                                                                DOUBLE_803df1a8))),&local_16c,
                         &local_184);
            uStack228 = FUN_800221a0(0,1000);
            uStack228 = uStack228 ^ 0x80000000;
            local_e8 = 0x43300000;
            FUN_802471e0((double)(FLOAT_803df1c4 *
                                 FLOAT_803df1c8 *
                                 FLOAT_803df1cc *
                                 (float)((double)CONCAT44(0x43300000,uStack228) - DOUBLE_803df1a8)),
                         auStack328,&local_160);
            FUN_80247574(auStack328,&local_184,&local_184);
            uStack236 = FUN_800221a0(0,1000);
            uStack236 = uStack236 ^ 0x80000000;
            local_f0 = 0x43300000;
            FUN_80247778((double)(float)((double)(float)((double)FLOAT_803df1cc *
                                                         (double)((float)((double)FLOAT_803df1a4 -
                                                                         dVar12) *
                                                                 (float)((double)CONCAT44(0x43300000
                                                                                          ,uStack236
                                                                                         ) -
                                                                        DOUBLE_803df1a8)) + dVar12)
                                        * dVar9),&local_160,auStack424);
            FUN_80247730(pfVar3,auStack424,auStack424);
            FUN_80247730(auStack424,&local_184,auStack424);
            FUN_8008f2c8(dVar11,param_2,&local_19c,auStack424,(int)(param_5 & 0xff) >> 1,param_6,
                         param_7 + 1,param_8);
          }
        }
        else {
          local_19c = *pfVar5;
          local_198 = pfVar5[1];
          local_194 = pfVar5[2];
          dVar14 = in_f28;
        }
        FUN_8008ee18(param_2,&local_190,&local_19c,param_5,param_6);
        local_190 = local_19c;
        local_18c = local_198;
        local_188 = local_194;
        in_f28 = dVar14;
        dVar15 = in_f26;
        dVar16 = in_f27;
      }
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  __psq_l0(auStack72,uVar8);
  __psq_l1(auStack72,uVar8);
  __psq_l0(auStack88,uVar8);
  __psq_l1(auStack88,uVar8);
  __psq_l0(auStack104,uVar8);
  __psq_l1(auStack104,uVar8);
  __psq_l0(auStack120,uVar8);
  __psq_l1(auStack120,uVar8);
  __psq_l0(auStack136,uVar8);
  __psq_l1(auStack136,uVar8);
  __psq_l0(auStack152,uVar8);
  __psq_l1(auStack152,uVar8);
  __psq_l0(auStack168,uVar8);
  __psq_l1(auStack168,uVar8);
  FUN_80286114();
  return;
}

