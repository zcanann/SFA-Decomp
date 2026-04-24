// Function: FUN_8008f554
// Entry: 8008f554
// Size: 1596 bytes

/* WARNING: Removing unreachable block (ram,0x8008fb70) */
/* WARNING: Removing unreachable block (ram,0x8008fb68) */
/* WARNING: Removing unreachable block (ram,0x8008fb60) */
/* WARNING: Removing unreachable block (ram,0x8008fb58) */
/* WARNING: Removing unreachable block (ram,0x8008fb50) */
/* WARNING: Removing unreachable block (ram,0x8008fb48) */
/* WARNING: Removing unreachable block (ram,0x8008fb40) */
/* WARNING: Removing unreachable block (ram,0x8008fb38) */
/* WARNING: Removing unreachable block (ram,0x8008fb30) */
/* WARNING: Removing unreachable block (ram,0x8008fb28) */
/* WARNING: Removing unreachable block (ram,0x8008fb20) */
/* WARNING: Removing unreachable block (ram,0x8008f5b4) */
/* WARNING: Removing unreachable block (ram,0x8008f5ac) */
/* WARNING: Removing unreachable block (ram,0x8008f5a4) */
/* WARNING: Removing unreachable block (ram,0x8008f59c) */
/* WARNING: Removing unreachable block (ram,0x8008f594) */
/* WARNING: Removing unreachable block (ram,0x8008f58c) */
/* WARNING: Removing unreachable block (ram,0x8008f584) */
/* WARNING: Removing unreachable block (ram,0x8008f57c) */
/* WARNING: Removing unreachable block (ram,0x8008f574) */
/* WARNING: Removing unreachable block (ram,0x8008f56c) */
/* WARNING: Removing unreachable block (ram,0x8008f564) */

void FUN_8008f554(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,undefined4 *param_6,uint param_7,uint param_8)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  int iVar4;
  float *pfVar5;
  int iVar6;
  uint uVar7;
  double extraout_f1;
  double dVar8;
  double dVar9;
  double in_f21;
  double dVar10;
  double in_f22;
  double in_f23;
  double dVar11;
  double in_f24;
  double dVar12;
  double in_f25;
  double dVar13;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double dVar14;
  double in_f30;
  double dVar15;
  double in_f31;
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
  undefined8 uVar16;
  float afStack_1a8 [3];
  float local_19c;
  float local_198;
  float local_194;
  float local_190;
  float local_18c;
  float local_188;
  float local_184;
  float local_180;
  float local_17c;
  float afStack_178 [3];
  float local_16c;
  float local_168;
  float local_164;
  float local_160;
  float local_15c;
  float local_158;
  float afStack_154 [3];
  float afStack_148 [12];
  undefined8 local_118;
  undefined4 local_110;
  uint uStack_10c;
  undefined4 local_108;
  uint uStack_104;
  undefined4 local_100;
  uint uStack_fc;
  undefined4 local_f8;
  uint uStack_f4;
  undefined4 local_f0;
  uint uStack_ec;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
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
  uVar16 = FUN_8028682c();
  pfVar3 = (float *)((ulonglong)uVar16 >> 0x20);
  pfVar5 = (float *)uVar16;
  if (param_7 < 3) {
    dVar10 = extraout_f1;
    FUN_80247eb8(pfVar5,pfVar3,afStack_154);
    dVar8 = FUN_80247f54(afStack_154);
    FUN_80247edc((double)(float)((double)FLOAT_803dfe24 / dVar8),afStack_154,&local_160);
    if (FLOAT_803dfe38 <= ABS(local_160)) {
      local_16c = FLOAT_803dfe20;
      local_164 = FLOAT_803dfe24;
    }
    else {
      local_16c = FLOAT_803dfe24;
      local_164 = FLOAT_803dfe20;
    }
    local_168 = FLOAT_803dfe20;
    FUN_80247fb0(&local_160,&local_16c,afStack_178);
    FUN_80247fb0(afStack_178,&local_160,&local_16c);
    FUN_80247ef8(&local_16c,&local_16c);
    iVar6 = (int)(dVar8 * dVar10);
    local_118 = (double)(longlong)iVar6;
    if (10 < iVar6) {
      iVar6 = 10;
    }
    if (iVar6 != 0) {
      iVar4 = 0;
      fVar1 = FLOAT_803dfe20;
      if (0 < iVar6) {
        if ((8 < iVar6) && (uVar7 = iVar6 - 1U >> 3, 0 < iVar6 + -8)) {
          do {
            local_118 = (double)CONCAT44(0x43300000,iVar4 + 1U ^ 0x80000000);
            uStack_10c = iVar4 + 2U ^ 0x80000000;
            local_110 = 0x43300000;
            uStack_104 = iVar4 + 3U ^ 0x80000000;
            local_108 = 0x43300000;
            uStack_fc = iVar4 + 4U ^ 0x80000000;
            local_100 = 0x43300000;
            uStack_f4 = iVar4 + 5U ^ 0x80000000;
            local_f8 = 0x43300000;
            uStack_ec = iVar4 + 6U ^ 0x80000000;
            local_f0 = 0x43300000;
            uStack_e4 = iVar4 + 7U ^ 0x80000000;
            local_e8 = 0x43300000;
            uStack_dc = iVar4 + 8U ^ 0x80000000;
            local_e0 = 0x43300000;
            fVar1 = fVar1 + (float)(local_118 - DOUBLE_803dfe28) +
                    (float)((double)CONCAT44(0x43300000,uStack_10c) - DOUBLE_803dfe28) +
                    (float)((double)CONCAT44(0x43300000,uStack_104) - DOUBLE_803dfe28) +
                    (float)((double)CONCAT44(0x43300000,uStack_fc) - DOUBLE_803dfe28) +
                    (float)((double)CONCAT44(0x43300000,uStack_f4) - DOUBLE_803dfe28) +
                    (float)((double)CONCAT44(0x43300000,uStack_ec) - DOUBLE_803dfe28) +
                    (float)((double)CONCAT44(0x43300000,uStack_e4) - DOUBLE_803dfe28) +
                    (float)((double)CONCAT44(0x43300000,uStack_dc) - DOUBLE_803dfe28);
            iVar4 = iVar4 + 8;
            uVar7 = uVar7 - 1;
          } while (uVar7 != 0);
        }
        iVar2 = iVar6 - iVar4;
        if (iVar4 < iVar6) {
          do {
            uStack_dc = iVar4 + 1U ^ 0x80000000;
            local_e0 = 0x43300000;
            fVar1 = fVar1 + (float)((double)CONCAT44(0x43300000,uStack_dc) - DOUBLE_803dfe28);
            iVar4 = iVar4 + 1;
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
        }
      }
      dVar12 = (double)(FLOAT_803dfe24 / fVar1);
      local_190 = *pfVar3;
      dVar13 = (double)local_190;
      local_18c = pfVar3[1];
      local_188 = pfVar3[2];
      dVar11 = (double)FLOAT_803dfe20;
      dVar14 = (double)local_188;
      dVar15 = (double)local_18c;
      for (iVar4 = 0; iVar4 <= iVar6; iVar4 = iVar4 + 1) {
        if (iVar4 < iVar6) {
          uStack_dc = FUN_80022264(1,100);
          uStack_dc = uStack_dc ^ 0x80000000;
          local_e0 = 0x43300000;
          FUN_80247edc((double)(FLOAT_803dfe3c *
                               FLOAT_803dfe40 *
                               (float)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack_dc
                                                                               ) - DOUBLE_803dfe28))
                               ),&local_16c,&local_184);
          uStack_e4 = FUN_80022264(0,1000);
          uStack_e4 = uStack_e4 ^ 0x80000000;
          local_e8 = 0x43300000;
          FUN_80247944((double)(FLOAT_803dfe44 *
                               FLOAT_803dfe48 *
                               FLOAT_803dfe4c *
                               (float)((double)CONCAT44(0x43300000,uStack_e4) - DOUBLE_803dfe28)),
                       afStack_148,&local_160);
          FUN_80247cd8(afStack_148,&local_184,&local_184);
          uStack_f4 = iVar6 - iVar4 ^ 0x80000000;
          local_f0 = 0x43300000;
          dVar11 = (double)(float)(dVar12 * (double)(float)((double)CONCAT44(0x43300000,uStack_f4) -
                                                           DOUBLE_803dfe28) + dVar11);
          local_f8 = 0x43300000;
          dVar9 = (double)(float)(dVar12 * (double)(float)(dVar8 * (double)(float)((double)CONCAT44(
                                                  0x43300000,uStack_f4) - DOUBLE_803dfe28)));
          dVar13 = (double)(float)((double)local_160 * dVar9 + dVar13);
          in_f27 = (double)(float)((double)local_15c * dVar9 + dVar15);
          in_f26 = (double)(float)((double)local_158 * dVar9 + dVar14);
          local_19c = (float)(dVar13 + (double)local_184);
          local_198 = (float)(in_f27 + (double)local_180);
          local_194 = (float)(in_f26 + (double)local_17c);
          uStack_ec = uStack_f4;
          uVar7 = FUN_80022264(1,3);
          if (((uVar7 == 1) && (0xb < (param_5 & 0xff))) && ((param_8 & 1) == 0)) {
            uStack_dc = FUN_80022264(0x32,100);
            uStack_dc = uStack_dc ^ 0x80000000;
            local_e0 = 0x43300000;
            FUN_80247edc((double)(FLOAT_803dfe3c *
                                 FLOAT_803dfe50 *
                                 (float)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,
                                                                                  uStack_dc) -
                                                                DOUBLE_803dfe28))),&local_16c,
                         &local_184);
            uStack_e4 = FUN_80022264(0,1000);
            uStack_e4 = uStack_e4 ^ 0x80000000;
            local_e8 = 0x43300000;
            FUN_80247944((double)(FLOAT_803dfe44 *
                                 FLOAT_803dfe48 *
                                 FLOAT_803dfe4c *
                                 (float)((double)CONCAT44(0x43300000,uStack_e4) - DOUBLE_803dfe28)),
                         afStack_148,&local_160);
            FUN_80247cd8(afStack_148,&local_184,&local_184);
            uStack_ec = FUN_80022264(0,1000);
            uStack_ec = uStack_ec ^ 0x80000000;
            local_f0 = 0x43300000;
            FUN_80247edc((double)(float)((double)(float)((double)FLOAT_803dfe4c *
                                                         (double)((float)((double)FLOAT_803dfe24 -
                                                                         dVar11) *
                                                                 (float)((double)CONCAT44(0x43300000
                                                                                          ,uStack_ec
                                                                                         ) -
                                                                        DOUBLE_803dfe28)) + dVar11)
                                        * dVar8),&local_160,afStack_1a8);
            FUN_80247e94(pfVar3,afStack_1a8,afStack_1a8);
            FUN_80247e94(afStack_1a8,&local_184,afStack_1a8);
            FUN_8008f554(dVar10,param_2,&local_19c,afStack_1a8,(int)(param_5 & 0xff) >> 1,param_6,
                         param_7 + 1,param_8);
          }
        }
        else {
          local_19c = *pfVar5;
          local_198 = pfVar5[1];
          local_194 = pfVar5[2];
          dVar13 = in_f28;
        }
        FUN_8008f0a4(&local_190,&local_19c,param_5,param_6);
        local_190 = local_19c;
        local_18c = local_198;
        local_188 = local_194;
        in_f28 = dVar13;
        dVar14 = in_f26;
        dVar15 = in_f27;
      }
    }
  }
  FUN_80286878();
  return;
}

