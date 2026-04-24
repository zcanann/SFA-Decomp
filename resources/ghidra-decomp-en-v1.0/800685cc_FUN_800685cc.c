// Function: FUN_800685cc
// Entry: 800685cc
// Size: 3060 bytes

/* WARNING: Removing unreachable block (ram,0x80069198) */
/* WARNING: Removing unreachable block (ram,0x80068dd8) */
/* WARNING: Removing unreachable block (ram,0x800691a0) */
/* WARNING: Removing unreachable block (ram,0x80068de0) */
/* WARNING: Removing unreachable block (ram,0x80068de8) */
/* WARNING: Removing unreachable block (ram,0x80068eb8) */
/* WARNING: Removing unreachable block (ram,0x80068ec0) */
/* WARNING: Removing unreachable block (ram,0x80068ec8) */

void FUN_800685cc(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5,
                 int param_6,int param_7,uint param_8,char param_9)

{
  int iVar1;
  short sVar2;
  short sVar3;
  bool bVar4;
  float *pfVar5;
  uint uVar6;
  uint uVar7;
  int *piVar8;
  int iVar9;
  undefined4 uVar10;
  char cVar13;
  char cVar14;
  ushort *puVar11;
  float *pfVar12;
  ushort *puVar15;
  short *psVar16;
  undefined uVar17;
  float *pfVar18;
  int iVar19;
  uint uVar20;
  int iVar21;
  int iVar22;
  int iVar23;
  int *piVar24;
  int *piVar25;
  int iVar26;
  int iVar27;
  int iVar28;
  int *piVar29;
  int *piVar30;
  int iVar31;
  uint uVar32;
  int *piVar33;
  byte bVar34;
  int iVar35;
  int iVar36;
  int iVar37;
  int iVar38;
  ushort *puVar39;
  int iVar40;
  undefined *puVar41;
  int iVar42;
  undefined4 uVar43;
  undefined4 uVar44;
  double dVar45;
  double dVar46;
  double dVar47;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar48;
  uint local_1b8;
  uint local_1b0;
  uint local_1ac;
  uint local_1a4;
  undefined auStack416 [4];
  int local_19c;
  uint local_198;
  float local_194;
  float local_190;
  float local_18c;
  float local_188;
  float local_184;
  float local_180;
  float local_17c [3];
  undefined auStack368 [12];
  undefined auStack356 [12];
  undefined auStack344 [12];
  undefined auStack332 [12];
  int local_140 [16];
  undefined4 local_100;
  uint uStack252;
  longlong local_f8;
  undefined4 local_f0;
  uint uStack236;
  longlong local_e8;
  undefined4 local_e0;
  uint uStack220;
  longlong local_d8;
  undefined4 local_d0;
  uint uStack204;
  longlong local_c8;
  uint local_c0;
  uint local_bc;
  undefined local_b8;
  ushort *local_b4;
  uint local_b0;
  int local_ac;
  int local_a8;
  int local_a4;
  int local_a0;
  int *local_9c;
  int *local_98;
  uint local_94;
  uint local_90;
  uint local_8c;
  uint local_88;
  uint local_84;
  uint local_80;
  uint local_7c;
  uint local_78;
  uint local_74;
  undefined4 *local_70;
  int local_6c;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar44 = 0x70007;
  uVar43 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar48 = FUN_802860a8();
  pfVar12 = (float *)((ulonglong)uVar48 >> 0x20);
  uVar6 = (int)uVar48 - DAT_803dcdc8;
  uVar7 = param_4 - DAT_803dcdcc;
  local_1ac = param_5 - DAT_803dcdc8;
  local_1a4 = param_7 - DAT_803dcdcc;
  local_1b8 = uVar6;
  if ((int)local_1ac < (int)uVar6) {
    local_1b8 = local_1ac;
    local_1ac = uVar6;
  }
  local_1b0 = uVar7;
  if ((int)local_1a4 < (int)uVar7) {
    local_1b0 = local_1a4;
    local_1a4 = uVar7;
  }
  uStack252 = local_1b8 ^ 0x80000000;
  local_100 = 0x43300000;
  dVar45 = (double)FUN_80291e40((double)((float)((double)CONCAT44(0x43300000,uStack252) -
                                                DOUBLE_803decd8) / FLOAT_803dece0));
  iVar1 = (int)dVar45;
  local_f8 = (longlong)iVar1;
  uStack236 = local_1b0 ^ 0x80000000;
  local_f0 = 0x43300000;
  dVar45 = (double)FUN_80291e40((double)((float)((double)CONCAT44(0x43300000,uStack236) -
                                                DOUBLE_803decd8) / FLOAT_803dece0));
  iVar26 = (int)dVar45;
  local_e8 = (longlong)iVar26;
  uStack220 = local_1ac ^ 0x80000000;
  local_e0 = 0x43300000;
  dVar45 = (double)FUN_80291e40((double)((float)((double)CONCAT44(0x43300000,uStack220) -
                                                DOUBLE_803decd8) / FLOAT_803dece0));
  local_d8 = (longlong)(int)dVar45;
  uStack204 = local_1a4 ^ 0x80000000;
  local_d0 = 0x43300000;
  dVar46 = (double)FUN_80291e40((double)((float)((double)CONCAT44(0x43300000,uStack204) -
                                                DOUBLE_803decd8) / FLOAT_803dece0));
  local_c8 = (longlong)(int)dVar46;
  iVar35 = 0;
  iVar38 = 0;
  piVar33 = local_140;
  piVar8 = &DAT_8038de44;
  local_9c = &DAT_8038de44;
  local_98 = piVar33;
  do {
    iVar31 = iVar1 * 0x280;
    piVar24 = piVar33;
    piVar25 = piVar8;
    iVar40 = iVar1;
    while ((iVar40 <= (int)dVar45 && (iVar35 < 0x10))) {
      iVar28 = iVar26 * 0x280;
      piVar29 = piVar24;
      piVar30 = piVar25;
      iVar23 = iVar26;
      while ((iVar23 <= (int)dVar46 && (iVar35 < 0x10))) {
        iVar27 = FUN_8005af2c(iVar40,iVar23,iVar38);
        if (iVar27 != 0) {
          *piVar24 = iVar27;
          *piVar25 = iVar31;
          piVar25[2] = iVar28;
          piVar24 = piVar24 + 1;
          piVar25 = piVar25 + 3;
          piVar29 = piVar29 + 1;
          piVar30 = piVar30 + 3;
          piVar33 = piVar33 + 1;
          piVar8 = piVar8 + 3;
          iVar35 = iVar35 + 1;
        }
        iVar28 = iVar28 + 0x280;
        iVar23 = iVar23 + 1;
      }
      iVar31 = iVar31 + 0x280;
      iVar40 = iVar40 + 1;
      piVar24 = piVar29;
      piVar25 = piVar30;
    }
    iVar38 = iVar38 + 1;
  } while (iVar38 < 5);
  if (iVar35 != 0) {
    uVar10 = FUN_800606dc(local_140[0],0);
    local_c0 = 0;
    local_198 = 0;
    FUN_8001f978(uVar10,(uint)*(ushort *)(local_140[0] + 0x98) << 3,&local_198,&local_19c,0x2000);
    FUN_8001f978(*(undefined4 *)(local_140[0] + 0x58),(uint)*(ushort *)(local_140[0] + 0x90) * 6,
                 &local_19c,auStack416,0x2000);
    local_70 = &DAT_8038de44;
    local_78 = param_8 & 0x40;
    local_7c = param_8 & 0x80;
    local_80 = param_8 & 0x200;
    local_84 = param_8 & 0x120;
    local_88 = param_8 & 0x20;
    local_8c = param_8 & 8;
    local_90 = param_8 & 0x100;
    local_94 = param_8 & 4;
    local_6c = iVar35 + -1;
    for (local_ac = 0; iVar1 = local_19c, local_ac < iVar35; local_ac = local_ac + 1) {
      local_bc = local_198;
      if (local_ac < local_6c) {
        iVar26 = local_98[1];
        local_c0 = local_c0 ^ 0x2000;
        iVar38 = local_c0 + 0x2000;
        uVar10 = FUN_800606dc(iVar26,0);
        local_198 = local_c0;
        cVar13 = FUN_8001f978(uVar10,(uint)*(ushort *)(iVar26 + 0x98) << 3,&local_198,&local_19c,
                              iVar38);
        cVar14 = FUN_8001f978(*(undefined4 *)(iVar26 + 0x58),(uint)*(ushort *)(iVar26 + 0x90) * 6,
                              &local_19c,auStack416,iVar38);
        FUN_800229c4(cVar13 + cVar14);
      }
      else {
        FUN_800229c4(0);
      }
      iVar38 = *local_98;
      iVar26 = *local_9c;
      local_a0 = local_1b8 - iVar26;
      local_a8 = local_1ac - iVar26;
      local_a4 = local_1b0 - local_9c[2];
      iVar40 = local_1a4 - local_9c[2];
      *local_9c = iVar26 + DAT_803dcdc8;
      local_9c[2] = local_9c[2] + DAT_803dcdcc;
      if (local_a0 < 0) {
        local_a0 = 0;
      }
      if (0x280 < local_a8) {
        local_a8 = 0x280;
      }
      if (local_a4 < 0) {
        local_a4 = 0;
      }
      if (0x280 < iVar40) {
        iVar40 = 0x280;
      }
      sVar2 = (short)*local_9c - (short)*local_70;
      sVar3 = (short)local_9c[2] - (short)local_70[2];
      uVar6 = 0;
      uVar7 = 1;
      iVar26 = 0;
      iVar31 = 2;
      do {
        if ((local_a0 <= iVar26 + 0x50) && (iVar26 <= local_a8)) {
          uVar6 = uVar6 | uVar7;
        }
        uVar7 = (uint)(short)((int)(short)uVar7 << 1);
        if ((local_a0 <= iVar26 + 0xa0) && (iVar26 + 0x50 <= local_a8)) {
          uVar6 = uVar6 | uVar7;
        }
        uVar7 = (uint)(short)(uVar7 << 1);
        if ((local_a0 <= iVar26 + 0xf0) && (iVar26 + 0xa0 <= local_a8)) {
          uVar6 = uVar6 | uVar7;
        }
        uVar7 = (uint)(short)(uVar7 << 1);
        if ((local_a0 <= iVar26 + 0x140) && (iVar26 + 0xf0 <= local_a8)) {
          uVar6 = uVar6 | uVar7;
        }
        uVar7 = (uint)(short)(uVar7 << 1);
        iVar26 = iVar26 + 0x140;
        iVar31 = iVar31 + -1;
      } while (iVar31 != 0);
      iVar26 = 0;
      iVar31 = 2;
      do {
        if ((local_a4 <= iVar26 + 0x50) && (iVar26 <= iVar40)) {
          uVar6 = uVar6 | uVar7;
        }
        uVar7 = (uint)(short)((int)(short)uVar7 << 1);
        if ((local_a4 <= iVar26 + 0xa0) && (iVar26 + 0x50 <= iVar40)) {
          uVar6 = uVar6 | uVar7;
        }
        uVar7 = (uint)(short)(uVar7 << 1);
        if ((local_a4 <= iVar26 + 0xf0) && (iVar26 + 0xa0 <= iVar40)) {
          uVar6 = uVar6 | uVar7;
        }
        uVar7 = (uint)(short)(uVar7 << 1);
        if ((local_a4 <= iVar26 + 0x140) && (iVar26 + 0xf0 <= iVar40)) {
          uVar6 = uVar6 | uVar7;
        }
        uVar7 = (uint)(short)(uVar7 << 1);
        iVar26 = iVar26 + 0x140;
        iVar31 = iVar31 + -1;
      } while (iVar31 != 0);
      puVar15 = *(ushort **)(iVar38 + 0x50);
      local_b4 = puVar15 + (uint)*(ushort *)(iVar38 + 0x9a) * 10;
      local_74 = (uint)(short)uVar6;
      for (; puVar15 < local_b4; puVar15 = puVar15 + 10) {
        uVar6 = *(uint *)(puVar15 + 8);
        if ((((uVar6 & 0x10) == 0) || (local_78 == 0)) && (((uVar6 & 4) != 0 || (local_7c == 0)))) {
          if ((uVar6 & 8) == 0) {
            if (((uVar6 & 2) == 0) || (local_88 != 0)) {
              bVar34 = 2;
              goto LAB_80068cb4;
            }
          }
          else if (((uVar6 & 1) == 0) && (local_80 == 0)) {
            bVar34 = 4;
            if (local_84 == 0) {
              bVar34 = 0x14;
            }
LAB_80068cb4:
            if (((((int)(short)puVar15[3] + (int)*(short *)(iVar38 + 0x8e) <= param_6) &&
                 (param_3 <= (int)(short)puVar15[4] + (int)*(short *)(iVar38 + 0x8e))) &&
                ((short)puVar15[1] <= local_a8)) &&
               (((local_a0 <= (short)puVar15[2] && ((short)puVar15[5] <= iVar40)) &&
                (local_a4 <= (short)puVar15[6])))) {
              if ((uVar6 & 4) != 0) {
                bVar34 = bVar34 | 8;
              }
              local_b8 = FUN_80060668(puVar15);
              uVar6 = (uint)*puVar15;
              puVar39 = (ushort *)(local_bc + uVar6 * 8);
              local_b0 = (uint)puVar15[10];
              for (; (int)uVar6 < (int)local_b0; uVar6 = uVar6 + 1) {
                if (((local_74 & puVar39[3] & 0xff) != 0) && ((local_74 & puVar39[3] & 0xff00) != 0)
                   ) {
                  psVar16 = (short *)(iVar1 + (uint)*puVar39 * 6);
                  iVar26 = (int)*psVar16 >> 3;
                  iVar23 = ((int)psVar16[1] >> 3) + (int)*(short *)(iVar38 + 0x8e);
                  iVar27 = (int)psVar16[2] >> 3;
                  *(short *)(pfVar12 + 4) = (short)iVar26 + sVar2;
                  *(short *)((int)pfVar12 + 0x16) = (short)iVar23;
                  *(short *)(pfVar12 + 7) = (short)iVar27 + sVar3;
                  uVar10 = __psq_l0(pfVar12 + 4,uVar44);
                  local_188 = (float)(double)CONCAT44(uVar10,0x3f800000);
                  uVar10 = __psq_l0((int)pfVar12 + 0x16,uVar44);
                  local_184 = (float)(double)CONCAT44(uVar10,0x3f800000);
                  uVar10 = __psq_l0(pfVar12 + 7,uVar44);
                  local_180 = (float)(double)CONCAT44(uVar10,0x3f800000);
                  uVar7 = 0;
                  uVar32 = 0;
                  uVar20 = 1;
                  pfVar18 = local_17c;
                  iVar42 = 2;
                  iVar31 = iVar26;
                  iVar28 = iVar23;
                  iVar36 = iVar27;
                  puVar11 = puVar39;
                  pfVar5 = pfVar12;
                  do {
                    puVar11 = puVar11 + 1;
                    psVar16 = (short *)(iVar1 + (uint)*puVar11 * 6);
                    iVar9 = (int)*psVar16 >> 3;
                    iVar21 = ((int)psVar16[1] >> 3) + (int)*(short *)(iVar38 + 0x8e);
                    iVar19 = (int)psVar16[2] >> 3;
                    iVar22 = iVar9;
                    if ((iVar9 <= iVar31) && (iVar22 = iVar31, iVar9 < iVar26)) {
                      iVar26 = iVar9;
                    }
                    if (iVar28 < iVar21) {
                      uVar7 = uVar20 & 0xff;
                      iVar28 = iVar21;
                    }
                    else if (iVar21 < iVar23) {
                      uVar32 = uVar20 & 0xff;
                      iVar23 = iVar21;
                    }
                    iVar37 = iVar19;
                    if ((iVar19 <= iVar36) && (iVar37 = iVar36, iVar19 < iVar27)) {
                      iVar27 = iVar19;
                    }
                    *(short *)((int)pfVar5 + 0x12) = (short)iVar9 + sVar2;
                    *(short *)(pfVar5 + 6) = (short)iVar21;
                    *(short *)((int)pfVar5 + 0x1e) = (short)iVar19 + sVar3;
                    uVar10 = __psq_l0((int)pfVar5 + 0x12,uVar44);
                    *pfVar18 = (float)(double)CONCAT44(uVar10,0x3f800000);
                    uVar10 = __psq_l0(pfVar5 + 6,uVar44);
                    pfVar18[1] = (float)(double)CONCAT44(uVar10,0x3f800000);
                    uVar10 = __psq_l0((int)pfVar5 + 0x1e,uVar44);
                    pfVar18[2] = (float)(double)CONCAT44(uVar10,0x3f800000);
                    pfVar18 = pfVar18 + 3;
                    uVar20 = uVar20 + 1;
                    iVar42 = iVar42 + -1;
                    iVar31 = iVar22;
                    iVar36 = iVar37;
                    pfVar5 = (float *)((int)pfVar5 + 2);
                  } while (iVar42 != 0);
                  if ((((iVar23 <= param_6) && (param_3 <= iVar28)) && (iVar26 <= local_a8)) &&
                     (((local_a0 <= iVar22 && (iVar27 <= iVar40)) && (local_a4 <= iVar37)))) {
                    FUN_80247754(&local_188,local_17c,auStack356);
                    FUN_80247754(local_17c,auStack368,auStack344);
                    FUN_8024784c(auStack356,auStack344,pfVar12 + 1);
                    dVar45 = (double)FUN_802477f0(pfVar12 + 1);
                    if (((double)FLOAT_803decb4 < dVar45) &&
                       ((((FUN_80247778((double)(float)((double)FLOAT_803decc4 / dVar45),pfVar12 + 1
                                        ,pfVar12 + 1), local_8c == 0 ||
                          ((pfVar12[2] < FLOAT_803decb0 && (FLOAT_803decec < pfVar12[2])))) ||
                         ((bVar34 == 4 && (local_90 != 0)))) &&
                        (((local_94 == 0 || (FLOAT_803decb0 <= pfVar12[2])) ||
                         (pfVar12[2] <= FLOAT_803decec)))))) {
                      dVar45 = (double)FUN_8024782c(pfVar12 + 1,&local_188);
                      *pfVar12 = (float)-dVar45;
                      if (param_9 != '\0') {
                        FUN_80247754(auStack368,&local_188,auStack332);
                        bVar4 = false;
                        iVar31 = 0;
                        puVar41 = auStack356;
                        dVar45 = (double)FLOAT_803decb4;
                        dVar46 = (double)FLOAT_803decc4;
                        iVar26 = 0;
                        do {
                          FUN_8024784c(pfVar12 + 1,puVar41,&local_194);
                          dVar47 = (double)FUN_802477f0(&local_194);
                          if (dVar47 <= dVar45) {
                            bVar4 = true;
                            break;
                          }
                          FUN_80247778((double)(float)(dVar46 / dVar47),&local_194,&local_194);
                          pfVar12[iVar26 + 9] = local_194;
                          pfVar12[iVar26 + 10] = local_190;
                          pfVar12[iVar26 + 0xb] = local_18c;
                          puVar41 = puVar41 + 0xc;
                          iVar31 = iVar31 + 1;
                          iVar26 = iVar26 + 3;
                        } while (iVar31 < 3);
                        if (bVar4) goto LAB_80069140;
                      }
                      uVar17 = local_b8;
                      if ((*(uint *)(puVar15 + 8) & 8) != 0) {
                        uVar17 = 0xe;
                      }
                      if ((*(uint *)(puVar15 + 8) & 0x20) != 0) {
                        bVar34 = bVar34 | 0x40;
                      }
                      *(undefined *)(pfVar12 + 0x12) = uVar17;
                      *(byte *)((int)pfVar12 + 0x4a) = (byte)(uVar7 << 4) | (byte)uVar32;
                      *(byte *)((int)pfVar12 + 0x49) = bVar34;
                      pfVar12 = pfVar12 + 0x13;
                      if (DAT_803dcf70 <= pfVar12) goto LAB_80069198;
                    }
                  }
                }
LAB_80069140:
                puVar39 = puVar39 + 4;
              }
            }
          }
        }
      }
      local_98 = local_98 + 1;
      local_9c = local_9c + 3;
    }
  }
LAB_80069198:
  __psq_l0(auStack8,uVar43);
  __psq_l1(auStack8,uVar43);
  __psq_l0(auStack24,uVar43);
  __psq_l1(auStack24,uVar43);
  FUN_802860f4(pfVar12);
  return;
}

