// Function: FUN_80139a8c
// Entry: 80139a8c
// Size: 2404 bytes

/* WARNING: Removing unreachable block (ram,0x8013a3c8) */
/* WARNING: Removing unreachable block (ram,0x8013a3d0) */

void FUN_80139a8c(void)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  short *psVar4;
  short sVar7;
  undefined2 uVar8;
  int iVar5;
  short sVar9;
  undefined4 uVar6;
  int iVar10;
  float *pfVar11;
  undefined4 unaff_r28;
  int iVar12;
  undefined4 uVar13;
  double dVar14;
  double dVar15;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar16;
  undefined8 uVar17;
  undefined4 local_78;
  undefined2 local_74;
  float local_70;
  undefined4 local_6c;
  float local_68;
  float local_64;
  undefined4 local_60;
  float local_5c;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar17 = FUN_802860d4();
  psVar4 = (short *)((ulonglong)uVar17 >> 0x20);
  pfVar11 = (float *)uVar17;
  iVar12 = *(int *)(psVar4 + 0x5c);
  dVar16 = (double)*(float *)(iVar12 + 0x14);
  FUN_80148bc8(dVar16,&DAT_803dbc4c);
  *(float *)(iVar12 + 0x2c) = *pfVar11 - *(float *)(psVar4 + 0xc);
  *(float *)(iVar12 + 0x30) = pfVar11[2] - *(float *)(psVar4 + 0x10);
  dVar14 = (double)FUN_802931a0((double)(*(float *)(iVar12 + 0x2c) * *(float *)(iVar12 + 0x2c) +
                                        *(float *)(iVar12 + 0x30) * *(float *)(iVar12 + 0x30)));
  if ((double)FLOAT_803e23dc != dVar14) {
    *(float *)(iVar12 + 0x2c) = (float)((double)*(float *)(iVar12 + 0x2c) / dVar14);
    *(float *)(iVar12 + 0x30) = (float)((double)*(float *)(iVar12 + 0x30) / dVar14);
  }
  dVar14 = (double)FLOAT_803e2420;
  if (dVar14 <= dVar16) {
    local_64 = FLOAT_803db414 * (float)((double)*(float *)(iVar12 + 0x2c) * dVar16) +
               *(float *)(psVar4 + 0xc);
    local_60 = *(undefined4 *)(psVar4 + 0xe);
    local_5c = FLOAT_803db414 * (float)((double)*(float *)(iVar12 + 0x30) * dVar16) +
               *(float *)(psVar4 + 0x10);
  }
  else {
    local_64 = (float)(dVar14 * (double)*(float *)(iVar12 + 0x2c)) * FLOAT_803db414 +
               *(float *)(psVar4 + 0xc);
    local_60 = *(undefined4 *)(psVar4 + 0xe);
    local_5c = (float)(dVar14 * (double)*(float *)(iVar12 + 0x30)) * FLOAT_803db414 +
               *(float *)(psVar4 + 0x10);
  }
  local_70 = local_64;
  local_6c = local_60;
  local_68 = local_5c;
  FUN_8013b1e0(psVar4 + 0xc,&local_70,pfVar11);
  dVar14 = (double)FUN_800216d0(&local_64,&local_70);
  if ((double)FLOAT_803e2468 < dVar14) {
    *(float *)(iVar12 + 0x2c) = local_70 - *(float *)(psVar4 + 0xc);
    *(float *)(iVar12 + 0x30) = local_68 - *(float *)(psVar4 + 0x10);
    dVar14 = (double)FUN_802931a0((double)(*(float *)(iVar12 + 0x2c) * *(float *)(iVar12 + 0x2c) +
                                          *(float *)(iVar12 + 0x30) * *(float *)(iVar12 + 0x30)));
    if ((double)FLOAT_803e23dc != dVar14) {
      *(float *)(iVar12 + 0x2c) = (float)((double)*(float *)(iVar12 + 0x2c) / dVar14);
      *(float *)(iVar12 + 0x30) = (float)((double)*(float *)(iVar12 + 0x30) / dVar14);
    }
  }
  if (dVar16 < (double)FLOAT_803e2420) {
    sVar7 = *psVar4;
    sVar9 = 0;
    iVar10 = *(int *)(psVar4 + 0x5c);
    dVar16 = (double)*(float *)(iVar10 + 0x2c);
    dVar14 = (double)*(float *)(iVar10 + 0x30);
    if (FLOAT_803e23ec < (float)(dVar16 * dVar16) + (float)(dVar14 * dVar14)) {
      sVar9 = FUN_800217c0(-dVar16,-dVar14);
      sVar9 = FUN_80139930(psVar4,(int)sVar9);
      uStack76 = (int)*psVar4 ^ 0x80000000;
      local_50 = 0x43300000;
      dVar14 = (double)FUN_80293e80((double)((FLOAT_803e2454 *
                                             (float)((double)CONCAT44(0x43300000,uStack76) -
                                                    DOUBLE_803e2460)) / FLOAT_803e2458));
      *(float *)(iVar10 + 0x2c) = (float)-dVar14;
      uStack84 = (int)*psVar4 ^ 0x80000000;
      local_58 = 0x43300000;
      dVar14 = (double)FUN_80294204((double)((FLOAT_803e2454 *
                                             (float)((double)CONCAT44(0x43300000,uStack84) -
                                                    DOUBLE_803e2460)) / FLOAT_803e2458));
      *(float *)(iVar10 + 0x30) = (float)-dVar14;
    }
    iVar10 = (int)sVar9;
    if ((*(uint *)(iVar12 + 0x54) & 0x100000) != 0) {
      if (FLOAT_803e23dc == *(float *)(iVar12 + 0x2ac)) {
        bVar3 = false;
      }
      else if (FLOAT_803e2410 == *(float *)(iVar12 + 0x2b0)) {
        bVar3 = true;
      }
      else if (*(float *)(iVar12 + 0x2b4) - *(float *)(iVar12 + 0x2b0) <= FLOAT_803e2414) {
        bVar3 = false;
      }
      else {
        bVar3 = true;
      }
      if (bVar3) {
        FUN_80148bc8(s_Turning_in_water_8031d4a4);
        FUN_8013a3f0((double)FLOAT_803e243c,psVar4,8,0);
        *(float *)(iVar12 + 0x79c) = FLOAT_803e2440;
        *(float *)(iVar12 + 0x838) = FLOAT_803e23dc;
      }
      else {
        FUN_80148bc8(s_Turning_out_of_water_8031d4b8);
        if ((*(uint *)(iVar12 + 0x54) & 0x400000) == 0) {
          if ((*(uint *)(iVar12 + 0x54) & 0x800000) != 0) {
            iVar5 = iVar10;
            if (iVar10 < 0) {
              iVar5 = -iVar10;
            }
            if (iVar5 < 0x3556) {
              if (iVar10 < 0) {
                iVar10 = -iVar10;
              }
              if (iVar10 < 0x2001) {
                unaff_r28 = 10;
              }
              else {
                unaff_r28 = 0xc;
              }
            }
            else {
              unaff_r28 = 0x28;
            }
          }
        }
        else {
          iVar5 = iVar10;
          if (iVar10 < 0) {
            iVar5 = -iVar10;
          }
          if (iVar5 < 0x3556) {
            if (iVar10 < 0) {
              iVar10 = -iVar10;
            }
            if (iVar10 < 0x2001) {
              unaff_r28 = 9;
            }
            else {
              unaff_r28 = 0xb;
            }
          }
          else {
            unaff_r28 = 0x27;
          }
        }
        *psVar4 = sVar7;
        FUN_8013a3f0((double)FLOAT_803e2478,psVar4,unaff_r28,0x1000100);
      }
    }
    *(float *)(iVar12 + 0x14) = FLOAT_803e2420;
    if (((*(uint *)(iVar12 + 0x54) & 0x100000) == 0) && ((*(uint *)(iVar12 + 0x54) & 0x200000) == 0)
       ) {
      uVar6 = 0;
      goto LAB_8013a3c8;
    }
  }
  else {
    iVar10 = *(int *)(psVar4 + 0x5c);
    dVar15 = (double)*(float *)(iVar10 + 0x2c);
    dVar14 = (double)*(float *)(iVar10 + 0x30);
    if (FLOAT_803e23ec < (float)(dVar15 * dVar15) + (float)(dVar14 * dVar14)) {
      sVar7 = FUN_800217c0(-dVar15,-dVar14);
      FUN_80139930(psVar4,(int)sVar7);
      uStack84 = (int)*psVar4 ^ 0x80000000;
      local_58 = 0x43300000;
      dVar14 = (double)FUN_80293e80((double)((FLOAT_803e2454 *
                                             (float)((double)CONCAT44(0x43300000,uStack84) -
                                                    DOUBLE_803e2460)) / FLOAT_803e2458));
      *(float *)(iVar10 + 0x2c) = (float)-dVar14;
      uStack76 = (int)*psVar4 ^ 0x80000000;
      local_50 = 0x43300000;
      dVar14 = (double)FUN_80294204((double)((FLOAT_803e2454 *
                                             (float)((double)CONCAT44(0x43300000,uStack76) -
                                                    DOUBLE_803e2460)) / FLOAT_803e2458));
      *(float *)(iVar10 + 0x30) = (float)-dVar14;
    }
    if (FLOAT_803e23dc == *(float *)(iVar12 + 0x2ac)) {
      bVar3 = false;
    }
    else if (FLOAT_803e2410 == *(float *)(iVar12 + 0x2b0)) {
      bVar3 = true;
    }
    else if (*(float *)(iVar12 + 0x2b4) - *(float *)(iVar12 + 0x2b0) <= FLOAT_803e2414) {
      bVar3 = false;
    }
    else {
      bVar3 = true;
    }
    if (bVar3) {
      FUN_8013a3f0((double)FLOAT_803e2468,psVar4,7,0x2000000);
      *(float *)(iVar12 + 0x79c) = FLOAT_803e2440;
      *(float *)(iVar12 + 0x838) = FLOAT_803e23dc;
      FUN_80148bc8(s_in_water_8031d46c);
    }
    else {
      if (*(char *)(iVar12 + 8) == '\x01') {
        iVar10 = *(int *)(psVar4 + 0x5c);
        pfVar11 = *(float **)(iVar10 + 0x28);
        fVar1 = FLOAT_803e23dc;
        if (pfVar11 == *(float **)(iVar10 + 0x6f0)) {
          fVar1 = *(float *)(iVar10 + 0x6f4) - *(float *)(psVar4 + 0xc);
          fVar2 = *(float *)(iVar10 + 0x6fc) - *(float *)(psVar4 + 0x10);
          dVar14 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
          dVar15 = (double)(float)((double)FLOAT_803db418 * dVar14);
          dVar14 = (double)FUN_802931a0((double)((*pfVar11 - *(float *)(psVar4 + 0xc)) *
                                                 (*pfVar11 - *(float *)(psVar4 + 0xc)) +
                                                (pfVar11[2] - *(float *)(psVar4 + 0x10)) *
                                                (pfVar11[2] - *(float *)(psVar4 + 0x10))));
          fVar1 = (float)((double)(float)((double)FLOAT_803db418 * dVar14) - dVar15);
        }
        if (fVar1 < FLOAT_803e23dc) {
          iVar10 = *(int *)(psVar4 + 0x5c);
          pfVar11 = *(float **)(iVar10 + 0x28);
          fVar1 = FLOAT_803e23dc;
          if (pfVar11 == *(float **)(iVar10 + 0x6f0)) {
            fVar1 = *(float *)(iVar10 + 0x6f4) - *(float *)(psVar4 + 0xc);
            fVar2 = *(float *)(iVar10 + 0x6fc) - *(float *)(psVar4 + 0x10);
            dVar14 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
            dVar15 = (double)(float)((double)FLOAT_803db418 * dVar14);
            dVar14 = (double)FUN_802931a0((double)((*pfVar11 - *(float *)(psVar4 + 0xc)) *
                                                   (*pfVar11 - *(float *)(psVar4 + 0xc)) +
                                                  (pfVar11[2] - *(float *)(psVar4 + 0x10)) *
                                                  (pfVar11[2] - *(float *)(psVar4 + 0x10))));
            fVar1 = (float)((double)(float)((double)FLOAT_803db418 * dVar14) - dVar15);
          }
          fVar1 = -fVar1;
        }
        else {
          iVar10 = *(int *)(psVar4 + 0x5c);
          pfVar11 = *(float **)(iVar10 + 0x28);
          fVar1 = FLOAT_803e23dc;
          if (pfVar11 == *(float **)(iVar10 + 0x6f0)) {
            fVar1 = *(float *)(iVar10 + 0x6f4) - *(float *)(psVar4 + 0xc);
            fVar2 = *(float *)(iVar10 + 0x6fc) - *(float *)(psVar4 + 0x10);
            dVar14 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
            dVar15 = (double)(float)((double)FLOAT_803db418 * dVar14);
            dVar14 = (double)FUN_802931a0((double)((*pfVar11 - *(float *)(psVar4 + 0xc)) *
                                                   (*pfVar11 - *(float *)(psVar4 + 0xc)) +
                                                  (pfVar11[2] - *(float *)(psVar4 + 0x10)) *
                                                  (pfVar11[2] - *(float *)(psVar4 + 0x10))));
            fVar1 = (float)((double)(float)((double)FLOAT_803db418 * dVar14) - dVar15);
          }
        }
        fVar2 = FLOAT_803e23dc;
        if ((FLOAT_803e23dc < fVar1) &&
           (*(float *)(iVar12 + 0x7a4) = *(float *)(iVar12 + 0x7a4) - FLOAT_803db414,
           *(float *)(iVar12 + 0x7a4) <= fVar2)) {
          uStack76 = FUN_800221a0(600,0x4b0);
          uStack76 = uStack76 ^ 0x80000000;
          local_50 = 0x43300000;
          *(float *)(iVar12 + 0x7a4) =
               (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e2460);
          iVar10 = FUN_8000b578(psVar4,0x10);
          if (iVar10 == 0) {
            if (dVar16 <= (double)FLOAT_803e23e8) {
              local_78 = DAT_803e23d4;
              local_74 = DAT_803e23d8;
              iVar10 = FUN_8001ffb4(0x25);
              if (iVar10 == 0) {
                FUN_800221a0(0,1);
              }
              else {
                FUN_800221a0(0,2);
              }
              iVar10 = FUN_800221a0(0,2);
              uVar8 = *(undefined2 *)((int)&local_78 + iVar10 * 2);
              iVar10 = *(int *)(psVar4 + 0x5c);
              if (((*(byte *)(iVar10 + 0x58) >> 6 & 1) == 0) &&
                 (((0x2f < psVar4[0x50] || (psVar4[0x50] < 0x29)) &&
                  (iVar5 = FUN_8000b578(psVar4,0x10), iVar5 == 0)))) {
                FUN_800393f8(psVar4,iVar10 + 0x3a8,uVar8,0x500,0xffffffff,0);
              }
            }
            else {
              uVar8 = FUN_800221a0(0x34d,0x34e);
              iVar10 = *(int *)(psVar4 + 0x5c);
              if ((((*(byte *)(iVar10 + 0x58) >> 6 & 1) == 0) &&
                  ((0x2f < psVar4[0x50] || (psVar4[0x50] < 0x29)))) &&
                 (iVar5 = FUN_8000b578(psVar4,0x10), iVar5 == 0)) {
                FUN_800393f8(psVar4,iVar10 + 0x3a8,uVar8,0x500,0xffffffff,0);
              }
            }
          }
        }
      }
      if (dVar16 <= (double)FLOAT_803e246c) {
        if (dVar16 <= (double)FLOAT_803e23e8) {
          if (dVar16 <= (double)FLOAT_803e2470) {
            if (dVar16 <= (double)FLOAT_803e2474) {
              FUN_8013a3f0((double)FLOAT_803e2468,psVar4,1,0x3000000);
            }
            else {
              FUN_8013a3f0((double)FLOAT_803e2468,psVar4,2,0x3000000);
            }
          }
          else {
            FUN_8013a3f0((double)FLOAT_803e2468,psVar4,4,0x3000000);
          }
        }
        else {
          FUN_8013a3f0((double)FLOAT_803e2468,psVar4,5,0x3000000);
        }
      }
      else {
        *(float *)(iVar12 + 0x7a0) = FLOAT_803e2440;
        FUN_8013a3f0((double)FLOAT_803e2468,psVar4,0x30,0x3000000);
      }
      FUN_80148bc8(s_moveTricky__out_of_water_8031d488);
    }
  }
  uVar6 = 1;
LAB_8013a3c8:
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  __psq_l0(auStack24,uVar13);
  __psq_l1(auStack24,uVar13);
  FUN_80286120(uVar6);
  return;
}

