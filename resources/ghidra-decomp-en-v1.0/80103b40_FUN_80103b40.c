// Function: FUN_80103b40
// Entry: 80103b40
// Size: 1280 bytes

/* WARNING: Removing unreachable block (ram,0x80104018) */
/* WARNING: Removing unreachable block (ram,0x80104008) */
/* WARNING: Removing unreachable block (ram,0x80104010) */
/* WARNING: Removing unreachable block (ram,0x80104020) */

void FUN_80103b40(void)

{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  uint in_r6;
  int iVar5;
  int iVar6;
  int iVar7;
  short sVar8;
  undefined4 uVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  undefined4 *puVar12;
  undefined4 *puVar13;
  short sVar14;
  undefined4 uVar15;
  double dVar16;
  undefined8 in_f28;
  double dVar17;
  undefined8 in_f29;
  double dVar18;
  undefined8 in_f30;
  double dVar19;
  undefined8 in_f31;
  float local_2f8;
  undefined auStack756 [4];
  float local_2f0;
  undefined auStack748 [4];
  undefined4 local_2e8;
  float local_2e4;
  undefined4 local_2e0;
  undefined4 local_2dc [21];
  undefined4 local_288 [21];
  undefined auStack564 [136];
  float local_1ac;
  undefined4 local_1a8;
  float local_1a4;
  int local_120;
  undefined4 local_80;
  uint uStack124;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  psVar3 = (short *)FUN_802860b8();
  FUN_80246c68();
  uVar9 = 0;
  (**(code **)(*DAT_803dca50 + 0x38))
            ((double)*(float *)(DAT_803dd530 + 0x8c),psVar3,&local_2f0,auStack756,&local_2f8,
             auStack748,0);
  local_120 = *(int *)(psVar3 + 0x52);
  local_2dc[1] = *(undefined4 *)(psVar3 + 0xe);
  local_2dc[0] = *(undefined4 *)(psVar3 + 0xc);
  local_2dc[2] = *(undefined4 *)(psVar3 + 0x10);
  local_288[0] = local_2dc[0];
  local_288[1] = local_2dc[1];
  local_288[2] = local_2dc[2];
  local_1a8 = local_2dc[1];
  if (*(short *)(local_120 + 0x44) == 1) {
    FUN_80296bd4(local_120,&local_2e8,&local_2e4,&local_2e0);
  }
  else {
    local_2e8 = *(undefined4 *)(local_120 + 0x18);
    local_2e4 = *(float *)(local_120 + 0x1c) + *(float *)(DAT_803dd530 + 0x8c);
    local_2e0 = *(undefined4 *)(local_120 + 0x20);
  }
  iVar7 = 0;
  iVar6 = -1;
  iVar5 = -1;
  sVar14 = 0xaaa;
  puVar11 = local_288;
  puVar10 = local_2dc;
  puVar12 = puVar10;
  puVar13 = puVar11;
  for (sVar8 = 0xf; sVar8 < 0x5b; sVar8 = sVar8 + 0xf) {
    if (iVar6 == -1) {
      dVar18 = (double)local_2f8;
      dVar19 = (double)local_2f0;
      iVar4 = *(int *)(psVar3 + 0x52);
      uStack124 = (int)sVar14 ^ 0x80000000;
      local_80 = 0x43300000;
      dVar17 = (double)((FLOAT_803e168c *
                        (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e1698)) /
                       FLOAT_803e1690);
      dVar16 = (double)FUN_80293e80(dVar17);
      dVar17 = (double)FUN_80294204(dVar17);
      dVar19 = (double)(float)(dVar19 * dVar17 - (double)(float)(dVar18 * dVar16));
      local_1ac = (float)(dVar19 + (double)*(float *)(iVar4 + 0x18));
      fVar1 = (float)(dVar19 * dVar16 + (double)(float)(dVar18 * dVar17)) + *(float *)(iVar4 + 0x20)
      ;
      local_1a4 = fVar1;
      puVar13[3] = local_1ac;
      puVar13[4] = local_1a8;
      puVar13[5] = fVar1;
      iVar4 = FUN_80103524((double)FLOAT_803e16a0,&local_2e8,&local_1ac,0,auStack564,7,0,0);
      if (iVar4 != 0) {
        iVar6 = iVar7;
      }
    }
    if (iVar5 == -1) {
      dVar18 = (double)local_2f8;
      dVar19 = (double)local_2f0;
      iVar4 = *(int *)(psVar3 + 0x52);
      uStack124 = (int)(short)(sVar8 * -0xb6) ^ 0x80000000;
      local_80 = 0x43300000;
      dVar17 = (double)((FLOAT_803e168c *
                        (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e1698)) /
                       FLOAT_803e1690);
      dVar16 = (double)FUN_80293e80(dVar17);
      dVar17 = (double)FUN_80294204(dVar17);
      dVar19 = (double)(float)(dVar19 * dVar17 - (double)(float)(dVar18 * dVar16));
      local_1ac = (float)(dVar19 + (double)*(float *)(iVar4 + 0x18));
      fVar1 = (float)(dVar19 * dVar16 + (double)(float)(dVar18 * dVar17)) + *(float *)(iVar4 + 0x20)
      ;
      local_1a4 = fVar1;
      puVar12[3] = local_1ac;
      puVar12[4] = local_1a8;
      puVar12[5] = fVar1;
      iVar4 = FUN_80103524((double)FLOAT_803e16a0,&local_2e8,&local_1ac,0,auStack564,7,0,0);
      if (iVar4 != 0) {
        iVar5 = iVar7;
      }
    }
    puVar13 = puVar13 + 3;
    puVar12 = puVar12 + 3;
    iVar7 = iVar7 + 1;
    sVar14 = sVar14 + 0xaaa;
  }
  if (iVar6 == -1) {
    iVar6 = 6;
  }
  else {
    for (iVar7 = 0; iVar7 <= iVar6; iVar7 = iVar7 + 1) {
      iVar4 = FUN_80103524((double)FLOAT_803e16a0,puVar11,local_288 + (iVar7 + 1) * 3,0,auStack564,7
                           ,0,0);
      if (iVar4 == 0) {
        iVar6 = 6;
        break;
      }
      puVar11 = puVar11 + 3;
    }
  }
  if (iVar5 == -1) {
    iVar5 = 6;
  }
  else {
    for (iVar7 = 0; iVar7 <= iVar5; iVar7 = iVar7 + 1) {
      iVar4 = FUN_80103524((double)FLOAT_803e16a0,puVar10,local_2dc + (iVar7 + 1) * 3,0,auStack564,7
                           ,0,0);
      if (iVar4 == 0) {
        iVar5 = 6;
        break;
      }
      puVar10 = puVar10 + 3;
    }
  }
  iVar7 = 0;
  if (iVar6 < iVar5) {
    iVar7 = 1;
  }
  else if (iVar5 < iVar6) {
    iVar7 = -1;
  }
  else if (iVar6 < 6) {
    iVar7 = 1;
  }
  if (iVar7 != 0) {
    uStack124 = (0x8000 - *psVar3) - (in_r6 & 0xffff);
    if (0x8000 < (int)uStack124) {
      uStack124 = uStack124 - 0xffff;
    }
    if ((int)uStack124 < -0x8000) {
      uStack124 = uStack124 + 0xffff;
    }
    if ((int)uStack124 < 0) {
      uStack124 = -uStack124;
    }
    fVar1 = *(float *)(psVar3 + 0x62) * *(float *)(psVar3 + 0x62);
    if (fVar1 < FLOAT_803e16a4) {
      fVar1 = FLOAT_803e16a4;
    }
    uStack124 = uStack124 ^ 0x80000000;
    local_80 = 0x43300000;
    fVar1 = FLOAT_803e16ac + fVar1 * FLOAT_803e16a8 +
            (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e1698) / FLOAT_803e16b0;
    if (fVar1 < FLOAT_803e16b4) {
      fVar1 = FLOAT_803e16b4;
    }
    if (FLOAT_803e16b8 < fVar1) {
      fVar1 = FLOAT_803e16b8;
    }
    if (iVar7 == -1) {
      fVar1 = -fVar1;
    }
    fVar1 = fVar1 * FLOAT_803dd52c + *(float *)(DAT_803dd530 + 0x28);
    fVar2 = FLOAT_803e16bc;
    if ((fVar1 <= FLOAT_803e16bc) && (fVar2 = fVar1, fVar1 < FLOAT_803e16c0)) {
      fVar2 = FLOAT_803e16c0;
    }
    *(float *)(DAT_803dd530 + 0x28) = fVar2;
    uVar9 = 1;
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  __psq_l0(auStack40,uVar15);
  __psq_l1(auStack40,uVar15);
  __psq_l0(auStack56,uVar15);
  __psq_l1(auStack56,uVar15);
  FUN_80286104(uVar9);
  return;
}

