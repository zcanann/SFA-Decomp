// Function: FUN_801923f8
// Entry: 801923f8
// Size: 972 bytes

/* WARNING: Removing unreachable block (ram,0x8019279c) */
/* WARNING: Removing unreachable block (ram,0x8019278c) */
/* WARNING: Removing unreachable block (ram,0x80192784) */
/* WARNING: Removing unreachable block (ram,0x80192794) */
/* WARNING: Removing unreachable block (ram,0x801927a4) */

void FUN_801923f8(void)

{
  double dVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  uint *puVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  short sVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  uint uVar14;
  uint uVar15;
  undefined4 uVar16;
  double dVar17;
  undefined8 in_f27;
  double dVar18;
  undefined8 in_f28;
  double dVar19;
  undefined8 in_f29;
  double dVar20;
  undefined8 in_f30;
  double dVar21;
  undefined8 in_f31;
  double dVar22;
  double local_90;
  double local_88;
  double local_80;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar16 = 0;
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
  puVar5 = (uint *)FUN_802860c8();
  DAT_803ddaf4 = FUN_80023cc8(puVar5[7] * puVar5[7] * 4,0xffffff,0);
  DAT_803ddaec = FUN_80023cc8(puVar5[7] * puVar5[7] * 3,0xffffff,0);
  dVar22 = DOUBLE_803e3f68;
  fVar4 = FLOAT_803e3f44;
  uVar15 = *puVar5;
  fVar2 = FLOAT_803e3f40 *
          (float)((double)CONCAT44(0x43300000,puVar5[2] ^ 0x80000000) - DOUBLE_803e3f68);
  dVar1 = (double)CONCAT44(0x43300000,puVar5[7] ^ 0x80000000) - DOUBLE_803e3f68;
  uVar14 = puVar5[1];
  local_90 = (double)CONCAT44(0x43300000,puVar5[3] ^ 0x80000000);
  fVar3 = FLOAT_803e3f40 * (float)(local_90 - DOUBLE_803e3f68);
  local_88 = (double)CONCAT44(0x43300000,puVar5[7] ^ 0x80000000);
  local_88 = local_88 - DOUBLE_803e3f68;
  puVar5[10] = (uint)FLOAT_803e3f44;
  puVar5[9] = (uint)fVar4;
  iVar13 = 0;
  dVar19 = (double)FLOAT_803e3f48;
  dVar20 = (double)FLOAT_803e3f4c;
  for (iVar12 = 0; fVar4 = FLOAT_803e3f44, iVar12 < (int)puVar5[7]; iVar12 = iVar12 + 1) {
    local_80 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000);
    dVar18 = (double)(float)(dVar19 * (double)(float)(local_80 - dVar22));
    iVar8 = iVar13;
    for (iVar11 = 0; iVar11 < (int)puVar5[7]; iVar11 = iVar11 + 1) {
      local_80 = (double)CONCAT44(0x43300000,uVar14 ^ 0x80000000);
      dVar17 = (double)FUN_80293e80((double)(float)((double)(float)(dVar19 * (double)(float)(
                                                  local_80 - dVar22)) / dVar20));
      dVar21 = (double)(float)((double)(float)puVar5[5] * dVar17);
      dVar17 = (double)FUN_80293e80((double)(float)(dVar18 / dVar20));
      *(float *)(DAT_803ddaf4 + iVar8) = (float)((double)(float)puVar5[4] * dVar17 + dVar21);
      if (*(float *)(DAT_803ddaf4 + iVar8) < (float)puVar5[9]) {
        puVar5[9] = (uint)*(float *)(DAT_803ddaf4 + iVar8);
      }
      if ((float)puVar5[10] < *(float *)(DAT_803ddaf4 + iVar8)) {
        puVar5[10] = (uint)*(float *)(DAT_803ddaf4 + iVar8);
      }
      uVar14 = uVar14 + (int)(fVar3 / (float)local_88);
      iVar8 = iVar8 + 4;
      iVar13 = iVar13 + 4;
    }
    uVar15 = uVar15 + (int)(fVar2 / (float)dVar1);
  }
  fVar2 = (float)puVar5[9];
  iVar12 = 0;
  iVar13 = 0;
  for (iVar8 = 0; iVar8 < (int)puVar5[7]; iVar8 = iVar8 + 1) {
    iVar11 = iVar12;
    iVar7 = iVar13;
    for (iVar10 = 0; iVar10 < (int)puVar5[7]; iVar10 = iVar10 + 1) {
      if (fVar4 <= *(float *)(DAT_803ddaf4 + iVar12)) {
        *(undefined *)(DAT_803ddaec + iVar13) = 0xff;
        *(undefined *)(DAT_803ddaec + iVar13 + 1) = 0xff;
        *(undefined *)(DAT_803ddaec + iVar13 + 2) = 0xff;
      }
      else {
        fVar3 = (*(float *)(DAT_803ddaf4 + iVar12) - (float)puVar5[9]) / -fVar2;
        *(char *)(DAT_803ddaec + iVar13) = (char)(int)(FLOAT_803e3f54 * fVar3 + FLOAT_803e3f50);
        *(char *)(DAT_803ddaec + iVar13 + 1) = (char)(int)(FLOAT_803e3f5c * fVar3 + FLOAT_803e3f58);
        *(char *)(DAT_803ddaec + iVar13 + 2) = (char)(int)(FLOAT_803e3f64 * fVar3 + FLOAT_803e3f60);
      }
      iVar12 = iVar12 + 4;
      iVar13 = iVar13 + 3;
      iVar11 = iVar11 + 4;
      iVar7 = iVar7 + 3;
    }
    iVar12 = iVar11;
    iVar13 = iVar7;
  }
  DAT_803ddaf0 = FUN_80023cc8(puVar5[8] * puVar5[8] * 4,0xffffff,0);
  sVar9 = 0;
  iVar12 = 0;
  for (iVar13 = 0; iVar13 < (int)puVar5[8]; iVar13 = iVar13 + 1) {
    sVar6 = 0;
    iVar8 = iVar12;
    for (iVar11 = 0; iVar11 < (int)puVar5[8]; iVar11 = iVar11 + 1) {
      *(short *)(DAT_803ddaf0 + iVar12) = sVar9;
      *(short *)(DAT_803ddaf0 + iVar12 + 2) = sVar6;
      iVar12 = iVar12 + 4;
      iVar8 = iVar8 + 4;
      sVar6 = sVar6 + 10;
    }
    sVar9 = sVar9 + 10;
    iVar12 = iVar8;
  }
  __psq_l0(auStack8,uVar16);
  __psq_l1(auStack8,uVar16);
  __psq_l0(auStack24,uVar16);
  __psq_l1(auStack24,uVar16);
  __psq_l0(auStack40,uVar16);
  __psq_l1(auStack40,uVar16);
  __psq_l0(auStack56,uVar16);
  __psq_l1(auStack56,uVar16);
  __psq_l0(auStack72,uVar16);
  __psq_l1(auStack72,uVar16);
  FUN_80286114();
  return;
}

