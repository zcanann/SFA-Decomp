// Function: FUN_80103ddc
// Entry: 80103ddc
// Size: 1280 bytes

/* WARNING: Removing unreachable block (ram,0x801042bc) */
/* WARNING: Removing unreachable block (ram,0x801042b4) */
/* WARNING: Removing unreachable block (ram,0x801042ac) */
/* WARNING: Removing unreachable block (ram,0x801042a4) */
/* WARNING: Removing unreachable block (ram,0x80103e04) */
/* WARNING: Removing unreachable block (ram,0x80103dfc) */
/* WARNING: Removing unreachable block (ram,0x80103df4) */
/* WARNING: Removing unreachable block (ram,0x80103dec) */

void FUN_80103ddc(void)

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
  float *pfVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  short sVar13;
  double dVar14;
  double dVar15;
  double in_f28;
  double in_f29;
  double dVar16;
  double in_f30;
  double dVar17;
  double in_f31;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_2f8;
  undefined auStack_2f4 [4];
  float local_2f0;
  undefined auStack_2ec [4];
  float local_2e8;
  float local_2e4;
  undefined4 local_2e0;
  float local_2dc [21];
  float local_288 [21];
  undefined auStack_234 [136];
  float local_1ac;
  float local_1a8;
  float local_1a4;
  int local_120;
  undefined4 local_80;
  uint uStack_7c;
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
  psVar3 = (short *)FUN_8028681c();
  FUN_802473cc();
  (**(code **)(*DAT_803dd6d0 + 0x38))
            ((double)*(float *)(DAT_803de1a8 + 0x8c),psVar3,&local_2f0,auStack_2f4,&local_2f8,
             auStack_2ec,0);
  local_120 = *(int *)(psVar3 + 0x52);
  local_2dc[1] = *(float *)(psVar3 + 0xe);
  local_2dc[0] = *(float *)(psVar3 + 0xc);
  local_2dc[2] = *(float *)(psVar3 + 0x10);
  local_288[0] = local_2dc[0];
  local_288[1] = local_2dc[1];
  local_288[2] = local_2dc[2];
  local_1a8 = local_2dc[1];
  if (*(short *)(local_120 + 0x44) == 1) {
    FUN_80297334(local_120,&local_2e8,&local_2e4,&local_2e0);
  }
  else {
    local_2e8 = *(float *)(local_120 + 0x18);
    local_2e4 = *(float *)(local_120 + 0x1c) + *(float *)(DAT_803de1a8 + 0x8c);
    local_2e0 = *(undefined4 *)(local_120 + 0x20);
  }
  iVar7 = 0;
  iVar6 = -1;
  iVar5 = -1;
  sVar13 = 0xaaa;
  pfVar10 = local_288;
  pfVar9 = local_2dc;
  pfVar11 = pfVar9;
  pfVar12 = pfVar10;
  for (sVar8 = 0xf; sVar8 < 0x5b; sVar8 = sVar8 + 0xf) {
    if (iVar6 == -1) {
      dVar16 = (double)local_2f8;
      dVar17 = (double)local_2f0;
      iVar4 = *(int *)(psVar3 + 0x52);
      uStack_7c = (int)sVar13 ^ 0x80000000;
      local_80 = 0x43300000;
      dVar14 = (double)FUN_802945e0();
      dVar15 = (double)FUN_80294964();
      dVar17 = (double)(float)(dVar17 * dVar15 - (double)(float)(dVar16 * dVar14));
      local_1ac = (float)(dVar17 + (double)*(float *)(iVar4 + 0x18));
      fVar1 = (float)(dVar17 * dVar14 + (double)(float)(dVar16 * dVar15)) + *(float *)(iVar4 + 0x20)
      ;
      local_1a4 = fVar1;
      pfVar12[3] = local_1ac;
      pfVar12[4] = local_1a8;
      pfVar12[5] = fVar1;
      iVar4 = FUN_801037c0((double)FLOAT_803e2320,&local_2e8,&local_1ac,(float *)0x0,
                           (int)auStack_234,7,'\0','\0');
      if (iVar4 != 0) {
        iVar6 = iVar7;
      }
    }
    if (iVar5 == -1) {
      dVar16 = (double)local_2f8;
      dVar17 = (double)local_2f0;
      iVar4 = *(int *)(psVar3 + 0x52);
      uStack_7c = (int)(short)(sVar8 * -0xb6) ^ 0x80000000;
      local_80 = 0x43300000;
      dVar14 = (double)FUN_802945e0();
      dVar15 = (double)FUN_80294964();
      dVar17 = (double)(float)(dVar17 * dVar15 - (double)(float)(dVar16 * dVar14));
      local_1ac = (float)(dVar17 + (double)*(float *)(iVar4 + 0x18));
      fVar1 = (float)(dVar17 * dVar14 + (double)(float)(dVar16 * dVar15)) + *(float *)(iVar4 + 0x20)
      ;
      local_1a4 = fVar1;
      pfVar11[3] = local_1ac;
      pfVar11[4] = local_1a8;
      pfVar11[5] = fVar1;
      iVar4 = FUN_801037c0((double)FLOAT_803e2320,&local_2e8,&local_1ac,(float *)0x0,
                           (int)auStack_234,7,'\0','\0');
      if (iVar4 != 0) {
        iVar5 = iVar7;
      }
    }
    pfVar12 = pfVar12 + 3;
    pfVar11 = pfVar11 + 3;
    iVar7 = iVar7 + 1;
    sVar13 = sVar13 + 0xaaa;
  }
  if (iVar6 == -1) {
    iVar6 = 6;
  }
  else {
    for (iVar7 = 0; iVar7 <= iVar6; iVar7 = iVar7 + 1) {
      iVar4 = FUN_801037c0((double)FLOAT_803e2320,pfVar10,local_288 + (iVar7 + 1) * 3,(float *)0x0,
                           (int)auStack_234,7,'\0','\0');
      if (iVar4 == 0) {
        iVar6 = 6;
        break;
      }
      pfVar10 = pfVar10 + 3;
    }
  }
  if (iVar5 == -1) {
    iVar5 = 6;
  }
  else {
    for (iVar7 = 0; iVar7 <= iVar5; iVar7 = iVar7 + 1) {
      iVar4 = FUN_801037c0((double)FLOAT_803e2320,pfVar9,local_2dc + (iVar7 + 1) * 3,(float *)0x0,
                           (int)auStack_234,7,'\0','\0');
      if (iVar4 == 0) {
        iVar5 = 6;
        break;
      }
      pfVar9 = pfVar9 + 3;
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
    uStack_7c = (0x8000 - *psVar3) - (in_r6 & 0xffff);
    if (0x8000 < (int)uStack_7c) {
      uStack_7c = uStack_7c - 0xffff;
    }
    if ((int)uStack_7c < -0x8000) {
      uStack_7c = uStack_7c + 0xffff;
    }
    if ((int)uStack_7c < 0) {
      uStack_7c = -uStack_7c;
    }
    fVar1 = *(float *)(psVar3 + 0x62) * *(float *)(psVar3 + 0x62);
    if (fVar1 < FLOAT_803e2324) {
      fVar1 = FLOAT_803e2324;
    }
    uStack_7c = uStack_7c ^ 0x80000000;
    local_80 = 0x43300000;
    fVar1 = FLOAT_803e232c + fVar1 * FLOAT_803e2328 +
            (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e2318) / FLOAT_803e2330;
    if (fVar1 < FLOAT_803e2334) {
      fVar1 = FLOAT_803e2334;
    }
    if (FLOAT_803e2338 < fVar1) {
      fVar1 = FLOAT_803e2338;
    }
    if (iVar7 == -1) {
      fVar1 = -fVar1;
    }
    fVar1 = fVar1 * FLOAT_803de1a4 + *(float *)(DAT_803de1a8 + 0x28);
    fVar2 = FLOAT_803e233c;
    if ((fVar1 <= FLOAT_803e233c) && (fVar2 = fVar1, fVar1 < FLOAT_803e2340)) {
      fVar2 = FLOAT_803e2340;
    }
    *(float *)(DAT_803de1a8 + 0x28) = fVar2;
  }
  FUN_80286868();
  return;
}

