// Function: FUN_802474e8
// Entry: 802474e8
// Size: 140 bytes

/* WARNING: Removing unreachable block (ram,0x8024756c) */
/* WARNING: Removing unreachable block (ram,0x80247568) */
/* WARNING: Removing unreachable block (ram,0x80247554) */
/* WARNING: Removing unreachable block (ram,0x80247534) */
/* WARNING: Removing unreachable block (ram,0x8024753c) */
/* WARNING: Removing unreachable block (ram,0x80247520) */
/* WARNING: Removing unreachable block (ram,0x8024751c) */
/* WARNING: Removing unreachable block (ram,0x8024750c) */
/* WARNING: Removing unreachable block (ram,0x802474f4) */
/* WARNING: Removing unreachable block (ram,0x802474e8) */
/* WARNING: Removing unreachable block (ram,0x802474ec) */
/* WARNING: Removing unreachable block (ram,0x80247500) */
/* WARNING: Removing unreachable block (ram,0x80247514) */
/* WARNING: Removing unreachable block (ram,0x8024754c) */

void FUN_802474e8(int param_1,int param_2,int param_3,int param_4)

{
  float fVar1;
  float fVar2;
  float *pfVar3;
  float *pfVar4;
  float *pfVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  float fVar20;
  float fVar21;
  float fVar22;
  float fVar23;
  float fVar24;
  
  fVar23 = (float)__psq_l0(param_1,0);
  fVar24 = (float)__psq_l1(param_1,0);
  fVar21 = (float)__psq_l0(param_1 + 0x10,0);
  fVar22 = (float)__psq_l1(param_1 + 0x10,0);
  param_4 = param_4 + -1;
  fVar19 = (float)__psq_l0(param_1 + 8,0);
  fVar20 = (float)__psq_l1(param_1 + 8,0);
  fVar17 = (float)__psq_l0(param_1 + 0x18,0);
  fVar18 = (float)__psq_l1(param_1 + 0x18,0);
  fVar6 = (float)__psq_l0(param_1 + 0x20,0);
  fVar7 = (float)__psq_l1(param_1 + 0x20,0);
  fVar8 = (float)__psq_l0(param_1 + 0x28,0);
  fVar9 = (float)__psq_l1(param_1 + 0x28,0);
  fVar10 = (float)__psq_l0(param_2,0);
  fVar12 = (float)__psq_l1(param_2,0);
  pfVar4 = (float *)(param_2 + 8);
  fVar14 = *pfVar4;
  fVar15 = fVar24 * fVar12 + fVar23 * fVar10 + fVar20;
  fVar16 = fVar22 * fVar12 + fVar21 * fVar10 + fVar18;
  fVar10 = fVar8 * fVar14 + fVar6 * fVar10;
  fVar12 = fVar9 * 1.0 + fVar7 * fVar12;
  pfVar3 = (float *)(param_3 + -4);
  do {
    pfVar5 = pfVar3;
    fVar11 = pfVar4[1];
    fVar13 = pfVar4[2];
    fVar1 = fVar19 * fVar14;
    fVar2 = fVar17 * fVar14;
    pfVar4 = pfVar4 + 3;
    fVar14 = *pfVar4;
    pfVar5[1] = fVar1 + fVar15;
    pfVar5[2] = fVar2 + fVar16;
    fVar15 = fVar24 * fVar13 + fVar23 * fVar11 + fVar20;
    fVar16 = fVar22 * fVar13 + fVar21 * fVar11 + fVar18;
    pfVar5[3] = fVar10 + fVar12;
    fVar10 = fVar8 * fVar14 + fVar6 * fVar11;
    fVar12 = fVar9 * 1.0 + fVar7 * fVar13;
    param_4 = param_4 + -1;
    pfVar3 = pfVar5 + 3;
  } while (param_4 != 0);
  pfVar5[4] = fVar19 * fVar14 + fVar15;
  pfVar5[5] = fVar17 * fVar14 + fVar16;
  pfVar5[6] = fVar10 + fVar12;
  return;
}

