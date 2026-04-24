// Function: FUN_80247c4c
// Entry: 80247c4c
// Size: 140 bytes

/* WARNING: Removing unreachable block (ram,0x80247cd0) */
/* WARNING: Removing unreachable block (ram,0x80247ccc) */
/* WARNING: Removing unreachable block (ram,0x80247c98) */
/* WARNING: Removing unreachable block (ram,0x80247cb8) */
/* WARNING: Removing unreachable block (ram,0x80247ca0) */
/* WARNING: Removing unreachable block (ram,0x80247cb0) */
/* WARNING: Removing unreachable block (ram,0x80247c84) */
/* WARNING: Removing unreachable block (ram,0x80247c80) */
/* WARNING: Removing unreachable block (ram,0x80247c78) */
/* WARNING: Removing unreachable block (ram,0x80247c70) */
/* WARNING: Removing unreachable block (ram,0x80247c64) */
/* WARNING: Removing unreachable block (ram,0x80247c58) */
/* WARNING: Removing unreachable block (ram,0x80247c50) */
/* WARNING: Removing unreachable block (ram,0x80247c4c) */

void FUN_80247c4c(float *param_1,float *param_2,int param_3,int param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
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
  float *pfVar22;
  float *pfVar23;
  float *pfVar24;
  int iVar25;
  
  fVar1 = *param_1;
  fVar10 = param_1[1];
  fVar2 = param_1[4];
  fVar11 = param_1[5];
  iVar25 = param_4 + -1;
  fVar3 = param_1[2];
  fVar12 = param_1[3];
  fVar4 = param_1[6];
  fVar13 = param_1[7];
  fVar5 = param_1[8];
  fVar14 = param_1[9];
  fVar6 = param_1[10];
  fVar15 = param_1[0xb];
  fVar7 = *param_2;
  fVar16 = param_2[1];
  pfVar23 = param_2 + 2;
  fVar8 = *pfVar23;
  fVar18 = fVar10 * fVar16 + fVar1 * fVar7 + fVar12;
  fVar19 = fVar11 * fVar16 + fVar2 * fVar7 + fVar13;
  fVar7 = fVar6 * fVar8 + fVar5 * fVar7;
  fVar16 = fVar15 * 1.0 + fVar14 * fVar16;
  pfVar22 = (float *)(param_3 + -4);
  do {
    pfVar24 = pfVar22;
    fVar9 = pfVar23[1];
    fVar17 = pfVar23[2];
    fVar21 = fVar3 * fVar8;
    fVar20 = fVar4 * fVar8;
    pfVar23 = pfVar23 + 3;
    fVar8 = *pfVar23;
    pfVar24[1] = fVar21 + fVar18;
    pfVar24[2] = fVar20 + fVar19;
    fVar18 = fVar10 * fVar17 + fVar1 * fVar9 + fVar12;
    fVar19 = fVar11 * fVar17 + fVar2 * fVar9 + fVar13;
    pfVar24[3] = fVar7 + fVar16;
    fVar7 = fVar6 * fVar8 + fVar5 * fVar9;
    fVar16 = fVar15 * 1.0 + fVar14 * fVar17;
    iVar25 = iVar25 + -1;
    pfVar22 = pfVar24 + 3;
  } while (iVar25 != 0);
  pfVar24[4] = fVar3 * fVar8 + fVar18;
  pfVar24[5] = fVar4 * fVar8 + fVar19;
  pfVar24[6] = fVar7 + fVar16;
  return;
}

