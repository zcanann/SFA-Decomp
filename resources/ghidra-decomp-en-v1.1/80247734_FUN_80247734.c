// Function: FUN_80247734
// Entry: 80247734
// Size: 248 bytes

/* WARNING: Removing unreachable block (ram,0x80247824) */
/* WARNING: Removing unreachable block (ram,0x80247818) */
/* WARNING: Removing unreachable block (ram,0x80247810) */
/* WARNING: Removing unreachable block (ram,0x80247808) */
/* WARNING: Removing unreachable block (ram,0x802477fc) */
/* WARNING: Removing unreachable block (ram,0x802477f4) */
/* WARNING: Removing unreachable block (ram,0x802477e8) */
/* WARNING: Removing unreachable block (ram,0x802477e0) */
/* WARNING: Removing unreachable block (ram,0x80247750) */
/* WARNING: Removing unreachable block (ram,0x80247748) */
/* WARNING: Removing unreachable block (ram,0x80247744) */
/* WARNING: Removing unreachable block (ram,0x8024773c) */
/* WARNING: Removing unreachable block (ram,0x80247738) */
/* WARNING: Removing unreachable block (ram,0x80247734) */

undefined4 FUN_80247734(float *param_1,float *param_2)

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
  
  fVar3 = *param_1;
  fVar4 = param_1[1];
  fVar9 = param_1[2];
  fVar5 = param_1[4];
  fVar6 = param_1[5];
  fVar10 = param_1[6];
  fVar7 = param_1[8];
  fVar8 = param_1[9];
  fVar11 = param_1[10];
  fVar14 = fVar4 * fVar10 - fVar6 * fVar9;
  fVar15 = fVar6 * fVar11 - fVar8 * fVar10;
  fVar13 = fVar8 * fVar9 - fVar4 * fVar11;
  fVar1 = fVar7 * fVar14 + fVar5 * fVar13 + fVar3 * fVar15;
  if (fVar1 != fVar9 - fVar9) {
    fVar2 = 1.0 / fVar1;
    fVar17 = -(fVar1 * fVar2 * fVar2 - (fVar2 + fVar2));
    fVar1 = param_1[3];
    fVar15 = fVar15 * fVar17;
    fVar16 = (fVar10 * fVar7 - fVar11 * fVar5) * fVar17;
    fVar2 = param_1[7];
    fVar13 = fVar13 * fVar17;
    fVar12 = (fVar11 * fVar3 - fVar9 * fVar7) * fVar17;
    fVar11 = param_1[0xb];
    fVar14 = fVar14 * fVar17;
    fVar10 = (fVar9 * fVar5 - fVar10 * fVar3) * fVar17;
    fVar9 = (fVar5 * fVar8 - fVar6 * fVar7) * fVar17;
    fVar7 = (fVar4 * fVar7 - fVar3 * fVar8) * fVar17;
    *param_2 = fVar15;
    param_2[1] = fVar13;
    param_2[4] = fVar16;
    param_2[5] = fVar12;
    fVar17 = (fVar3 * fVar6 - fVar4 * fVar5) * fVar17;
    param_2[8] = fVar9;
    param_2[9] = fVar7;
    param_2[10] = fVar17;
    param_2[2] = fVar14;
    param_2[3] = -(fVar14 * fVar11 + fVar13 * fVar2 + fVar15 * fVar1);
    param_2[6] = fVar10;
    param_2[7] = -(fVar10 * fVar11 + fVar12 * fVar2 + fVar16 * fVar1);
    param_2[0xb] = -(fVar17 * fVar11 + fVar7 * fVar2 + fVar9 * fVar1);
    return 1;
  }
  return 0;
}

