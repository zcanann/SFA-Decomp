// Function: FUN_801c11ac
// Entry: 801c11ac
// Size: 616 bytes

/* WARNING: Removing unreachable block (ram,0x801c13f4) */
/* WARNING: Removing unreachable block (ram,0x801c13ec) */
/* WARNING: Removing unreachable block (ram,0x801c13e4) */
/* WARNING: Removing unreachable block (ram,0x801c11cc) */
/* WARNING: Removing unreachable block (ram,0x801c11c4) */
/* WARNING: Removing unreachable block (ram,0x801c11bc) */

void FUN_801c11ac(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4,short *param_5
                 )

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  short sVar7;
  short sVar8;
  short sVar9;
  short sVar10;
  short sVar11;
  short sVar12;
  uint uVar13;
  int iVar14;
  short *psVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  
  uVar13 = FUN_8028682c();
  fVar1 = FLOAT_803e5a78 * *param_3;
  fVar2 = FLOAT_803e5a78 * param_3[1];
  fVar3 = FLOAT_803e5a78 * param_3[2];
  fVar4 = FLOAT_803e5a78 * *param_4;
  fVar5 = FLOAT_803e5a78 * param_4[1];
  fVar6 = FLOAT_803e5a78 * param_4[2];
  FUN_80003494((uint)param_5,uVar13,0x60);
  iVar14 = 0;
  psVar15 = param_5;
  dVar18 = DOUBLE_803e5a88;
  do {
    dVar17 = (double)(float)((double)CONCAT44(0x43300000,(int)*psVar15 ^ 0x80000000) - dVar18);
    dVar16 = (double)FUN_80294964();
    *psVar15 = (short)(int)(dVar17 * dVar16);
    dVar16 = (double)FUN_802945e0();
    psVar15[2] = (short)(int)(-dVar17 * dVar16);
    psVar15 = psVar15 + 8;
    iVar14 = iVar14 + 1;
  } while (iVar14 < 6);
  sVar7 = (short)(int)fVar1;
  *param_5 = *param_5 + sVar7;
  sVar8 = (short)(int)fVar2;
  param_5[1] = param_5[1] + sVar8;
  sVar9 = (short)(int)fVar3;
  param_5[2] = param_5[2] + sVar9;
  sVar10 = (short)(int)fVar4;
  param_5[0x18] = param_5[0x18] + sVar10;
  sVar11 = (short)(int)fVar5;
  param_5[0x19] = param_5[0x19] + sVar11;
  sVar12 = (short)(int)fVar6;
  param_5[0x1a] = param_5[0x1a] + sVar12;
  param_5[8] = param_5[8] + sVar7;
  param_5[9] = param_5[9] + sVar8;
  param_5[10] = param_5[10] + sVar9;
  param_5[0x20] = param_5[0x20] + sVar10;
  param_5[0x21] = param_5[0x21] + sVar11;
  param_5[0x22] = param_5[0x22] + sVar12;
  param_5[0x10] = param_5[0x10] + sVar7;
  param_5[0x11] = param_5[0x11] + sVar8;
  param_5[0x12] = param_5[0x12] + sVar9;
  param_5[0x28] = param_5[0x28] + sVar10;
  param_5[0x29] = param_5[0x29] + sVar11;
  param_5[0x2a] = param_5[0x2a] + sVar12;
  FUN_80286878();
  return;
}

