// Function: FUN_800e2278
// Entry: 800e2278
// Size: 536 bytes

/* WARNING: Removing unreachable block (ram,0x800e2478) */
/* WARNING: Removing unreachable block (ram,0x800e2470) */
/* WARNING: Removing unreachable block (ram,0x800e2468) */
/* WARNING: Removing unreachable block (ram,0x800e2298) */
/* WARNING: Removing unreachable block (ram,0x800e2290) */
/* WARNING: Removing unreachable block (ram,0x800e2288) */

void FUN_800e2278(undefined8 param_1,double param_2,double param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  float *pfVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  uint uVar12;
  double extraout_f1;
  double dVar13;
  double dVar14;
  longlong lVar15;
  
  lVar15 = FUN_8028683c();
  uVar4 = (uint)((ulonglong)lVar15 >> 0x20);
  pfVar5 = (float *)lVar15;
  if (lVar15 < 0) {
    iVar9 = 0;
  }
  else {
    iVar7 = DAT_803de0f0 + -1;
    iVar11 = 0;
    while (iVar11 <= iVar7) {
      iVar8 = iVar7 + iVar11 >> 1;
      iVar9 = (&DAT_803a2448)[iVar8];
      if (*(uint *)(iVar9 + 0x14) < uVar4) {
        iVar11 = iVar8 + 1;
      }
      else {
        if (*(uint *)(iVar9 + 0x14) <= uVar4) goto LAB_800e2324;
        iVar7 = iVar8 + -1;
      }
    }
    iVar9 = 0;
  }
LAB_800e2324:
  *pfVar5 = FLOAT_803e12dc;
  uVar10 = uVar4;
  dVar14 = extraout_f1;
  do {
    uVar12 = 0xffffffff;
    iVar7 = 0;
    iVar11 = iVar9;
    while ((iVar7 < 4 && (uVar12 == 0xffffffff))) {
      if (((int)*(char *)(iVar9 + 0x1b) & 1 << iVar7) == 0) {
        uVar12 = *(uint *)(iVar11 + 0x1c);
      }
      iVar11 = iVar11 + 4;
      iVar7 = iVar7 + 1;
    }
    iVar11 = iVar9;
    if (uVar12 != 0xffffffff) {
      if ((int)uVar12 < 0) {
        iVar11 = 0;
      }
      else {
        iVar8 = DAT_803de0f0 + -1;
        iVar7 = 0;
        while (iVar7 <= iVar8) {
          iVar6 = iVar8 + iVar7 >> 1;
          iVar11 = (&DAT_803a2448)[iVar6];
          if (*(uint *)(iVar11 + 0x14) < uVar12) {
            iVar7 = iVar6 + 1;
          }
          else {
            if (*(uint *)(iVar11 + 0x14) <= uVar12) goto LAB_800e23ec;
            iVar8 = iVar6 + -1;
          }
        }
        iVar11 = 0;
      }
LAB_800e23ec:
      iVar7 = FUN_800e21c0(dVar14,param_2,param_3,iVar9,iVar11);
      uVar10 = uVar12;
      if ((iVar7 != 0) &&
         (fVar1 = (float)((double)*(float *)(iVar9 + 8) - dVar14),
         fVar2 = (float)((double)*(float *)(iVar9 + 0xc) - param_2),
         fVar3 = (float)((double)*(float *)(iVar9 + 0x10) - param_3),
         dVar13 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2)),
         dVar13 < (double)*pfVar5)) {
        *pfVar5 = (float)dVar13;
      }
    }
    if ((uVar10 == uVar4) || (iVar9 = iVar11, uVar12 == 0xffffffff)) {
      FUN_80286888();
      return;
    }
  } while( true );
}

