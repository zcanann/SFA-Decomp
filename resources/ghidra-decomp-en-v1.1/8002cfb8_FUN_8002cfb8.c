// Function: FUN_8002cfb8
// Entry: 8002cfb8
// Size: 600 bytes

/* WARNING: Removing unreachable block (ram,0x8002d1f0) */
/* WARNING: Removing unreachable block (ram,0x8002d1e8) */
/* WARNING: Removing unreachable block (ram,0x8002d1e0) */
/* WARNING: Removing unreachable block (ram,0x8002cfd8) */
/* WARNING: Removing unreachable block (ram,0x8002cfd0) */
/* WARNING: Removing unreachable block (ram,0x8002cfc8) */

void FUN_8002cfb8(void)

{
  char cVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  char *pcVar6;
  int iVar7;
  float *pfVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  float *pfVar12;
  int iVar13;
  int iVar14;
  double extraout_f1;
  double dVar15;
  double in_f29;
  double dVar16;
  double in_f30;
  double dVar17;
  double in_f31;
  double dVar18;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_2b8 [164];
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
  piVar5 = (int *)FUN_8028682c();
  iVar11 = *piVar5;
  uVar4 = countLeadingZeros((uint)*(ushort *)(iVar11 + 2));
  if (((((uVar4 >> 5 & 0x1000) == 0) && (*(char *)(iVar11 + 0xf3) != '\0')) &&
      (pfVar8 = *(float **)(iVar11 + 0x18), pfVar8 != (float *)0x0)) &&
     (iVar10 = piVar5[5], iVar10 != 0)) {
    **(float **)(iVar10 + 4) = (float)((double)*pfVar8 * extraout_f1);
    if (**(float **)(iVar10 + 4) == FLOAT_803df50c) {
      **(float **)(iVar10 + 4) = (float)((double)pfVar8[1] * extraout_f1);
    }
    **(float **)(iVar10 + 8) = **(float **)(iVar10 + 4) * **(float **)(iVar10 + 4);
    **(float **)(iVar10 + 0xc) = FLOAT_803df554;
    **(undefined4 **)(iVar10 + 0x10) = **(undefined4 **)(iVar10 + 4);
    dVar18 = (double)FLOAT_803df50c;
    local_2b8[0] = FLOAT_803df50c;
    iVar14 = 4;
    iVar13 = 0x1c;
    pfVar12 = local_2b8;
    dVar16 = (double)FLOAT_803df510;
    dVar17 = extraout_f1;
    for (iVar9 = 1; pfVar12 = pfVar12 + 1, pfVar8 = pfVar8 + 1,
        iVar9 < (int)(uint)*(byte *)(*piVar5 + 0xf3); iVar9 = iVar9 + 1) {
      *(float *)(*(int *)(iVar10 + 4) + iVar14) = (float)(dVar17 * (double)*pfVar8);
      fVar2 = *(float *)(*(int *)(iVar10 + 4) + iVar14);
      *(float *)(*(int *)(iVar10 + 8) + iVar14) = fVar2 * fVar2;
      pcVar6 = (char *)(*(int *)(iVar11 + 0x3c) + iVar13);
      cVar1 = *pcVar6;
      dVar15 = FUN_80293900((double)(*(float *)(pcVar6 + 0xc) * *(float *)(pcVar6 + 0xc) +
                                    *(float *)(pcVar6 + 4) * *(float *)(pcVar6 + 4) +
                                    *(float *)(pcVar6 + 8) * *(float *)(pcVar6 + 8)));
      *(float *)(*(int *)(iVar10 + 0xc) + iVar14) = (float)(dVar17 * dVar15);
      if ((double)*(float *)(*(int *)(iVar10 + 0xc) + iVar14) == dVar18) {
        *(float *)(*(int *)(iVar10 + 0xc) + iVar14) = FLOAT_803df558;
      }
      dVar15 = (double)*(float *)(*(int *)(iVar11 + 0x1c) + iVar14);
      if (dVar16 <= dVar15) {
        *(float *)(*(int *)(iVar10 + 0xc) + iVar14) =
             (float)((double)*(float *)(*(int *)(iVar10 + 0xc) + iVar14) * dVar15);
      }
      iVar3 = cVar1 * 4;
      *pfVar12 = local_2b8[cVar1] + *(float *)(*(int *)(iVar10 + 0xc) + iVar14);
      if ((double)*pfVar8 == dVar18) {
        *(undefined4 *)(*(int *)(iVar10 + 0x10) + iVar14) =
             *(undefined4 *)(*(int *)(iVar10 + 0x10) + iVar3);
      }
      else {
        *(float *)(*(int *)(iVar10 + 0x10) + iVar14) =
             *pfVar12 + *(float *)(*(int *)(iVar10 + 4) + iVar14);
        iVar7 = *(int *)(iVar10 + 0x10);
        fVar2 = *(float *)(iVar7 + iVar3);
        if (fVar2 < *(float *)(iVar7 + iVar14)) {
          fVar2 = *(float *)(iVar7 + iVar14);
        }
        *(float *)(iVar7 + iVar14) = fVar2;
      }
      iVar14 = iVar14 + 4;
      iVar13 = iVar13 + 0x1c;
    }
  }
  FUN_80286878();
  return;
}

