// Function: FUN_8002cec0
// Entry: 8002cec0
// Size: 600 bytes

/* WARNING: Removing unreachable block (ram,0x8002d0f0) */
/* WARNING: Removing unreachable block (ram,0x8002d0e8) */
/* WARNING: Removing unreachable block (ram,0x8002d0f8) */

void FUN_8002cec0(void)

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
  undefined4 uVar15;
  double extraout_f1;
  double dVar16;
  undefined8 in_f29;
  double dVar17;
  undefined8 in_f30;
  double dVar18;
  undefined8 in_f31;
  double dVar19;
  float local_2b8 [164];
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
  piVar5 = (int *)FUN_802860c8();
  iVar11 = *piVar5;
  uVar4 = countLeadingZeros((uint)*(ushort *)(iVar11 + 2));
  if (((((uVar4 >> 5 & 0x1000) == 0) && (*(char *)(iVar11 + 0xf3) != '\0')) &&
      (pfVar8 = *(float **)(iVar11 + 0x18), pfVar8 != (float *)0x0)) &&
     (iVar10 = piVar5[5], iVar10 != 0)) {
    **(float **)(iVar10 + 4) = (float)((double)*pfVar8 * extraout_f1);
    if (**(float **)(iVar10 + 4) == FLOAT_803de88c) {
      **(float **)(iVar10 + 4) = (float)((double)pfVar8[1] * extraout_f1);
    }
    **(float **)(iVar10 + 8) = **(float **)(iVar10 + 4) * **(float **)(iVar10 + 4);
    **(float **)(iVar10 + 0xc) = FLOAT_803de8d4;
    **(undefined4 **)(iVar10 + 0x10) = **(undefined4 **)(iVar10 + 4);
    dVar19 = (double)FLOAT_803de88c;
    local_2b8[0] = FLOAT_803de88c;
    iVar14 = 4;
    iVar13 = 0x1c;
    pfVar12 = local_2b8;
    dVar17 = (double)FLOAT_803de890;
    dVar18 = extraout_f1;
    for (iVar9 = 1; pfVar12 = pfVar12 + 1, pfVar8 = pfVar8 + 1,
        iVar9 < (int)(uint)*(byte *)(*piVar5 + 0xf3); iVar9 = iVar9 + 1) {
      *(float *)(*(int *)(iVar10 + 4) + iVar14) = (float)(dVar18 * (double)*pfVar8);
      fVar2 = *(float *)(*(int *)(iVar10 + 4) + iVar14);
      *(float *)(*(int *)(iVar10 + 8) + iVar14) = fVar2 * fVar2;
      pcVar6 = (char *)(*(int *)(iVar11 + 0x3c) + iVar13);
      cVar1 = *pcVar6;
      dVar16 = (double)FUN_802931a0((double)(*(float *)(pcVar6 + 0xc) * *(float *)(pcVar6 + 0xc) +
                                            *(float *)(pcVar6 + 4) * *(float *)(pcVar6 + 4) +
                                            *(float *)(pcVar6 + 8) * *(float *)(pcVar6 + 8)));
      *(float *)(*(int *)(iVar10 + 0xc) + iVar14) = (float)(dVar18 * dVar16);
      if ((double)*(float *)(*(int *)(iVar10 + 0xc) + iVar14) == dVar19) {
        *(float *)(*(int *)(iVar10 + 0xc) + iVar14) = FLOAT_803de8d8;
      }
      dVar16 = (double)*(float *)(*(int *)(iVar11 + 0x1c) + iVar14);
      if (dVar17 <= dVar16) {
        *(float *)(*(int *)(iVar10 + 0xc) + iVar14) =
             (float)((double)*(float *)(*(int *)(iVar10 + 0xc) + iVar14) * dVar16);
      }
      iVar3 = cVar1 * 4;
      *pfVar12 = local_2b8[cVar1] + *(float *)(*(int *)(iVar10 + 0xc) + iVar14);
      if ((double)*pfVar8 == dVar19) {
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
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  __psq_l0(auStack40,uVar15);
  __psq_l1(auStack40,uVar15);
  FUN_80286114();
  return;
}

