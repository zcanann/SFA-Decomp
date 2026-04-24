// Function: FUN_8028504c
// Entry: 8028504c
// Size: 948 bytes

void FUN_8028504c(uint *param_1,int param_2)

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
  double dVar16;
  uint *puVar17;
  int iVar18;
  int iVar19;
  int iVar20;
  int iVar21;
  int iVar22;
  int iVar23;
  int iVar24;
  int iVar25;
  int iVar26;
  int iVar27;
  int iVar28;
  int iVar29;
  int iVar30;
  int iVar31;
  int iVar32;
  int iVar33;
  float *pfVar34;
  float *pfVar35;
  float *pfVar36;
  int *piVar37;
  uint uVar38;
  int *piVar39;
  int iVar40;
  int iVar41;
  int iVar42;
  
  dVar16 = DAT_803e7928;
  fVar15 = DAT_803e7920;
  fVar2 = *(float *)(param_2 + 0xf0);
  fVar3 = *(float *)(param_2 + 0x11c);
  fVar12 = *(float *)(param_2 + 0x118) * DAT_803e7924;
  fVar13 = DAT_803e7924 - fVar12;
  iVar18 = 0;
  do {
    iVar40 = iVar18 * 8 + param_2;
    fVar4 = *(float *)(iVar40 + 0xf4);
    fVar5 = *(float *)(iVar40 + 0xf8);
    iVar40 = iVar18 * 4 + param_2;
    fVar6 = *(float *)(iVar40 + 0x10c);
    pfVar34 = *(float **)(iVar40 + 0x124);
    pfVar35 = *(float **)(iVar40 + 0x130);
    iVar41 = *(int *)(param_2 + 0x120);
    piVar37 = (int *)(param_2 + 0x78 + iVar18 * 0x28);
    piVar39 = (int *)(param_2 + iVar18 * 0x28);
    iVar29 = *piVar37;
    iVar28 = piVar37[1];
    iVar27 = piVar37[5];
    iVar26 = piVar37[6];
    fVar7 = (float)piVar37[4];
    fVar8 = (float)piVar37[9];
    iVar33 = piVar37[2];
    iVar32 = piVar37[7];
    iVar19 = piVar37[3];
    iVar20 = piVar37[8];
    iVar24 = *piVar39;
    iVar23 = piVar39[1];
    iVar22 = piVar39[5];
    iVar21 = piVar39[6];
    fVar9 = (float)piVar39[4];
    fVar10 = (float)piVar39[9];
    iVar31 = piVar39[2];
    iVar30 = piVar39[7];
    iVar25 = piVar39[3];
    iVar40 = piVar39[8];
    fVar1 = (float)((double)CONCAT44(0x43300000,*param_1 ^ 0x80000000) - dVar16);
    iVar42 = 0x9f;
    do {
      puVar17 = param_1;
      fVar11 = fVar1;
      if (iVar41 != 0) {
        fVar11 = *pfVar35;
        pfVar36 = pfVar35 + 1;
        *pfVar35 = fVar1;
        pfVar35 = pfVar36;
        if (pfVar36 == pfVar34 + iVar41 + -1) {
          pfVar35 = pfVar34;
        }
      }
      param_1 = puVar17 + 1;
      uVar38 = *param_1;
      *(float *)(iVar19 + iVar29) = fVar4 * fVar7 + fVar11;
      iVar29 = iVar29 + 4;
      *(float *)(iVar20 + iVar27) = fVar5 * fVar8 + fVar11;
      fVar7 = *(float *)(iVar19 + iVar28);
      iVar28 = iVar28 + 4;
      fVar8 = *(float *)(iVar20 + iVar26);
      iVar27 = iVar27 + 4;
      iVar26 = iVar26 + 4;
      if (iVar29 == iVar33) {
        iVar29 = 0;
      }
      fVar11 = fVar2 * fVar9 + fVar7 + fVar8;
      if (iVar28 == iVar33) {
        iVar28 = 0;
      }
      if (iVar27 == iVar32) {
        iVar27 = 0;
      }
      *(float *)(iVar25 + iVar24) = fVar11;
      fVar11 = fVar2 * fVar11 - fVar9;
      iVar24 = iVar24 + 4;
      if (iVar26 == iVar32) {
        iVar26 = 0;
      }
      fVar9 = *(float *)(iVar25 + iVar23);
      iVar23 = iVar23 + 4;
      if (iVar24 == iVar31) {
        iVar24 = 0;
      }
      if (iVar23 == iVar31) {
        iVar23 = 0;
      }
      fVar6 = fVar3 * fVar6 + -fVar11 * fVar15;
      fVar11 = fVar2 * fVar10 + fVar6;
      *(float *)(iVar40 + iVar22) = fVar11;
      fVar11 = fVar2 * fVar11 - fVar10;
      fVar14 = fVar13 * fVar1;
      fVar10 = *(float *)(iVar40 + iVar21);
      iVar22 = iVar22 + 4;
      iVar21 = iVar21 + 4;
      if (iVar22 == iVar30) {
        iVar22 = 0;
      }
      if (iVar21 == iVar30) {
        iVar21 = 0;
      }
      fVar1 = (float)((double)CONCAT44(0x43300000,uVar38 ^ 0x80000000) - dVar16);
      *puVar17 = (int)(fVar12 * -fVar11 + fVar14);
      iVar42 = iVar42 + -1;
    } while (iVar42 != 0);
    pfVar36 = pfVar35;
    fVar11 = fVar1;
    if (iVar41 != 0) {
      fVar11 = *pfVar35;
      *pfVar35 = fVar1;
      pfVar36 = pfVar35 + 1;
      if (pfVar35 + 1 == pfVar34 + iVar41 + -1) {
        pfVar36 = pfVar34;
      }
    }
    *(float *)(iVar19 + iVar29) = fVar4 * fVar7 + fVar11;
    iVar29 = iVar29 + 4;
    *(float *)(iVar20 + iVar27) = fVar5 * fVar8 + fVar11;
    fVar4 = *(float *)(iVar19 + iVar28);
    iVar28 = iVar28 + 4;
    fVar5 = *(float *)(iVar20 + iVar26);
    iVar27 = iVar27 + 4;
    iVar26 = iVar26 + 4;
    if (iVar29 == iVar33) {
      iVar29 = 0;
    }
    fVar7 = fVar2 * fVar9 + fVar4 + fVar5;
    if (iVar28 == iVar33) {
      iVar28 = 0;
    }
    if (iVar27 == iVar32) {
      iVar27 = 0;
    }
    *(float *)(iVar25 + iVar24) = fVar7;
    iVar24 = iVar24 + 4;
    if (iVar26 == iVar32) {
      iVar26 = 0;
    }
    iVar19 = *(int *)(iVar25 + iVar23);
    iVar23 = iVar23 + 4;
    if (iVar24 == iVar31) {
      iVar24 = 0;
    }
    if (iVar23 == iVar31) {
      iVar23 = 0;
    }
    fVar7 = fVar3 * fVar6 + -(fVar2 * fVar7 - fVar9) * fVar15;
    fVar6 = fVar2 * fVar10 + fVar7;
    piVar37 = (int *)(param_2 + 0x78 + iVar18 * 0x28);
    *(float *)(iVar40 + iVar22) = fVar6;
    iVar40 = *(int *)(iVar40 + iVar21);
    iVar22 = iVar22 + 4;
    iVar21 = iVar21 + 4;
    if (iVar22 == iVar30) {
      iVar22 = 0;
    }
    if (iVar21 == iVar30) {
      iVar21 = 0;
    }
    piVar39 = (int *)(param_2 + iVar18 * 0x28);
    *param_1 = (int)(fVar12 * -(fVar2 * fVar6 - fVar10) + fVar13 * fVar1);
    *piVar37 = iVar29;
    piVar37[1] = iVar28;
    piVar37[5] = iVar27;
    piVar37[6] = iVar26;
    param_1 = puVar17 + 2;
    piVar37[4] = (int)fVar4;
    piVar37[9] = (int)fVar5;
    iVar20 = iVar18 * 4 + param_2;
    iVar18 = iVar18 + 1;
    *piVar39 = iVar24;
    piVar39[1] = iVar23;
    piVar39[5] = iVar22;
    piVar39[6] = iVar21;
    piVar39[4] = iVar19;
    piVar39[9] = iVar40;
    *(float *)(iVar20 + 0x10c) = fVar7;
    *(float **)(iVar20 + 0x130) = pfVar36;
  } while (iVar18 != 3);
  return;
}

