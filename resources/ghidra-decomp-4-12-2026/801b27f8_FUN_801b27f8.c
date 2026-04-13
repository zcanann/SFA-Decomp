// Function: FUN_801b27f8
// Entry: 801b27f8
// Size: 780 bytes

/* WARNING: Removing unreachable block (ram,0x801b2ae4) */
/* WARNING: Removing unreachable block (ram,0x801b2adc) */
/* WARNING: Removing unreachable block (ram,0x801b2810) */
/* WARNING: Removing unreachable block (ram,0x801b2808) */

void FUN_801b27f8(void)

{
  char cVar1;
  short sVar2;
  float fVar3;
  float fVar4;
  short sVar6;
  int iVar5;
  int iVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  
  iVar7 = FUN_8028683c();
  iVar12 = *(int *)(iVar7 + 0x4c);
  iVar8 = FUN_8002bac4();
  iVar13 = *(int *)(iVar7 + 0xb8);
  if (*(short *)(iVar13 + 0xa6) < 1) {
    iVar7 = FUN_800396d0(iVar7,0);
    sVar2 = *(short *)(iVar7 + 2);
    cVar1 = *(char *)(iVar12 + 0x28);
    uVar9 = FUN_80021884();
    iVar10 = ((uVar9 & 0xffff) + 0x8000) - ((int)sVar2 + cVar1 * 0x100 & 0xffffU);
    if (0x8000 < iVar10) {
      iVar10 = iVar10 + -0xffff;
    }
    if (iVar10 < -0x8000) {
      iVar10 = iVar10 + 0xffff;
    }
    if ((iVar10 < 0x1200) && (-0x1200 < iVar10)) {
      *(undefined *)(iVar13 + 0xad) = 1;
    }
    if (0x800 < iVar10) {
      iVar10 = 0x800;
    }
    if (iVar10 < -0x800) {
      iVar10 = -0x800;
    }
    iVar10 = iVar10 >> 3;
    if (iVar10 != 0) {
      sVar2 = *(short *)(iVar7 + 2);
      sVar6 = sVar2;
      if (sVar2 < 0) {
        sVar6 = -sVar2;
      }
      if ((int)DAT_803dcb6a - (int)DAT_803dcb6c < (int)sVar6) {
        if (iVar10 < 0) {
          iVar11 = -1;
        }
        else if (iVar10 < 1) {
          iVar11 = 0;
        }
        else {
          iVar11 = 1;
        }
        if (sVar2 < 0) {
          iVar5 = -1;
        }
        else if (sVar2 < 1) {
          iVar5 = 0;
        }
        else {
          iVar5 = 1;
        }
        if (iVar5 == iVar11) {
          iVar10 = (iVar10 * ((int)DAT_803dcb6a - (int)sVar6)) / (int)DAT_803dcb6c;
        }
      }
      *(short *)(iVar7 + 2) = *(short *)(iVar7 + 2) + (short)iVar10;
    }
    fVar3 = *(float *)(iVar13 + 0x8c) - *(float *)(iVar13 + 4);
    fVar4 = *(float *)(iVar13 + 0x94) - *(float *)(iVar13 + 0xc);
    dVar16 = (double)(fVar3 * fVar3 + fVar4 * fVar4);
    dVar14 = FUN_80293900(dVar16);
    dVar15 = (double)FLOAT_803e5560;
    fVar3 = (float)(dVar15 + (double)*(float *)(iVar13 + 8)) - *(float *)(iVar13 + 0x90);
    if (dVar15 < dVar16) {
      dVar15 = dVar16;
    }
    iVar7 = (uint)*(byte *)(iVar12 + 0x2b) * 2;
    if (((dVar15 < (double)(float)((double)CONCAT44(0x43300000,iVar7 * iVar7 ^ 0x80000000) -
                                  DOUBLE_803e5558)) || (fVar3 < FLOAT_803dcb7c)) ||
       ((*(ushort *)(iVar8 + 0xb0) & 0x1000) != 0)) {
      *(undefined *)(iVar13 + 0xad) = 0;
    }
    iVar7 = (uint)*(byte *)(iVar12 + 0x2b) * 2;
    uVar9 = iVar7 * iVar7 ^ 0x80000000;
    if (dVar15 <= (double)(float)((double)CONCAT44(0x43300000,uVar9) - DOUBLE_803e5558)) {
      dVar15 = (double)(float)((double)CONCAT44(0x43300000,uVar9) - DOUBLE_803e5558);
    }
    fVar3 = FLOAT_803e5564 * fVar3 - (float)((double)FLOAT_803e5568 * dVar14);
    fVar4 = FLOAT_803e556c;
    if (fVar3 < FLOAT_803e556c) {
      fVar4 = fVar3;
    }
    dVar14 = (double)((float)((double)(FLOAT_803e553c * -FLOAT_803dcb58) * dVar15) / fVar4);
    dVar15 = (double)FLOAT_803e5550;
    if (dVar15 < dVar14) {
      dVar15 = dVar14;
    }
    dVar15 = FUN_80293900(dVar15);
    *(float *)(iVar13 + 0x98) =
         (float)((double)*(float *)(iVar13 + 0x98) +
                (double)((float)(dVar15 - (double)*(float *)(iVar13 + 0x98)) / FLOAT_803e5570));
  }
  FUN_80286888();
  return;
}

