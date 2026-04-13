// Function: FUN_8000feac
// Entry: 8000feac
// Size: 396 bytes

/* WARNING: Removing unreachable block (ram,0x80010018) */

void FUN_8000feac(void)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  float *pfVar8;
  float *pfVar9;
  float *pfVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  uint unaff_GQR0;
  double dVar14;
  double in_f31;
  double dVar15;
  double in_ps31_1;
  undefined8 uVar16;
  float local_138 [21];
  float local_e4 [21];
  float local_90 [34];
  undefined4 local_8;
  float fStack_4;
  
  bVar1 = (byte)unaff_GQR0 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar15 = 1.0;
  }
  else {
    dVar15 = (double)ldexpf((byte)(unaff_GQR0 >> 8) & 0x3f);
  }
  if (bVar1 == 4 || bVar1 == 6) {
    local_8 = (float)CONCAT13((char)(dVar15 * in_f31),
                              CONCAT12((char)(dVar15 * in_ps31_1),local_8._2_2_));
  }
  else if (bVar1 == 5 || bVar1 == 7) {
    local_8 = (float)CONCAT22((short)(dVar15 * in_f31),(short)(dVar15 * in_ps31_1));
  }
  else {
    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
  }
  uVar16 = FUN_8028682c();
  iVar5 = (int)((ulonglong)uVar16 >> 0x20);
  iVar13 = 0;
  iVar12 = 0;
  iVar11 = 0;
  if (*(int *)(iVar5 + 0x84) != 0) {
    iVar13 = *(int *)(iVar5 + 0x84) + *(int *)(iVar5 + 0x10) * 4;
  }
  if (*(int *)(iVar5 + 0x88) != 0) {
    iVar12 = *(int *)(iVar5 + 0x88) + *(int *)(iVar5 + 0x10) * 4;
  }
  if (*(int *)(iVar5 + 0x8c) != 0) {
    iVar11 = *(int *)(iVar5 + 0x8c) + *(int *)(iVar5 + 0x10) * 4;
  }
  if (*(undefined **)(iVar5 + 0x98) != (undefined *)0x0) {
    FUN_80010038(iVar13,iVar12,iVar11,local_90,local_e4,local_138,(uint)uVar16,
                 *(undefined **)(iVar5 + 0x98));
  }
  dVar15 = (double)FLOAT_803df2d8;
  *(float *)(iVar5 + 0x14) = FLOAT_803df2d8;
  pfVar10 = local_90;
  pfVar9 = local_e4;
  pfVar8 = local_138;
  iVar7 = iVar5;
  for (iVar6 = 0; iVar6 < (int)(uint)uVar16; iVar6 = iVar6 + 1) {
    fVar2 = FLOAT_803df2d8;
    if (iVar13 != 0) {
      fVar2 = pfVar10[1] - *pfVar10;
    }
    fVar3 = FLOAT_803df2d8;
    if (iVar12 != 0) {
      fVar3 = pfVar9[1] - *pfVar9;
    }
    fVar4 = FLOAT_803df2d8;
    if (iVar11 != 0) {
      fVar4 = pfVar8[1] - *pfVar8;
    }
    dVar14 = (double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3);
    if (dVar14 <= dVar15) {
      *(float *)(iVar7 + 0x18) = FLOAT_803df2fc;
    }
    else {
      dVar14 = FUN_80293900(dVar14);
      *(float *)(iVar7 + 0x18) = (float)dVar14;
    }
    *(float *)(iVar5 + 0x14) = *(float *)(iVar5 + 0x14) + *(float *)(iVar7 + 0x18);
    pfVar10 = pfVar10 + 1;
    pfVar9 = pfVar9 + 1;
    pfVar8 = pfVar8 + 1;
    iVar7 = iVar7 + 4;
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-((byte)(unaff_GQR0 >> 0x18) & 0x3f));
  }
  FUN_80286878();
  return;
}

