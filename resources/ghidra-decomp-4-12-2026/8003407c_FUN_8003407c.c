// Function: FUN_8003407c
// Entry: 8003407c
// Size: 1232 bytes

/* WARNING: Removing unreachable block (ram,0x8003452c) */
/* WARNING: Removing unreachable block (ram,0x80034524) */
/* WARNING: Removing unreachable block (ram,0x8003451c) */
/* WARNING: Removing unreachable block (ram,0x80034514) */
/* WARNING: Removing unreachable block (ram,0x8003450c) */
/* WARNING: Removing unreachable block (ram,0x80034504) */
/* WARNING: Removing unreachable block (ram,0x800344fc) */
/* WARNING: Removing unreachable block (ram,0x800344f4) */
/* WARNING: Removing unreachable block (ram,0x800340c4) */
/* WARNING: Removing unreachable block (ram,0x800340bc) */
/* WARNING: Removing unreachable block (ram,0x800340b4) */
/* WARNING: Removing unreachable block (ram,0x800340ac) */
/* WARNING: Removing unreachable block (ram,0x800340a4) */
/* WARNING: Removing unreachable block (ram,0x8003409c) */
/* WARNING: Removing unreachable block (ram,0x80034094) */
/* WARNING: Removing unreachable block (ram,0x8003408c) */

void FUN_8003407c(void)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  bool bVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  double dVar23;
  double dVar24;
  undefined8 uVar25;
  undefined8 local_b0;
  
  uVar25 = FUN_80286840();
  iVar10 = (int)((ulonglong)uVar25 >> 0x20);
  iVar12 = (int)uVar25;
  iVar15 = *(int *)(iVar10 + 0x54);
  iVar14 = *(int *)(iVar12 + 0x54);
  if ((*(char *)(iVar15 + 0xae) != '\0') || (*(char *)(iVar14 + 0xae) != '\0')) goto LAB_800344f4;
  dVar23 = (double)(*(float *)(iVar12 + 0x18) - *(float *)(iVar10 + 0x18));
  dVar18 = (double)*(float *)(iVar12 + 0x1c);
  dVar17 = (double)*(float *)(iVar10 + 0x1c);
  dVar22 = (double)(float)(dVar18 - dVar17);
  dVar21 = (double)(*(float *)(iVar12 + 0x20) - *(float *)(iVar10 + 0x20));
  dVar24 = (double)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar15 + 0x5a) ^ 0x80000000)
                          - DOUBLE_803df5c0);
  local_b0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar14 + 0x5a) ^ 0x80000000);
  dVar20 = (double)(float)(local_b0 - DOUBLE_803df5c0);
  bVar9 = false;
  bVar1 = *(byte *)(iVar14 + 0x62);
  if (((bVar1 & 2) != 0) || ((*(byte *)(iVar15 + 0x62) & 2) != 0)) {
    if (dVar22 <= (double)FLOAT_803df590) {
      dVar22 = dVar20;
      if ((bVar1 & 2) != 0) {
        local_b0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar14 + 0x5e) ^ 0x80000000);
        dVar22 = (double)(float)(local_b0 - DOUBLE_803df5c0);
      }
      if ((*(byte *)(iVar15 + 0x62) & 2) == 0) {
        dVar17 = dVar17 - dVar24;
      }
      else {
        dVar17 = dVar17 + (double)(float)((double)CONCAT44(0x43300000,
                                                           (int)*(short *)(iVar15 + 0x5c) ^
                                                           0x80000000) - DOUBLE_803df5c0);
      }
      if ((float)(dVar18 + dVar22) < (float)dVar17) goto LAB_800344f4;
    }
    else {
      dVar22 = dVar24;
      if ((*(byte *)(iVar15 + 0x62) & 2) != 0) {
        local_b0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar15 + 0x5e) ^ 0x80000000);
        dVar22 = (double)(float)(local_b0 - DOUBLE_803df5c0);
      }
      if ((bVar1 & 2) == 0) {
        dVar18 = dVar18 - dVar20;
      }
      else {
        dVar18 = dVar18 + (double)(float)((double)CONCAT44(0x43300000,
                                                           (int)*(short *)(iVar14 + 0x5c) ^
                                                           0x80000000) - DOUBLE_803df5c0);
      }
      if ((float)(dVar17 + dVar22) < (float)dVar18) goto LAB_800344f4;
    }
    dVar22 = (double)FLOAT_803df590;
    bVar9 = true;
  }
  dVar18 = (double)(float)(dVar21 * dVar21 +
                          (double)(float)(dVar23 * dVar23 + (double)(float)(dVar22 * dVar22)));
  if (dVar18 != (double)FLOAT_803df590) {
    dVar18 = FUN_80293900(dVar18);
  }
  iVar11 = (int)((double)CONCAT44(0x43300000,(int)dVar18 ^ 0x80000000) - DOUBLE_803df5c0);
  iVar13 = iVar11;
  if (0x400 < iVar11) {
    iVar13 = 0x400;
  }
  if (iVar13 <= *(short *)(iVar15 + 0x58)) {
    *(short *)(iVar15 + 0x58) = (short)iVar13;
  }
  if (0x400 < iVar11) {
    iVar11 = 0x400;
  }
  if (iVar11 <= *(short *)(iVar14 + 0x58)) {
    *(short *)(iVar14 + 0x58) = (short)iVar11;
  }
  if ((*(ushort *)(iVar14 + 0x60) & 1) != 0) {
    dVar17 = (double)(float)(dVar20 + dVar24);
    fVar2 = *(float *)(iVar15 + 0x1c);
    fVar5 = *(float *)(iVar10 + 0x18) - fVar2;
    fVar3 = *(float *)(iVar15 + 0x20);
    fVar4 = *(float *)(iVar15 + 0x24);
    fVar7 = *(float *)(iVar10 + 0x20) - fVar4;
    fVar6 = *(float *)(iVar10 + 0x1c) - fVar3;
    if (bVar9) {
      fVar6 = FLOAT_803df590;
    }
    fVar8 = fVar7 * fVar7 + fVar5 * fVar5 + fVar6 * fVar6;
    if (FLOAT_803df598 < fVar8) {
      fVar8 = (fVar7 * (*(float *)(iVar12 + 0x20) - fVar4) +
              fVar5 * (*(float *)(iVar12 + 0x18) - fVar2) +
              fVar6 * (*(float *)(iVar12 + 0x1c) - fVar3)) / fVar8;
      if ((FLOAT_803df590 <= fVar8) && (fVar8 <= FLOAT_803df598)) {
        fVar4 = (fVar8 * fVar7 + fVar4) - *(float *)(iVar12 + 0x20);
        fVar5 = (fVar8 * fVar5 + fVar2) - *(float *)(iVar12 + 0x18);
        fVar2 = (fVar8 * fVar6 + fVar3) - *(float *)(iVar12 + 0x1c);
        dVar18 = FUN_80293900((double)(fVar4 * fVar4 + fVar5 * fVar5 + fVar2 * fVar2));
      }
    }
    if ((dVar18 < dVar17) && ((double)FLOAT_803df590 < dVar18)) {
      FUN_80036548(iVar12,iVar10,*(char *)(iVar15 + 0x6c),*(undefined *)(iVar15 + 0x6d),0);
      FUN_80036548(iVar10,iVar12,*(char *)(iVar14 + 0x6c),*(undefined *)(iVar14 + 0x6d),0);
      if (((*(ushort *)(iVar14 + 0x60) & 2) == 0) && ((*(ushort *)(iVar15 + 0x60) & 2) == 0)) {
        dVar20 = (double)(*(float *)(iVar14 + 0x1c) - *(float *)(iVar15 + 0x1c));
        dVar24 = (double)(*(float *)(iVar14 + 0x24) - *(float *)(iVar15 + 0x24));
        fVar2 = *(float *)(iVar14 + 0x20) - *(float *)(iVar15 + 0x20);
        if (bVar9) {
          fVar2 = FLOAT_803df590;
        }
        dVar19 = (double)fVar2;
        dVar16 = FUN_80293900((double)(float)(dVar24 * dVar24 +
                                             (double)(float)(dVar20 * dVar20 +
                                                            (double)(float)(dVar19 * dVar19))));
        if (dVar16 <= (double)FLOAT_803df590) {
          dVar20 = dVar23 / dVar18;
          dVar19 = dVar22 / dVar18;
          dVar24 = dVar21 / dVar18;
        }
        else {
          dVar20 = dVar20 / dVar16;
          dVar19 = dVar19 / dVar16;
          dVar24 = dVar24 / dVar16;
        }
        fVar2 = (float)(dVar17 - dVar18);
        FUN_80033a8c((double)((float)dVar20 * fVar2),(double)((float)dVar19 * fVar2),
                     (double)((float)dVar24 * fVar2),iVar10,iVar12,0);
      }
    }
  }
LAB_800344f4:
  FUN_8028688c();
  return;
}

