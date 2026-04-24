// Function: FUN_80033f84
// Entry: 80033f84
// Size: 1232 bytes

/* WARNING: Removing unreachable block (ram,0x8003442c) */
/* WARNING: Removing unreachable block (ram,0x8003441c) */
/* WARNING: Removing unreachable block (ram,0x8003440c) */
/* WARNING: Removing unreachable block (ram,0x800343fc) */
/* WARNING: Removing unreachable block (ram,0x80034404) */
/* WARNING: Removing unreachable block (ram,0x80034414) */
/* WARNING: Removing unreachable block (ram,0x80034424) */
/* WARNING: Removing unreachable block (ram,0x80034434) */

void FUN_80033f84(void)

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
  undefined4 uVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  undefined8 in_f24;
  undefined8 in_f25;
  double dVar20;
  undefined8 in_f26;
  double dVar21;
  undefined8 in_f27;
  double dVar22;
  undefined8 in_f28;
  double dVar23;
  undefined8 in_f29;
  double dVar24;
  undefined8 in_f30;
  double dVar25;
  undefined8 in_f31;
  undefined8 uVar26;
  double local_b0;
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar16 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  uVar26 = FUN_802860dc();
  iVar10 = (int)((ulonglong)uVar26 >> 0x20);
  iVar12 = (int)uVar26;
  iVar15 = *(int *)(iVar10 + 0x54);
  iVar14 = *(int *)(iVar12 + 0x54);
  if ((*(char *)(iVar15 + 0xae) != '\0') || (*(char *)(iVar14 + 0xae) != '\0')) goto LAB_800343fc;
  dVar24 = (double)(*(float *)(iVar12 + 0x18) - *(float *)(iVar10 + 0x18));
  dVar19 = (double)*(float *)(iVar12 + 0x1c);
  dVar18 = (double)*(float *)(iVar10 + 0x1c);
  dVar23 = (double)(float)(dVar19 - dVar18);
  dVar22 = (double)(*(float *)(iVar12 + 0x20) - *(float *)(iVar10 + 0x20));
  dVar25 = (double)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar15 + 0x5a) ^ 0x80000000)
                          - DOUBLE_803de940);
  local_b0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar14 + 0x5a) ^ 0x80000000);
  dVar21 = (double)(float)(local_b0 - DOUBLE_803de940);
  bVar9 = false;
  bVar1 = *(byte *)(iVar14 + 0x62);
  if (((bVar1 & 2) != 0) || ((*(byte *)(iVar15 + 0x62) & 2) != 0)) {
    if (dVar23 <= (double)FLOAT_803de910) {
      dVar23 = dVar21;
      if ((bVar1 & 2) != 0) {
        local_b0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar14 + 0x5e) ^ 0x80000000);
        dVar23 = (double)(float)(local_b0 - DOUBLE_803de940);
      }
      if ((*(byte *)(iVar15 + 0x62) & 2) == 0) {
        dVar18 = dVar18 - dVar25;
      }
      else {
        dVar18 = dVar18 + (double)(float)((double)CONCAT44(0x43300000,
                                                           (int)*(short *)(iVar15 + 0x5c) ^
                                                           0x80000000) - DOUBLE_803de940);
      }
      if ((float)(dVar19 + dVar23) < (float)dVar18) goto LAB_800343fc;
    }
    else {
      dVar23 = dVar25;
      if ((*(byte *)(iVar15 + 0x62) & 2) != 0) {
        local_b0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar15 + 0x5e) ^ 0x80000000);
        dVar23 = (double)(float)(local_b0 - DOUBLE_803de940);
      }
      if ((bVar1 & 2) == 0) {
        dVar19 = dVar19 - dVar21;
      }
      else {
        dVar19 = dVar19 + (double)(float)((double)CONCAT44(0x43300000,
                                                           (int)*(short *)(iVar14 + 0x5c) ^
                                                           0x80000000) - DOUBLE_803de940);
      }
      if ((float)(dVar18 + dVar23) < (float)dVar19) goto LAB_800343fc;
    }
    dVar23 = (double)FLOAT_803de910;
    bVar9 = true;
  }
  dVar19 = (double)(float)(dVar22 * dVar22 +
                          (double)(float)(dVar24 * dVar24 + (double)(float)(dVar23 * dVar23)));
  if (dVar19 != (double)FLOAT_803de910) {
    dVar19 = (double)FUN_802931a0(dVar19);
  }
  iVar11 = (int)((double)CONCAT44(0x43300000,(int)dVar19 ^ 0x80000000) - DOUBLE_803de940);
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
    dVar18 = (double)(float)(dVar21 + dVar25);
    fVar2 = *(float *)(iVar15 + 0x1c);
    fVar6 = *(float *)(iVar10 + 0x18) - fVar2;
    fVar3 = *(float *)(iVar15 + 0x20);
    fVar4 = *(float *)(iVar15 + 0x24);
    fVar8 = *(float *)(iVar10 + 0x20) - fVar4;
    fVar5 = *(float *)(iVar10 + 0x1c) - fVar3;
    if (bVar9) {
      fVar5 = FLOAT_803de910;
    }
    fVar7 = fVar8 * fVar8 + fVar6 * fVar6 + fVar5 * fVar5;
    if (FLOAT_803de918 < fVar7) {
      fVar7 = (fVar8 * (*(float *)(iVar12 + 0x20) - fVar4) +
              fVar6 * (*(float *)(iVar12 + 0x18) - fVar2) +
              fVar5 * (*(float *)(iVar12 + 0x1c) - fVar3)) / fVar7;
      if ((FLOAT_803de910 <= fVar7) && (fVar7 <= FLOAT_803de918)) {
        fVar4 = (fVar7 * fVar8 + fVar4) - *(float *)(iVar12 + 0x20);
        fVar6 = (fVar7 * fVar6 + fVar2) - *(float *)(iVar12 + 0x18);
        fVar2 = (fVar7 * fVar5 + fVar3) - *(float *)(iVar12 + 0x1c);
        dVar19 = (double)FUN_802931a0((double)(fVar4 * fVar4 + fVar6 * fVar6 + fVar2 * fVar2));
      }
    }
    if ((dVar19 < dVar18) && ((double)FLOAT_803de910 < dVar19)) {
      FUN_80036450(iVar12,iVar10,*(undefined *)(iVar15 + 0x6c),*(undefined *)(iVar15 + 0x6d),0);
      FUN_80036450(iVar10,iVar12,*(undefined *)(iVar14 + 0x6c),*(undefined *)(iVar14 + 0x6d),0);
      if (((*(ushort *)(iVar14 + 0x60) & 2) == 0) && ((*(ushort *)(iVar15 + 0x60) & 2) == 0)) {
        dVar21 = (double)(*(float *)(iVar14 + 0x1c) - *(float *)(iVar15 + 0x1c));
        dVar25 = (double)(*(float *)(iVar14 + 0x24) - *(float *)(iVar15 + 0x24));
        fVar2 = *(float *)(iVar14 + 0x20) - *(float *)(iVar15 + 0x20);
        if (bVar9) {
          fVar2 = FLOAT_803de910;
        }
        dVar20 = (double)fVar2;
        dVar17 = (double)FUN_802931a0((double)(float)(dVar25 * dVar25 +
                                                     (double)(float)(dVar21 * dVar21 +
                                                                    (double)(float)(dVar20 * dVar20)
                                                                    )));
        if (dVar17 <= (double)FLOAT_803de910) {
          dVar21 = dVar24 / dVar19;
          dVar20 = dVar23 / dVar19;
          dVar25 = dVar22 / dVar19;
        }
        else {
          dVar21 = dVar21 / dVar17;
          dVar20 = dVar20 / dVar17;
          dVar25 = dVar25 / dVar17;
        }
        fVar2 = (float)(dVar18 - dVar19);
        FUN_80033994((double)((float)dVar21 * fVar2),(double)((float)dVar20 * fVar2),
                     (double)((float)dVar25 * fVar2),iVar10,iVar12,0);
      }
    }
  }
LAB_800343fc:
  __psq_l0(auStack8,uVar16);
  __psq_l1(auStack8,uVar16);
  __psq_l0(auStack24,uVar16);
  __psq_l1(auStack24,uVar16);
  __psq_l0(auStack40,uVar16);
  __psq_l1(auStack40,uVar16);
  __psq_l0(auStack56,uVar16);
  __psq_l1(auStack56,uVar16);
  __psq_l0(auStack72,uVar16);
  __psq_l1(auStack72,uVar16);
  __psq_l0(auStack88,uVar16);
  __psq_l1(auStack88,uVar16);
  __psq_l0(auStack104,uVar16);
  __psq_l1(auStack104,uVar16);
  __psq_l0(auStack120,uVar16);
  __psq_l1(auStack120,uVar16);
  FUN_80286128();
  return;
}

