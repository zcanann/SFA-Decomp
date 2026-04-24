// Function: FUN_800dc398
// Entry: 800dc398
// Size: 4772 bytes

/* WARNING: Removing unreachable block (ram,0x800dd618) */
/* WARNING: Removing unreachable block (ram,0x800dd608) */
/* WARNING: Removing unreachable block (ram,0x800dd5f8) */
/* WARNING: Removing unreachable block (ram,0x800dd5f0) */
/* WARNING: Removing unreachable block (ram,0x800dd600) */
/* WARNING: Removing unreachable block (ram,0x800dd610) */
/* WARNING: Removing unreachable block (ram,0x800dd620) */

void FUN_800dc398(void)

{
  bool bVar1;
  byte bVar2;
  byte bVar3;
  float fVar4;
  float fVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  char *pcVar9;
  int *piVar10;
  int iVar11;
  undefined2 *puVar12;
  int iVar13;
  int iVar14;
  char cVar16;
  uint uVar15;
  byte bVar17;
  short *psVar18;
  int iVar19;
  int iVar20;
  byte *pbVar21;
  int iVar22;
  int iVar23;
  undefined4 uVar24;
  undefined8 in_f25;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar25;
  double dVar26;
  undefined8 in_f28;
  double dVar27;
  undefined8 in_f29;
  double dVar28;
  double dVar29;
  undefined8 in_f30;
  double dVar30;
  double dVar31;
  undefined8 in_f31;
  double dVar32;
  int local_2c8;
  char local_2c4 [2];
  char local_2c2;
  char local_290;
  byte abStack588 [364];
  double local_e0;
  double local_d8;
  double local_d0;
  double local_c8;
  double local_c0;
  double local_b8;
  double local_b0;
  double local_a8;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar24 = 0;
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
  FUN_802860c4();
  FUN_80059c2c(local_2c4);
  iVar14 = 1;
  iVar13 = 0;
  pcVar9 = local_2c4;
  iVar23 = 0xc;
  do {
    if (*pcVar9 != '\0') {
      iVar14 = iVar14 * iVar13;
    }
    if (pcVar9[1] != '\0') {
      iVar14 = iVar14 * (iVar13 + 1);
    }
    if (pcVar9[2] != '\0') {
      iVar14 = iVar14 * (iVar13 + 2);
    }
    if (pcVar9[3] != '\0') {
      iVar14 = iVar14 * (iVar13 + 3);
    }
    if (pcVar9[4] != '\0') {
      iVar14 = iVar14 * (iVar13 + 4);
    }
    if (pcVar9[5] != '\0') {
      iVar14 = iVar14 * (iVar13 + 5);
    }
    if (pcVar9[6] != '\0') {
      iVar14 = iVar14 * (iVar13 + 6);
    }
    if (pcVar9[7] != '\0') {
      iVar14 = iVar14 * (iVar13 + 7);
    }
    if (pcVar9[8] != '\0') {
      iVar14 = iVar14 * (iVar13 + 8);
    }
    if (pcVar9[9] != '\0') {
      iVar14 = iVar14 * (iVar13 + 9);
    }
    pcVar9 = pcVar9 + 10;
    iVar13 = iVar13 + 10;
    iVar23 = iVar23 + -1;
  } while (iVar23 != 0);
  if (iVar14 != DAT_803dd460) {
    fVar4 = FLOAT_803e0600;
    if ((local_2c2 == '\0') && (local_290 == '\0')) {
      fVar4 = FLOAT_803e0604;
    }
    dVar25 = (double)fVar4;
    DAT_803dd460 = iVar14;
    piVar10 = (int *)(**(code **)(*DAT_803dca9c + 0x10))(&local_2c8);
    FUN_800033a8(&DAT_803a1730,0,0xb5);
    iVar13 = 8;
    puVar12 = &DAT_8039cae8;
    do {
      puVar12[0x12] = 0;
      puVar12[0x2a] = 0;
      puVar12[0x42] = 0;
      puVar12[0x5a] = 0;
      puVar12[0x72] = 0;
      puVar12[0x8a] = 0;
      puVar12[0xa2] = 0;
      puVar12[0xba] = 0;
      puVar12[0xd2] = 0;
      puVar12[0xea] = 0;
      puVar12[0x102] = 0;
      puVar12[0x11a] = 0;
      puVar12[0x132] = 0;
      puVar12[0x14a] = 0;
      puVar12[0x162] = 0;
      puVar12[0x17a] = 0;
      puVar12[0x192] = 0;
      puVar12[0x1aa] = 0;
      puVar12[0x1c2] = 0;
      puVar12[0x1da] = 0;
      puVar12[0x1f2] = 0;
      puVar12[0x20a] = 0;
      puVar12[0x222] = 0;
      puVar12[0x23a] = 0;
      puVar12[0x252] = 0;
      puVar12[0x26a] = 0;
      puVar12[0x282] = 0;
      puVar12[0x29a] = 0;
      puVar12[0x2b2] = 0;
      puVar12[0x2ca] = 0;
      puVar12[0x2e2] = 0;
      puVar12[0x2fa] = 0;
      puVar12 = puVar12 + 0x300;
      iVar13 = iVar13 + -1;
    } while (iVar13 != 0);
    DAT_803dd468 = 1;
    for (iVar13 = 0; iVar13 < local_2c8; iVar13 = iVar13 + 1) {
      iVar14 = *piVar10;
      if (*(char *)(iVar14 + 0x19) == '&') {
        uVar15 = (uint)*(byte *)(iVar14 + 3);
        iVar23 = uVar15 * 0x28;
        psVar18 = &DAT_8039fae8 + uVar15 * 0x14;
        (&DAT_803a1730)[uVar15] = 1;
        local_e0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 4) ^ 0x80000000);
        dVar30 = (double)(float)((double)(float)(local_e0 - DOUBLE_803e05e0) * dVar25 +
                                (double)*(float *)(iVar14 + 8));
        local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 5) ^ 0x80000000);
        dVar32 = (double)(float)((double)(float)(local_d8 - DOUBLE_803e05e0) * dVar25 +
                                (double)*(float *)(iVar14 + 0x10));
        local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 6) ^ 0x80000000);
        dVar28 = (double)(float)((double)(float)(local_d0 - DOUBLE_803e05e0) * dVar25 +
                                (double)*(float *)(iVar14 + 8));
        local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 7) ^ 0x80000000);
        dVar29 = (double)(float)((double)(float)(local_c8 - DOUBLE_803e05e0) * dVar25 +
                                (double)*(float *)(iVar14 + 0x10));
        dVar31 = (double)(float)(dVar29 - dVar32);
        dVar27 = (double)(float)(dVar30 - dVar28);
        dVar26 = (double)FUN_802931a0((double)(float)(dVar31 * dVar31 +
                                                     (double)(float)(dVar27 * dVar27)));
        if (dVar26 != (double)FLOAT_803e05f0) {
          dVar31 = (double)(float)(dVar31 / dVar26);
          dVar27 = (double)(float)(dVar27 / dVar26);
        }
        dVar26 = (double)FLOAT_803e05fc;
        iVar19 = (int)(dVar26 * dVar31);
        local_c8 = (double)(longlong)iVar19;
        *psVar18 = (short)iVar19;
        iVar19 = (int)(dVar26 * dVar27);
        local_d0 = (double)(longlong)iVar19;
        (&DAT_8039faea)[uVar15 * 0x14] = (short)iVar19;
        dVar26 = DOUBLE_803e05e0;
        local_d8 = (double)CONCAT44(0x43300000,(int)*psVar18 ^ 0x80000000);
        local_e0 = (double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_8039faea)[uVar15 * 0x14] ^ 0x80000000);
        (&DAT_8039faf8)[uVar15 * 10] =
             -(float)((double)(float)(local_d8 - DOUBLE_803e05e0) * dVar30 +
                     (double)(float)((double)(float)(local_e0 - DOUBLE_803e05e0) * dVar32));
        local_c0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 0x30) ^ 0x80000000);
        dVar30 = (double)(float)((double)(float)(local_c0 - dVar26) * dVar25 +
                                (double)*(float *)(iVar14 + 8));
        local_b8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 0x31) ^ 0x80000000);
        dVar32 = (double)(float)((double)(float)(local_b8 - dVar26) * dVar25 +
                                (double)*(float *)(iVar14 + 0x10));
        dVar27 = (double)(float)(dVar32 - dVar29);
        dVar31 = (double)(float)(dVar28 - dVar30);
        dVar26 = (double)FUN_802931a0((double)(float)(dVar27 * dVar27 +
                                                     (double)(float)(dVar31 * dVar31)));
        if (dVar26 != (double)FLOAT_803e05f0) {
          dVar27 = (double)(float)(dVar27 / dVar26);
          dVar31 = (double)(float)(dVar31 / dVar26);
        }
        dVar26 = (double)FLOAT_803e05fc;
        iVar19 = (int)(dVar26 * dVar27);
        local_b8 = (double)(longlong)iVar19;
        *(short *)(&DAT_8039faec + iVar23) = (short)iVar19;
        iVar19 = (int)(dVar26 * dVar31);
        local_c0 = (double)(longlong)iVar19;
        *(short *)(&DAT_8039faee + iVar23) = (short)iVar19;
        dVar26 = DOUBLE_803e05e0;
        local_c8 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_8039faec + iVar23) ^ 0x80000000)
        ;
        local_d0 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_8039faee + iVar23) ^ 0x80000000)
        ;
        *(float *)(&DAT_8039fafc + iVar23) =
             -(float)((double)(float)(local_c8 - DOUBLE_803e05e0) * dVar28 +
                     (double)(float)((double)(float)(local_d0 - DOUBLE_803e05e0) * dVar29));
        local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 0x32) ^ 0x80000000);
        dVar29 = (double)(float)((double)(float)(local_d8 - dVar26) * dVar25 +
                                (double)*(float *)(iVar14 + 8));
        local_e0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 0x33) ^ 0x80000000);
        dVar28 = (double)(float)((double)(float)(local_e0 - dVar26) * dVar25 +
                                (double)*(float *)(iVar14 + 0x10));
        dVar27 = (double)(float)(dVar28 - dVar32);
        dVar31 = (double)(float)(dVar30 - dVar29);
        dVar26 = (double)FUN_802931a0((double)(float)(dVar27 * dVar27 +
                                                     (double)(float)(dVar31 * dVar31)));
        if (dVar26 != (double)FLOAT_803e05f0) {
          dVar27 = (double)(float)(dVar27 / dVar26);
          dVar31 = (double)(float)(dVar31 / dVar26);
        }
        dVar26 = (double)FLOAT_803e05fc;
        iVar19 = (int)(dVar26 * dVar27);
        local_b8 = (double)(longlong)iVar19;
        *(short *)(&DAT_8039faf0 + iVar23) = (short)iVar19;
        iVar19 = (int)(dVar26 * dVar31);
        local_c0 = (double)(longlong)iVar19;
        *(short *)(&DAT_8039faf2 + iVar23) = (short)iVar19;
        dVar26 = DOUBLE_803e05e0;
        local_c8 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_8039faf0 + iVar23) ^ 0x80000000)
        ;
        local_d0 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_8039faf2 + iVar23) ^ 0x80000000)
        ;
        *(float *)(&DAT_8039fb00 + iVar23) =
             -(float)((double)(float)(local_c8 - DOUBLE_803e05e0) * dVar30 +
                     (double)(float)((double)(float)(local_d0 - DOUBLE_803e05e0) * dVar32));
        local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 5) ^ 0x80000000);
        dVar27 = (double)(float)((double)(float)((double)(float)(local_d8 - dVar26) * dVar25 +
                                                (double)*(float *)(iVar14 + 0x10)) - dVar28);
        local_e0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 4) ^ 0x80000000);
        dVar31 = (double)(float)(dVar29 - (double)(float)((double)(float)(local_e0 - dVar26) *
                                                          dVar25 + (double)*(float *)(iVar14 + 8)));
        dVar26 = (double)FUN_802931a0((double)(float)(dVar27 * dVar27 +
                                                     (double)(float)(dVar31 * dVar31)));
        if (dVar26 != (double)FLOAT_803e05f0) {
          dVar27 = (double)(float)(dVar27 / dVar26);
          dVar31 = (double)(float)(dVar31 / dVar26);
        }
        dVar26 = (double)FLOAT_803e05fc;
        iVar19 = (int)(dVar26 * dVar27);
        local_b8 = (double)(longlong)iVar19;
        *(short *)(&DAT_8039faf4 + iVar23) = (short)iVar19;
        iVar19 = (int)(dVar26 * dVar31);
        local_c0 = (double)(longlong)iVar19;
        *(short *)(&DAT_8039faf6 + iVar23) = (short)iVar19;
        dVar26 = DOUBLE_803e05e0;
        local_c8 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_8039faf4 + iVar23) ^ 0x80000000)
        ;
        local_d0 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_8039faf6 + iVar23) ^ 0x80000000)
        ;
        *(float *)(&DAT_8039fb04 + iVar23) =
             -(float)((double)(float)(local_c8 - DOUBLE_803e05e0) * dVar29 +
                     (double)(float)((double)(float)(local_d0 - DOUBLE_803e05e0) * dVar28));
        fVar4 = FLOAT_803e05d0;
        local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 0x18) ^ 0x80000000);
        iVar23 = (int)(FLOAT_803e05d0 * (float)(local_d8 - dVar26) + *(float *)(iVar14 + 0xc));
        local_e0 = (double)(longlong)iVar23;
        (&DAT_8039fb08)[uVar15 * 0x14] = (short)iVar23;
        local_b0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 0x1a) ^ 0x80000000);
        iVar23 = (int)-(fVar4 * (float)(local_b0 - dVar26) - *(float *)(iVar14 + 0xc));
        local_a8 = (double)(longlong)iVar23;
        (&DAT_8039fb0a)[uVar15 * 0x14] = (short)iVar23;
        iVar19 = 0;
        iVar23 = iVar14;
        do {
          iVar22 = iVar19 + 0x24;
          *(undefined *)((int)psVar18 + iVar22) = 0;
          if ((-1 < *(int *)(iVar23 + 0x1c)) &&
             (iVar11 = (**(code **)(*DAT_803dca9c + 0x1c))(), iVar11 != 0)) {
            bVar2 = *(byte *)(iVar14 + 3);
            bVar3 = *(byte *)(iVar11 + 3);
            if (bVar2 < bVar3) {
              sVar6 = CONCAT11(bVar3,bVar2);
            }
            else {
              sVar6 = CONCAT11(bVar2,bVar3);
            }
            cVar16 = '\x01';
            puVar12 = &DAT_8039cb18;
            iVar7 = DAT_803dd468 + -1;
            if (1 < DAT_803dd468) {
              do {
                if (sVar6 == puVar12[0x12]) {
                  *(char *)((int)psVar18 + iVar22) = cVar16;
                  break;
                }
                puVar12 = puVar12 + 0x18;
                cVar16 = cVar16 + '\x01';
                iVar7 = iVar7 + -1;
              } while (iVar7 != 0);
            }
            iVar7 = DAT_803dd468;
            if (*(char *)((int)psVar18 + iVar22) == '\0') {
              iVar20 = 0;
              iVar8 = *(int *)(iVar14 + 0x14);
              if ((((*(int *)(iVar11 + 0x1c) != iVar8) &&
                   (iVar20 = 1, *(int *)(iVar11 + 0x20) != iVar8)) &&
                  (iVar20 = 2, *(int *)(iVar11 + 0x24) != iVar8)) &&
                 (iVar20 = 3, *(int *)(iVar11 + 0x28) != iVar8)) {
                iVar20 = 4;
              }
              *(char *)((int)psVar18 + iVar22) = (char)DAT_803dd468;
              (&DAT_8039cb0c)[iVar7 * 0x18] = sVar6;
              fVar4 = FLOAT_803e0608;
              abStack588[iVar7 * 2] = *(byte *)(iVar14 + 3);
              abStack588[iVar7 * 2 + 1] = *(byte *)(iVar11 + 3);
              local_a8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar23 + 0x34) ^ 0x80000000);
              dVar29 = (double)(float)((double)(float)(local_a8 - DOUBLE_803e05e0) * dVar25 +
                                      (double)*(float *)(iVar14 + 8));
              local_b0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar23 + 0x35) ^ 0x80000000);
              dVar28 = (double)(float)((double)(float)(local_b0 - DOUBLE_803e05e0) * dVar25 +
                                      (double)*(float *)(iVar14 + 0x10));
              local_b8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar23 + 0x36) ^ 0x80000000);
              dVar30 = (double)(float)((double)(float)(local_b8 - DOUBLE_803e05e0) * dVar25 +
                                      (double)*(float *)(iVar14 + 8));
              local_c0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar23 + 0x37) ^ 0x80000000);
              dVar32 = (double)(float)((double)(float)(local_c0 - DOUBLE_803e05e0) * dVar25 +
                                      (double)*(float *)(iVar14 + 0x10));
              iVar22 = (int)((float)(dVar29 + dVar30) * FLOAT_803e0608);
              local_c8 = (double)(longlong)iVar22;
              (&DAT_8039cb0e)[iVar7 * 0x18] = (short)iVar22;
              iVar22 = (int)((float)(dVar28 + dVar32) * fVar4);
              local_d0 = (double)(longlong)iVar22;
              (&DAT_8039cb10)[iVar7 * 0x18] = (short)iVar22;
              dVar27 = (double)(float)(dVar32 - dVar28);
              dVar31 = (double)(float)(dVar29 - dVar30);
              dVar26 = (double)FUN_802931a0((double)(float)(dVar27 * dVar27 +
                                                           (double)(float)(dVar31 * dVar31)));
              if (dVar26 != (double)FLOAT_803e05f0) {
                dVar27 = (double)(float)(dVar27 / dVar26);
                dVar31 = (double)(float)(dVar31 / dVar26);
              }
              dVar26 = (double)FLOAT_803e05fc;
              iVar22 = (int)(dVar26 * dVar27);
              local_a8 = (double)(longlong)iVar22;
              (&DAT_8039cae8)[iVar7 * 0x18] = (short)iVar22;
              iVar22 = (int)(dVar26 * dVar31);
              local_b0 = (double)(longlong)iVar22;
              (&DAT_8039caea)[iVar7 * 0x18] = (short)iVar22;
              dVar26 = DOUBLE_803e05e0;
              local_b8 = (double)CONCAT44(0x43300000,
                                          (int)(short)(&DAT_8039cae8)[iVar7 * 0x18] ^ 0x80000000);
              local_c0 = (double)CONCAT44(0x43300000,
                                          (int)(short)(&DAT_8039caea)[iVar7 * 0x18] ^ 0x80000000);
              (&DAT_8039caf8)[iVar7 * 0xc] =
                   -(float)((double)(float)(local_b8 - DOUBLE_803e05e0) * dVar29 +
                           (double)(float)((double)(float)(local_c0 - DOUBLE_803e05e0) * dVar28));
              iVar7 = iVar11 + iVar20 * 4;
              local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x34) ^ 0x80000000);
              dVar29 = (double)(float)((double)(float)(local_c8 - dVar26) * dVar25 +
                                      (double)*(float *)(iVar11 + 8));
              local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x35) ^ 0x80000000);
              dVar28 = (double)(float)((double)(float)(local_d0 - dVar26) * dVar25 +
                                      (double)*(float *)(iVar11 + 0x10));
              iVar22 = DAT_803dd468 * 0x30;
              dVar27 = (double)(float)(dVar28 - dVar32);
              dVar31 = (double)(float)(dVar30 - dVar29);
              dVar26 = (double)FUN_802931a0((double)(float)(dVar27 * dVar27 +
                                                           (double)(float)(dVar31 * dVar31)));
              if (dVar26 != (double)FLOAT_803e05f0) {
                dVar27 = (double)(float)(dVar27 / dVar26);
                dVar31 = (double)(float)(dVar31 / dVar26);
              }
              dVar26 = (double)FLOAT_803e05fc;
              iVar8 = (int)(dVar26 * dVar27);
              local_a8 = (double)(longlong)iVar8;
              *(short *)(&DAT_8039caec + iVar22) = (short)iVar8;
              iVar8 = (int)(dVar26 * dVar31);
              local_b0 = (double)(longlong)iVar8;
              *(short *)(&DAT_8039caee + iVar22) = (short)iVar8;
              dVar26 = DOUBLE_803e05e0;
              local_b8 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(&DAT_8039caec + iVar22) ^ 0x80000000);
              local_c0 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(&DAT_8039caee + iVar22) ^ 0x80000000);
              *(float *)(&DAT_8039cafc + iVar22) =
                   -(float)((double)(float)(local_b8 - DOUBLE_803e05e0) * dVar30 +
                           (double)(float)((double)(float)(local_c0 - DOUBLE_803e05e0) * dVar32));
              fVar4 = FLOAT_803e0608;
              iVar8 = DAT_803dd468;
              local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x36) ^ 0x80000000);
              dVar30 = (double)(float)((double)(float)(local_c8 - dVar26) * dVar25 +
                                      (double)*(float *)(iVar11 + 8));
              local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x37) ^ 0x80000000);
              dVar32 = (double)(float)((double)(float)(local_d0 - dVar26) * dVar25 +
                                      (double)*(float *)(iVar11 + 0x10));
              iVar22 = (int)((float)(dVar29 + dVar30) * FLOAT_803e0608);
              local_d8 = (double)(longlong)iVar22;
              iVar7 = DAT_803dd468 * 0x30;
              (&DAT_8039cb12)[DAT_803dd468 * 0x18] = (short)iVar22;
              iVar22 = (int)((float)(dVar28 + dVar32) * fVar4);
              local_e0 = (double)(longlong)iVar22;
              (&DAT_8039cb14)[iVar8 * 0x18] = (short)iVar22;
              dVar27 = (double)(float)(dVar32 - dVar28);
              dVar31 = (double)(float)(dVar29 - dVar30);
              dVar26 = (double)FUN_802931a0((double)(float)(dVar27 * dVar27 +
                                                           (double)(float)(dVar31 * dVar31)));
              if (dVar26 != (double)FLOAT_803e05f0) {
                dVar27 = (double)(float)(dVar27 / dVar26);
                dVar31 = (double)(float)(dVar31 / dVar26);
              }
              dVar26 = (double)FLOAT_803e05fc;
              iVar22 = (int)(dVar26 * dVar27);
              local_a8 = (double)(longlong)iVar22;
              *(short *)(&DAT_8039caf0 + iVar7) = (short)iVar22;
              iVar22 = (int)(dVar26 * dVar31);
              local_b0 = (double)(longlong)iVar22;
              *(short *)(&DAT_8039caf2 + iVar7) = (short)iVar22;
              dVar26 = DOUBLE_803e05e0;
              local_b8 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(&DAT_8039caf0 + iVar7) ^ 0x80000000);
              local_c0 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(&DAT_8039caf2 + iVar7) ^ 0x80000000);
              *(float *)(&DAT_8039cb00 + iVar7) =
                   -(float)((double)(float)(local_b8 - DOUBLE_803e05e0) * dVar29 +
                           (double)(float)((double)(float)(local_c0 - DOUBLE_803e05e0) * dVar28));
              iVar22 = DAT_803dd468 * 0x30;
              local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar23 + 0x35) ^ 0x80000000);
              dVar27 = (double)(float)((double)(float)((double)(float)(local_c8 - dVar26) * dVar25 +
                                                      (double)*(float *)(iVar14 + 0x10)) - dVar32);
              local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar23 + 0x34) ^ 0x80000000);
              dVar31 = (double)(float)(dVar30 - (double)(float)((double)(float)(local_d0 - dVar26) *
                                                                dVar25 + (double)*(float *)(iVar14 +
                                                                                           8)));
              dVar26 = (double)FUN_802931a0((double)(float)(dVar27 * dVar27 +
                                                           (double)(float)(dVar31 * dVar31)));
              if (dVar26 != (double)FLOAT_803e05f0) {
                dVar27 = (double)(float)(dVar27 / dVar26);
                dVar31 = (double)(float)(dVar31 / dVar26);
              }
              dVar26 = (double)FLOAT_803e05fc;
              *(short *)(&DAT_8039caf4 + iVar22) = (short)(int)(dVar26 * dVar27);
              *(short *)(&DAT_8039caf6 + iVar22) = (short)(int)(dVar26 * dVar31);
              dVar26 = DOUBLE_803e05e0;
              local_b8 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(&DAT_8039caf4 + iVar22) ^ 0x80000000);
              local_c0 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(&DAT_8039caf6 + iVar22) ^ 0x80000000);
              *(float *)(&DAT_8039cb04 + iVar22) =
                   -(float)((double)(float)(local_b8 - DOUBLE_803e05e0) * dVar30 +
                           (double)(float)((double)(float)(local_c0 - DOUBLE_803e05e0) * dVar32));
              local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 0x18) ^ 0x80000000);
              fVar5 = FLOAT_803e05d0 * (float)(local_c8 - dVar26) + *(float *)(iVar14 + 0xc);
              local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x18) ^ 0x80000000);
              fVar4 = FLOAT_803e05d0 * (float)(local_d0 - dVar26) + *(float *)(iVar11 + 0xc);
              if (fVar5 <= fVar4) {
                (&DAT_8039cb08)[DAT_803dd468 * 0x18] = (short)(int)fVar4;
              }
              else {
                (&DAT_8039cb08)[DAT_803dd468 * 0x18] = (short)(int)fVar5;
              }
              local_a8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar14 + 0x1a) ^ 0x80000000);
              fVar4 = -(FLOAT_803e05d0 * (float)(local_a8 - DOUBLE_803e05e0) -
                       *(float *)(iVar14 + 0xc));
              local_b0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x1a) ^ 0x80000000);
              fVar5 = -(FLOAT_803e05d0 * (float)(local_b0 - DOUBLE_803e05e0) -
                       *(float *)(iVar11 + 0xc));
              if (fVar5 <= fVar4) {
                iVar22 = (int)fVar5;
                local_a8 = (double)(longlong)iVar22;
                (&DAT_8039cb0a)[DAT_803dd468 * 0x18] = (short)iVar22;
              }
              else {
                iVar22 = (int)fVar4;
                local_a8 = (double)(longlong)iVar22;
                (&DAT_8039cb0a)[DAT_803dd468 * 0x18] = (short)iVar22;
              }
              DAT_803dd468 = DAT_803dd468 + 1;
            }
          }
          iVar23 = iVar23 + 4;
          iVar19 = iVar19 + 1;
        } while (iVar19 < 4);
      }
      piVar10 = piVar10 + 1;
    }
    pbVar21 = abStack588;
    dVar26 = (double)FLOAT_803e05f0;
    dVar31 = (double)FLOAT_803e060c;
    dVar25 = DOUBLE_803e05e0;
    puVar12 = &DAT_8039cae8;
    for (iVar13 = 1; pbVar21 = pbVar21 + 2, iVar13 < DAT_803dd468; iVar13 = iVar13 + 1) {
      bVar2 = *pbVar21;
      bVar3 = pbVar21[1];
      local_a8 = (double)CONCAT44(0x43300000,
                                  (int)(short)puVar12[0x2d] - (int)(short)puVar12[0x2b] ^ 0x80000000
                                 );
      dVar27 = (double)(float)(local_a8 - dVar25);
      local_b0 = (double)CONCAT44(0x43300000,
                                  (int)(short)puVar12[0x2e] - (int)(short)puVar12[0x2c] ^ 0x80000000
                                 );
      dVar29 = (double)(float)(local_b0 - dVar25);
      iVar14 = 0;
      do {
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2c] ^ 0x80000000);
        dVar28 = local_a8 - dVar25;
        local_b0 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2b] ^ 0x80000000);
        dVar30 = local_b0 - dVar25;
        uVar15 = 0;
        for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
          local_a8 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039fae8)
                                                  [(uint)bVar2 * 0x14 + (uVar15 & 0xff)] ^
                                      0x80000000);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039fae8)
                                                  [(uint)bVar2 * 0x14 + (uVar15 & 0xff) + 1] ^
                                      0x80000000);
          if (dVar26 < (double)(*(float *)(&DAT_8039fae8 + (uint)bVar2 * 0x14 + (uint)bVar17 * 2 + 8
                                          ) +
                               (float)dVar30 * (float)(local_a8 - dVar25) +
                               (float)dVar28 * (float)(local_b0 - dVar25))) break;
          uVar15 = uVar15 + 2;
        }
        if (bVar17 == 4) goto LAB_800dd3d4;
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2c] ^ 0x80000000);
        dVar28 = local_a8 - dVar25;
        local_b0 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2b] ^ 0x80000000);
        dVar30 = local_b0 - dVar25;
        uVar15 = 0;
        for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
          local_a8 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039fae8)
                                                  [(uint)bVar3 * 0x14 + (uVar15 & 0xff)] ^
                                      0x80000000);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039fae8)
                                                  [(uint)bVar3 * 0x14 + (uVar15 & 0xff) + 1] ^
                                      0x80000000);
          if (dVar26 < (double)(*(float *)(&DAT_8039fae8 + (uint)bVar3 * 0x14 + (uint)bVar17 * 2 + 8
                                          ) +
                               (float)dVar30 * (float)(local_a8 - dVar25) +
                               (float)dVar28 * (float)(local_b0 - dVar25))) break;
          uVar15 = uVar15 + 2;
        }
        if (bVar17 == 4) goto LAB_800dd3d4;
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2b] ^ 0x80000000);
        iVar23 = (int)((float)(local_a8 - dVar25) + (float)(dVar27 / dVar31));
        local_b0 = (double)(longlong)iVar23;
        puVar12[0x2b] = (short)iVar23;
        local_b8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2c] ^ 0x80000000);
        iVar23 = (int)((float)(local_b8 - dVar25) + (float)(dVar29 / dVar31));
        local_c0 = (double)(longlong)iVar23;
        puVar12[0x2c] = (short)iVar23;
        bVar1 = iVar14 != 100;
        iVar14 = iVar14 + 1;
      } while (bVar1);
      FUN_8007d6dc(s_Unable_to_find_exit_point_0_on_p_8031156c,puVar12[0x2a] & 0xff,
                   (int)(uint)(ushort)puVar12[0x2a] >> 8);
LAB_800dd3d4:
      iVar14 = 0;
      do {
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2e] ^ 0x80000000);
        dVar28 = local_a8 - dVar25;
        local_b0 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2d] ^ 0x80000000);
        dVar30 = local_b0 - dVar25;
        uVar15 = 0;
        for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
          local_a8 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039fae8)
                                                  [(uint)bVar2 * 0x14 + (uVar15 & 0xff)] ^
                                      0x80000000);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039fae8)
                                                  [(uint)bVar2 * 0x14 + (uVar15 & 0xff) + 1] ^
                                      0x80000000);
          if (dVar26 < (double)(*(float *)(&DAT_8039fae8 + (uint)bVar2 * 0x14 + (uint)bVar17 * 2 + 8
                                          ) +
                               (float)dVar30 * (float)(local_a8 - dVar25) +
                               (float)dVar28 * (float)(local_b0 - dVar25))) break;
          uVar15 = uVar15 + 2;
        }
        if (bVar17 == 4) goto LAB_800dd5d8;
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2e] ^ 0x80000000);
        dVar28 = local_a8 - dVar25;
        local_b0 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2d] ^ 0x80000000);
        dVar30 = local_b0 - dVar25;
        uVar15 = 0;
        for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
          local_a8 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039fae8)
                                                  [(uint)bVar3 * 0x14 + (uVar15 & 0xff)] ^
                                      0x80000000);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_8039fae8)
                                                  [(uint)bVar3 * 0x14 + (uVar15 & 0xff) + 1] ^
                                      0x80000000);
          if (dVar26 < (double)(*(float *)(&DAT_8039fae8 + (uint)bVar3 * 0x14 + (uint)bVar17 * 2 + 8
                                          ) +
                               (float)dVar30 * (float)(local_a8 - dVar25) +
                               (float)dVar28 * (float)(local_b0 - dVar25))) break;
          uVar15 = uVar15 + 2;
        }
        if (bVar17 == 4) goto LAB_800dd5d8;
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2d] ^ 0x80000000);
        iVar23 = (int)((float)(local_a8 - dVar25) - (float)(dVar27 / dVar31));
        local_b0 = (double)(longlong)iVar23;
        puVar12[0x2d] = (short)iVar23;
        local_b8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2e] ^ 0x80000000);
        iVar23 = (int)((float)(local_b8 - dVar25) - (float)(dVar29 / dVar31));
        local_c0 = (double)(longlong)iVar23;
        puVar12[0x2e] = (short)iVar23;
        bVar1 = iVar14 != 100;
        iVar14 = iVar14 + 1;
      } while (bVar1);
      FUN_8007d6dc(s_Unable_to_find_exit_point_1_on_p_803115b0,puVar12[0x2a] & 0xff,
                   (int)(uint)(ushort)puVar12[0x2a] >> 8);
LAB_800dd5d8:
      puVar12 = puVar12 + 0x18;
    }
  }
  __psq_l0(auStack8,uVar24);
  __psq_l1(auStack8,uVar24);
  __psq_l0(auStack24,uVar24);
  __psq_l1(auStack24,uVar24);
  __psq_l0(auStack40,uVar24);
  __psq_l1(auStack40,uVar24);
  __psq_l0(auStack56,uVar24);
  __psq_l1(auStack56,uVar24);
  __psq_l0(auStack72,uVar24);
  __psq_l1(auStack72,uVar24);
  __psq_l0(auStack88,uVar24);
  __psq_l1(auStack88,uVar24);
  __psq_l0(auStack104,uVar24);
  __psq_l1(auStack104,uVar24);
  FUN_80286110();
  return;
}

