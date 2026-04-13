// Function: FUN_800dc624
// Entry: 800dc624
// Size: 4768 bytes

/* WARNING: Removing unreachable block (ram,0x800dd8a4) */
/* WARNING: Removing unreachable block (ram,0x800dd89c) */
/* WARNING: Removing unreachable block (ram,0x800dd894) */
/* WARNING: Removing unreachable block (ram,0x800dd88c) */
/* WARNING: Removing unreachable block (ram,0x800dd884) */
/* WARNING: Removing unreachable block (ram,0x800dd87c) */
/* WARNING: Removing unreachable block (ram,0x800dd874) */
/* WARNING: Removing unreachable block (ram,0x800dc664) */
/* WARNING: Removing unreachable block (ram,0x800dc65c) */
/* WARNING: Removing unreachable block (ram,0x800dc654) */
/* WARNING: Removing unreachable block (ram,0x800dc64c) */
/* WARNING: Removing unreachable block (ram,0x800dc644) */
/* WARNING: Removing unreachable block (ram,0x800dc63c) */
/* WARNING: Removing unreachable block (ram,0x800dc634) */

void FUN_800dc624(void)

{
  bool bVar1;
  byte bVar2;
  byte bVar3;
  float fVar4;
  float fVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int *piVar10;
  int iVar11;
  undefined2 *puVar12;
  char *pcVar13;
  char cVar15;
  uint uVar14;
  int iVar16;
  byte bVar17;
  int iVar18;
  byte *pbVar19;
  int iVar20;
  char *pcVar21;
  short *psVar22;
  int iVar23;
  int iVar24;
  double in_f25;
  double in_f26;
  double in_f27;
  double dVar25;
  double dVar26;
  double in_f28;
  double dVar27;
  double in_f29;
  double dVar28;
  double dVar29;
  double in_f30;
  double dVar30;
  double dVar31;
  double in_f31;
  double dVar32;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_2c8;
  char local_2c4 [52];
  char local_290;
  byte abStack_24c [364];
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
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
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  FUN_80286824();
  pcVar21 = &DAT_803120d8;
  FUN_80059da8(local_2c4);
  iVar16 = 0;
  pcVar13 = local_2c4;
  iVar24 = 0xf;
  do {
    iVar7 = iVar16;
    if ((((*pcVar13 != *pcVar21) || (iVar7 = iVar16 + 1, pcVar13[1] != pcVar21[1])) ||
        (iVar7 = iVar16 + 2, pcVar13[2] != pcVar21[2])) ||
       (((iVar7 = iVar16 + 3, pcVar13[3] != pcVar21[3] ||
         (iVar7 = iVar16 + 4, pcVar13[4] != pcVar21[4])) ||
        ((iVar7 = iVar16 + 5, pcVar13[5] != pcVar21[5] ||
         ((iVar7 = iVar16 + 6, pcVar13[6] != pcVar21[6] ||
          (iVar7 = iVar16 + 7, pcVar13[7] != pcVar21[7])))))))) break;
    pcVar21 = pcVar21 + 8;
    pcVar13 = pcVar13 + 8;
    iVar16 = iVar16 + 8;
    iVar24 = iVar24 + -1;
    iVar7 = iVar16;
  } while (iVar24 != 0);
  if (iVar7 != 0x78) {
    FUN_80003494(0x803120d8,(uint)local_2c4,0x78);
    fVar4 = FLOAT_803e1280;
    if ((local_2c4[2] == '\0') && (local_290 == '\0')) {
      fVar4 = FLOAT_803e1284;
    }
    dVar25 = (double)fVar4;
    piVar10 = (int *)(**(code **)(*DAT_803dd71c + 0x10))(&local_2c8);
    FUN_800033a8(-0x7fc5dc70,0,0xb5);
    iVar16 = 8;
    puVar12 = &DAT_8039d748;
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
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    DAT_803de0e4 = 1;
    for (iVar16 = 0; iVar16 < local_2c8; iVar16 = iVar16 + 1) {
      iVar24 = *piVar10;
      if (*(char *)(iVar24 + 0x19) == '&') {
        uVar14 = (uint)*(byte *)(iVar24 + 3);
        iVar7 = uVar14 * 0x28;
        psVar22 = &DAT_803a0748 + uVar14 * 0x14;
        (&DAT_803a2390)[uVar14] = 1;
        local_e0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 4) ^ 0x80000000);
        dVar30 = (double)(float)((double)(float)(local_e0 - DOUBLE_803e1260) * dVar25 +
                                (double)*(float *)(iVar24 + 8));
        local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 5) ^ 0x80000000);
        dVar32 = (double)(float)((double)(float)(local_d8 - DOUBLE_803e1260) * dVar25 +
                                (double)*(float *)(iVar24 + 0x10));
        local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 6) ^ 0x80000000);
        dVar28 = (double)(float)((double)(float)(local_d0 - DOUBLE_803e1260) * dVar25 +
                                (double)*(float *)(iVar24 + 8));
        local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 7) ^ 0x80000000);
        dVar29 = (double)(float)((double)(float)(local_c8 - DOUBLE_803e1260) * dVar25 +
                                (double)*(float *)(iVar24 + 0x10));
        dVar31 = (double)(float)(dVar29 - dVar32);
        dVar27 = (double)(float)(dVar30 - dVar28);
        dVar26 = FUN_80293900((double)(float)(dVar31 * dVar31 + (double)(float)(dVar27 * dVar27)));
        if (dVar26 != (double)FLOAT_803e1270) {
          dVar31 = (double)(float)(dVar31 / dVar26);
          dVar27 = (double)(float)(dVar27 / dVar26);
        }
        dVar26 = (double)FLOAT_803e127c;
        iVar23 = (int)(dVar26 * dVar31);
        local_c8 = (double)(longlong)iVar23;
        *psVar22 = (short)iVar23;
        iVar23 = (int)(dVar26 * dVar27);
        local_d0 = (double)(longlong)iVar23;
        (&DAT_803a074a)[uVar14 * 0x14] = (short)iVar23;
        dVar26 = DOUBLE_803e1260;
        local_d8 = (double)CONCAT44(0x43300000,(int)*psVar22 ^ 0x80000000);
        local_e0 = (double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_803a074a)[uVar14 * 0x14] ^ 0x80000000);
        (&DAT_803a0758)[uVar14 * 10] =
             -(float)((double)(float)(local_d8 - DOUBLE_803e1260) * dVar30 +
                     (double)(float)((double)(float)(local_e0 - DOUBLE_803e1260) * dVar32));
        local_c0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x30) ^ 0x80000000);
        dVar30 = (double)(float)((double)(float)(local_c0 - dVar26) * dVar25 +
                                (double)*(float *)(iVar24 + 8));
        local_b8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x31) ^ 0x80000000);
        dVar32 = (double)(float)((double)(float)(local_b8 - dVar26) * dVar25 +
                                (double)*(float *)(iVar24 + 0x10));
        dVar27 = (double)(float)(dVar32 - dVar29);
        dVar31 = (double)(float)(dVar28 - dVar30);
        dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 + (double)(float)(dVar31 * dVar31)));
        if (dVar26 != (double)FLOAT_803e1270) {
          dVar27 = (double)(float)(dVar27 / dVar26);
          dVar31 = (double)(float)(dVar31 / dVar26);
        }
        dVar26 = (double)FLOAT_803e127c;
        iVar23 = (int)(dVar26 * dVar27);
        local_b8 = (double)(longlong)iVar23;
        *(short *)(&DAT_803a074c + iVar7) = (short)iVar23;
        iVar23 = (int)(dVar26 * dVar31);
        local_c0 = (double)(longlong)iVar23;
        *(short *)(&DAT_803a074e + iVar7) = (short)iVar23;
        dVar26 = DOUBLE_803e1260;
        local_c8 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803a074c + iVar7) ^ 0x80000000);
        local_d0 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803a074e + iVar7) ^ 0x80000000);
        *(float *)(&DAT_803a075c + iVar7) =
             -(float)((double)(float)(local_c8 - DOUBLE_803e1260) * dVar28 +
                     (double)(float)((double)(float)(local_d0 - DOUBLE_803e1260) * dVar29));
        local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x32) ^ 0x80000000);
        dVar29 = (double)(float)((double)(float)(local_d8 - dVar26) * dVar25 +
                                (double)*(float *)(iVar24 + 8));
        local_e0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x33) ^ 0x80000000);
        dVar28 = (double)(float)((double)(float)(local_e0 - dVar26) * dVar25 +
                                (double)*(float *)(iVar24 + 0x10));
        dVar27 = (double)(float)(dVar28 - dVar32);
        dVar31 = (double)(float)(dVar30 - dVar29);
        dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 + (double)(float)(dVar31 * dVar31)));
        if (dVar26 != (double)FLOAT_803e1270) {
          dVar27 = (double)(float)(dVar27 / dVar26);
          dVar31 = (double)(float)(dVar31 / dVar26);
        }
        dVar26 = (double)FLOAT_803e127c;
        iVar23 = (int)(dVar26 * dVar27);
        local_b8 = (double)(longlong)iVar23;
        *(short *)(&DAT_803a0750 + iVar7) = (short)iVar23;
        iVar23 = (int)(dVar26 * dVar31);
        local_c0 = (double)(longlong)iVar23;
        *(short *)(&DAT_803a0752 + iVar7) = (short)iVar23;
        dVar26 = DOUBLE_803e1260;
        local_c8 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803a0750 + iVar7) ^ 0x80000000);
        local_d0 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803a0752 + iVar7) ^ 0x80000000);
        *(float *)(&DAT_803a0760 + iVar7) =
             -(float)((double)(float)(local_c8 - DOUBLE_803e1260) * dVar30 +
                     (double)(float)((double)(float)(local_d0 - DOUBLE_803e1260) * dVar32));
        local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 5) ^ 0x80000000);
        dVar27 = (double)(float)((double)(float)((double)(float)(local_d8 - dVar26) * dVar25 +
                                                (double)*(float *)(iVar24 + 0x10)) - dVar28);
        local_e0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 4) ^ 0x80000000);
        dVar31 = (double)(float)(dVar29 - (double)(float)((double)(float)(local_e0 - dVar26) *
                                                          dVar25 + (double)*(float *)(iVar24 + 8)));
        dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 + (double)(float)(dVar31 * dVar31)));
        if (dVar26 != (double)FLOAT_803e1270) {
          dVar27 = (double)(float)(dVar27 / dVar26);
          dVar31 = (double)(float)(dVar31 / dVar26);
        }
        dVar26 = (double)FLOAT_803e127c;
        iVar23 = (int)(dVar26 * dVar27);
        local_b8 = (double)(longlong)iVar23;
        *(short *)(&DAT_803a0754 + iVar7) = (short)iVar23;
        iVar23 = (int)(dVar26 * dVar31);
        local_c0 = (double)(longlong)iVar23;
        *(short *)(&DAT_803a0756 + iVar7) = (short)iVar23;
        dVar26 = DOUBLE_803e1260;
        local_c8 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803a0754 + iVar7) ^ 0x80000000);
        local_d0 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803a0756 + iVar7) ^ 0x80000000);
        *(float *)(&DAT_803a0764 + iVar7) =
             -(float)((double)(float)(local_c8 - DOUBLE_803e1260) * dVar29 +
                     (double)(float)((double)(float)(local_d0 - DOUBLE_803e1260) * dVar28));
        fVar4 = FLOAT_803e1250;
        local_d8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x18) ^ 0x80000000);
        iVar7 = (int)(FLOAT_803e1250 * (float)(local_d8 - dVar26) + *(float *)(iVar24 + 0xc));
        local_e0 = (double)(longlong)iVar7;
        (&DAT_803a0768)[uVar14 * 0x14] = (short)iVar7;
        local_b0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x1a) ^ 0x80000000);
        iVar7 = (int)-(fVar4 * (float)(local_b0 - dVar26) - *(float *)(iVar24 + 0xc));
        local_a8 = (double)(longlong)iVar7;
        (&DAT_803a076a)[uVar14 * 0x14] = (short)iVar7;
        iVar23 = 0;
        iVar7 = iVar24;
        do {
          iVar20 = iVar23 + 0x24;
          *(undefined *)((int)psVar22 + iVar20) = 0;
          if ((-1 < *(int *)(iVar7 + 0x1c)) &&
             (iVar11 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar11 != 0)) {
            bVar2 = *(byte *)(iVar24 + 3);
            bVar3 = *(byte *)(iVar11 + 3);
            if (bVar2 < bVar3) {
              sVar6 = CONCAT11(bVar3,bVar2);
            }
            else {
              sVar6 = CONCAT11(bVar2,bVar3);
            }
            cVar15 = '\x01';
            iVar8 = DAT_803de0e4 + -1;
            puVar12 = &DAT_8039d748;
            if (1 < DAT_803de0e4) {
              do {
                if (sVar6 == puVar12[0x2a]) {
                  *(char *)((int)psVar22 + iVar20) = cVar15;
                  break;
                }
                cVar15 = cVar15 + '\x01';
                iVar8 = iVar8 + -1;
                puVar12 = puVar12 + 0x18;
              } while (iVar8 != 0);
            }
            iVar8 = DAT_803de0e4;
            if (*(char *)((int)psVar22 + iVar20) == '\0') {
              iVar18 = 0;
              iVar9 = *(int *)(iVar24 + 0x14);
              if ((((*(int *)(iVar11 + 0x1c) != iVar9) &&
                   (iVar18 = 1, *(int *)(iVar11 + 0x20) != iVar9)) &&
                  (iVar18 = 2, *(int *)(iVar11 + 0x24) != iVar9)) &&
                 (iVar18 = 3, *(int *)(iVar11 + 0x28) != iVar9)) {
                iVar18 = 4;
              }
              *(char *)((int)psVar22 + iVar20) = (char)DAT_803de0e4;
              (&DAT_8039d76c)[iVar8 * 0x18] = sVar6;
              fVar4 = FLOAT_803e1288;
              abStack_24c[iVar8 * 2] = *(byte *)(iVar24 + 3);
              abStack_24c[iVar8 * 2 + 1] = *(byte *)(iVar11 + 3);
              local_a8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x34) ^ 0x80000000);
              dVar29 = (double)(float)((double)(float)(local_a8 - DOUBLE_803e1260) * dVar25 +
                                      (double)*(float *)(iVar24 + 8));
              local_b0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x35) ^ 0x80000000);
              dVar28 = (double)(float)((double)(float)(local_b0 - DOUBLE_803e1260) * dVar25 +
                                      (double)*(float *)(iVar24 + 0x10));
              local_b8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x36) ^ 0x80000000);
              dVar30 = (double)(float)((double)(float)(local_b8 - DOUBLE_803e1260) * dVar25 +
                                      (double)*(float *)(iVar24 + 8));
              local_c0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x37) ^ 0x80000000);
              dVar32 = (double)(float)((double)(float)(local_c0 - DOUBLE_803e1260) * dVar25 +
                                      (double)*(float *)(iVar24 + 0x10));
              iVar20 = (int)((float)(dVar29 + dVar30) * FLOAT_803e1288);
              local_c8 = (double)(longlong)iVar20;
              (&DAT_8039d76e)[iVar8 * 0x18] = (short)iVar20;
              iVar20 = (int)((float)(dVar28 + dVar32) * fVar4);
              local_d0 = (double)(longlong)iVar20;
              (&DAT_8039d770)[iVar8 * 0x18] = (short)iVar20;
              dVar27 = (double)(float)(dVar32 - dVar28);
              dVar31 = (double)(float)(dVar29 - dVar30);
              dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 +
                                                   (double)(float)(dVar31 * dVar31)));
              if (dVar26 != (double)FLOAT_803e1270) {
                dVar27 = (double)(float)(dVar27 / dVar26);
                dVar31 = (double)(float)(dVar31 / dVar26);
              }
              dVar26 = (double)FLOAT_803e127c;
              iVar20 = (int)(dVar26 * dVar27);
              local_a8 = (double)(longlong)iVar20;
              (&DAT_8039d748)[iVar8 * 0x18] = (short)iVar20;
              iVar20 = (int)(dVar26 * dVar31);
              local_b0 = (double)(longlong)iVar20;
              (&DAT_8039d74a)[iVar8 * 0x18] = (short)iVar20;
              dVar26 = DOUBLE_803e1260;
              local_b8 = (double)CONCAT44(0x43300000,
                                          (int)(short)(&DAT_8039d748)[iVar8 * 0x18] ^ 0x80000000);
              local_c0 = (double)CONCAT44(0x43300000,
                                          (int)(short)(&DAT_8039d74a)[iVar8 * 0x18] ^ 0x80000000);
              (&DAT_8039d758)[iVar8 * 0xc] =
                   -(float)((double)(float)(local_b8 - DOUBLE_803e1260) * dVar29 +
                           (double)(float)((double)(float)(local_c0 - DOUBLE_803e1260) * dVar28));
              iVar8 = iVar11 + iVar18 * 4;
              local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar8 + 0x34) ^ 0x80000000);
              dVar29 = (double)(float)((double)(float)(local_c8 - dVar26) * dVar25 +
                                      (double)*(float *)(iVar11 + 8));
              local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar8 + 0x35) ^ 0x80000000);
              dVar28 = (double)(float)((double)(float)(local_d0 - dVar26) * dVar25 +
                                      (double)*(float *)(iVar11 + 0x10));
              iVar20 = DAT_803de0e4 * 0x30;
              dVar27 = (double)(float)(dVar28 - dVar32);
              dVar31 = (double)(float)(dVar30 - dVar29);
              dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 +
                                                   (double)(float)(dVar31 * dVar31)));
              if (dVar26 != (double)FLOAT_803e1270) {
                dVar27 = (double)(float)(dVar27 / dVar26);
                dVar31 = (double)(float)(dVar31 / dVar26);
              }
              dVar26 = (double)FLOAT_803e127c;
              iVar9 = (int)(dVar26 * dVar27);
              local_a8 = (double)(longlong)iVar9;
              *(short *)(iVar20 + -0x7fc628b4) = (short)iVar9;
              iVar9 = (int)(dVar26 * dVar31);
              local_b0 = (double)(longlong)iVar9;
              *(short *)(iVar20 + -0x7fc628b2) = (short)iVar9;
              dVar26 = DOUBLE_803e1260;
              local_b8 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(iVar20 + -0x7fc628b4) ^ 0x80000000);
              local_c0 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(iVar20 + -0x7fc628b2) ^ 0x80000000);
              *(float *)(iVar20 + -0x7fc628a4) =
                   -(float)((double)(float)(local_b8 - DOUBLE_803e1260) * dVar30 +
                           (double)(float)((double)(float)(local_c0 - DOUBLE_803e1260) * dVar32));
              fVar4 = FLOAT_803e1288;
              iVar9 = DAT_803de0e4;
              local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar8 + 0x36) ^ 0x80000000);
              dVar30 = (double)(float)((double)(float)(local_c8 - dVar26) * dVar25 +
                                      (double)*(float *)(iVar11 + 8));
              local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar8 + 0x37) ^ 0x80000000);
              dVar32 = (double)(float)((double)(float)(local_d0 - dVar26) * dVar25 +
                                      (double)*(float *)(iVar11 + 0x10));
              iVar20 = (int)((float)(dVar29 + dVar30) * FLOAT_803e1288);
              local_d8 = (double)(longlong)iVar20;
              iVar8 = DAT_803de0e4 * 0x30;
              (&DAT_8039d772)[DAT_803de0e4 * 0x18] = (short)iVar20;
              iVar20 = (int)((float)(dVar28 + dVar32) * fVar4);
              local_e0 = (double)(longlong)iVar20;
              (&DAT_8039d774)[iVar9 * 0x18] = (short)iVar20;
              dVar27 = (double)(float)(dVar32 - dVar28);
              dVar31 = (double)(float)(dVar29 - dVar30);
              dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 +
                                                   (double)(float)(dVar31 * dVar31)));
              if (dVar26 != (double)FLOAT_803e1270) {
                dVar27 = (double)(float)(dVar27 / dVar26);
                dVar31 = (double)(float)(dVar31 / dVar26);
              }
              dVar26 = (double)FLOAT_803e127c;
              iVar20 = (int)(dVar26 * dVar27);
              local_a8 = (double)(longlong)iVar20;
              *(short *)(iVar8 + -0x7fc628b0) = (short)iVar20;
              iVar20 = (int)(dVar26 * dVar31);
              local_b0 = (double)(longlong)iVar20;
              *(short *)(iVar8 + -0x7fc628ae) = (short)iVar20;
              dVar26 = DOUBLE_803e1260;
              local_b8 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(iVar8 + -0x7fc628b0) ^ 0x80000000);
              local_c0 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(iVar8 + -0x7fc628ae) ^ 0x80000000);
              *(float *)(iVar8 + -0x7fc628a0) =
                   -(float)((double)(float)(local_b8 - DOUBLE_803e1260) * dVar29 +
                           (double)(float)((double)(float)(local_c0 - DOUBLE_803e1260) * dVar28));
              iVar20 = DAT_803de0e4 * 0x30;
              local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x35) ^ 0x80000000);
              dVar27 = (double)(float)((double)(float)((double)(float)(local_c8 - dVar26) * dVar25 +
                                                      (double)*(float *)(iVar24 + 0x10)) - dVar32);
              local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar7 + 0x34) ^ 0x80000000);
              dVar31 = (double)(float)(dVar30 - (double)(float)((double)(float)(local_d0 - dVar26) *
                                                                dVar25 + (double)*(float *)(iVar24 +
                                                                                           8)));
              dVar26 = FUN_80293900((double)(float)(dVar27 * dVar27 +
                                                   (double)(float)(dVar31 * dVar31)));
              if (dVar26 != (double)FLOAT_803e1270) {
                dVar27 = (double)(float)(dVar27 / dVar26);
                dVar31 = (double)(float)(dVar31 / dVar26);
              }
              dVar26 = (double)FLOAT_803e127c;
              *(short *)(iVar20 + -0x7fc628ac) = (short)(int)(dVar26 * dVar27);
              *(short *)(iVar20 + -0x7fc628aa) = (short)(int)(dVar26 * dVar31);
              dVar26 = DOUBLE_803e1260;
              local_b8 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(iVar20 + -0x7fc628ac) ^ 0x80000000);
              local_c0 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(iVar20 + -0x7fc628aa) ^ 0x80000000);
              *(float *)(iVar20 + -0x7fc6289c) =
                   -(float)((double)(float)(local_b8 - DOUBLE_803e1260) * dVar30 +
                           (double)(float)((double)(float)(local_c0 - DOUBLE_803e1260) * dVar32));
              local_c8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x18) ^ 0x80000000);
              fVar5 = FLOAT_803e1250 * (float)(local_c8 - dVar26) + *(float *)(iVar24 + 0xc);
              local_d0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x18) ^ 0x80000000);
              fVar4 = FLOAT_803e1250 * (float)(local_d0 - dVar26) + *(float *)(iVar11 + 0xc);
              if (fVar5 <= fVar4) {
                (&DAT_8039d768)[DAT_803de0e4 * 0x18] = (short)(int)fVar4;
              }
              else {
                (&DAT_8039d768)[DAT_803de0e4 * 0x18] = (short)(int)fVar5;
              }
              local_a8 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar24 + 0x1a) ^ 0x80000000);
              fVar4 = -(FLOAT_803e1250 * (float)(local_a8 - DOUBLE_803e1260) -
                       *(float *)(iVar24 + 0xc));
              local_b0 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar11 + 0x1a) ^ 0x80000000);
              fVar5 = -(FLOAT_803e1250 * (float)(local_b0 - DOUBLE_803e1260) -
                       *(float *)(iVar11 + 0xc));
              if (fVar5 <= fVar4) {
                iVar20 = (int)fVar5;
                local_a8 = (double)(longlong)iVar20;
                (&DAT_8039d76a)[DAT_803de0e4 * 0x18] = (short)iVar20;
              }
              else {
                iVar20 = (int)fVar4;
                local_a8 = (double)(longlong)iVar20;
                (&DAT_8039d76a)[DAT_803de0e4 * 0x18] = (short)iVar20;
              }
              DAT_803de0e4 = DAT_803de0e4 + 1;
            }
          }
          iVar7 = iVar7 + 4;
          iVar23 = iVar23 + 1;
        } while (iVar23 < 4);
      }
      piVar10 = piVar10 + 1;
    }
    pbVar19 = abStack_24c;
    dVar26 = (double)FLOAT_803e1270;
    dVar31 = (double)FLOAT_803e128c;
    dVar25 = DOUBLE_803e1260;
    puVar12 = &DAT_8039d748;
    for (iVar16 = 1; pbVar19 = pbVar19 + 2, iVar16 < DAT_803de0e4; iVar16 = iVar16 + 1) {
      bVar2 = *pbVar19;
      bVar3 = pbVar19[1];
      local_a8 = (double)CONCAT44(0x43300000,
                                  (int)(short)puVar12[0x2d] - (int)(short)puVar12[0x2b] ^ 0x80000000
                                 );
      dVar27 = (double)(float)(local_a8 - dVar25);
      local_b0 = (double)CONCAT44(0x43300000,
                                  (int)(short)puVar12[0x2e] - (int)(short)puVar12[0x2c] ^ 0x80000000
                                 );
      dVar29 = (double)(float)(local_b0 - dVar25);
      iVar24 = 0;
      do {
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2c] ^ 0x80000000);
        dVar28 = local_a8 - dVar25;
        local_b0 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2b] ^ 0x80000000);
        dVar30 = local_b0 - dVar25;
        uVar14 = 0;
        for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
          local_a8 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar2 * 0x14 + (uVar14 & 0xff)] ^
                                      0x80000000);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar2 * 0x14 + (uVar14 & 0xff) + 1] ^
                                      0x80000000);
          if (dVar26 < (double)(*(float *)(&DAT_803a0748 + (uint)bVar2 * 0x14 + (uint)bVar17 * 2 + 8
                                          ) +
                               (float)dVar30 * (float)(local_a8 - dVar25) +
                               (float)dVar28 * (float)(local_b0 - dVar25))) break;
          uVar14 = uVar14 + 2;
        }
        if (bVar17 == 4) goto LAB_800dd65c;
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2c] ^ 0x80000000);
        dVar28 = local_a8 - dVar25;
        local_b0 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2b] ^ 0x80000000);
        dVar30 = local_b0 - dVar25;
        uVar14 = 0;
        for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
          local_a8 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar3 * 0x14 + (uVar14 & 0xff)] ^
                                      0x80000000);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar3 * 0x14 + (uVar14 & 0xff) + 1] ^
                                      0x80000000);
          if (dVar26 < (double)(*(float *)(&DAT_803a0748 + (uint)bVar3 * 0x14 + (uint)bVar17 * 2 + 8
                                          ) +
                               (float)dVar30 * (float)(local_a8 - dVar25) +
                               (float)dVar28 * (float)(local_b0 - dVar25))) break;
          uVar14 = uVar14 + 2;
        }
        if (bVar17 == 4) goto LAB_800dd65c;
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2b] ^ 0x80000000);
        iVar7 = (int)((float)(local_a8 - dVar25) + (float)(dVar27 / dVar31));
        local_b0 = (double)(longlong)iVar7;
        puVar12[0x2b] = (short)iVar7;
        local_b8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2c] ^ 0x80000000);
        iVar7 = (int)((float)(local_b8 - dVar25) + (float)(dVar29 / dVar31));
        local_c0 = (double)(longlong)iVar7;
        puVar12[0x2c] = (short)iVar7;
        bVar1 = iVar24 != 100;
        iVar24 = iVar24 + 1;
      } while (bVar1);
      FUN_8007d858();
LAB_800dd65c:
      iVar24 = 0;
      do {
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2e] ^ 0x80000000);
        dVar28 = local_a8 - dVar25;
        local_b0 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2d] ^ 0x80000000);
        dVar30 = local_b0 - dVar25;
        uVar14 = 0;
        for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
          local_a8 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar2 * 0x14 + (uVar14 & 0xff)] ^
                                      0x80000000);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar2 * 0x14 + (uVar14 & 0xff) + 1] ^
                                      0x80000000);
          if (dVar26 < (double)(*(float *)(&DAT_803a0748 + (uint)bVar2 * 0x14 + (uint)bVar17 * 2 + 8
                                          ) +
                               (float)dVar30 * (float)(local_a8 - dVar25) +
                               (float)dVar28 * (float)(local_b0 - dVar25))) break;
          uVar14 = uVar14 + 2;
        }
        if (bVar17 == 4) goto LAB_800dd85c;
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2e] ^ 0x80000000);
        dVar28 = local_a8 - dVar25;
        local_b0 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2d] ^ 0x80000000);
        dVar30 = local_b0 - dVar25;
        uVar14 = 0;
        for (bVar17 = 0; bVar17 < 4; bVar17 = bVar17 + 1) {
          local_a8 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar3 * 0x14 + (uVar14 & 0xff)] ^
                                      0x80000000);
          local_b0 = (double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0748)
                                                  [(uint)bVar3 * 0x14 + (uVar14 & 0xff) + 1] ^
                                      0x80000000);
          if (dVar26 < (double)(*(float *)(&DAT_803a0748 + (uint)bVar3 * 0x14 + (uint)bVar17 * 2 + 8
                                          ) +
                               (float)dVar30 * (float)(local_a8 - dVar25) +
                               (float)dVar28 * (float)(local_b0 - dVar25))) break;
          uVar14 = uVar14 + 2;
        }
        if (bVar17 == 4) goto LAB_800dd85c;
        local_a8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2d] ^ 0x80000000);
        iVar7 = (int)((float)(local_a8 - dVar25) - (float)(dVar27 / dVar31));
        local_b0 = (double)(longlong)iVar7;
        puVar12[0x2d] = (short)iVar7;
        local_b8 = (double)CONCAT44(0x43300000,(int)(short)puVar12[0x2e] ^ 0x80000000);
        iVar7 = (int)((float)(local_b8 - dVar25) - (float)(dVar29 / dVar31));
        local_c0 = (double)(longlong)iVar7;
        puVar12[0x2e] = (short)iVar7;
        bVar1 = iVar24 != 100;
        iVar24 = iVar24 + 1;
      } while (bVar1);
      FUN_8007d858();
LAB_800dd85c:
      puVar12 = puVar12 + 0x18;
    }
  }
  FUN_80286870();
  return;
}

