// Function: FUN_8010e5b4
// Entry: 8010e5b4
// Size: 3212 bytes

/* WARNING: Removing unreachable block (ram,0x8010f218) */
/* WARNING: Removing unreachable block (ram,0x8010f208) */
/* WARNING: Removing unreachable block (ram,0x8010e644) */
/* WARNING: Removing unreachable block (ram,0x8010f210) */
/* WARNING: Removing unreachable block (ram,0x8010f220) */

void FUN_8010e5b4(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  short *psVar4;
  int iVar5;
  short *psVar6;
  uint uVar7;
  int iVar8;
  char cVar12;
  char cVar13;
  short sVar10;
  short *psVar9;
  short sVar11;
  int iVar14;
  undefined4 uVar15;
  double dVar16;
  double dVar17;
  undefined8 uVar18;
  double dVar19;
  undefined8 in_f28;
  double dVar20;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar21;
  undefined8 in_f31;
  double local_98;
  double local_88;
  undefined auStack56 [16];
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
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  psVar4 = (short *)FUN_802860d4();
  dVar20 = (double)FLOAT_803e1a28;
  iVar14 = *(int *)(psVar4 + 0x52);
  iVar5 = FUN_8002e0b4(0x42fff);
  psVar6 = (short *)FUN_8002e0b4(0x4325b);
  uVar7 = FUN_80014ee8(0);
  FUN_80014e70(0);
  if (*(char *)(DAT_803dd588 + 2) == '\x01') {
    psVar9 = (short *)FUN_8002e0b4(0x43077);
    if (*(char *)((int)DAT_803dd588 + 9) == *(char *)(DAT_803dd588 + 2)) {
      if ((*(char *)((int)DAT_803dd588 + 0x15) < '\0') &&
         (iVar8 = (**(code **)(*DAT_803dca4c + 0x14))(), iVar8 != 0)) {
        FUN_8012ddb8(1);
        (**(code **)(*DAT_803dca4c + 0xc))(0xc,1);
        *(byte *)((int)DAT_803dd588 + 0x15) = *(byte *)((int)DAT_803dd588 + 0x15) & 0x7f;
        iVar8 = FUN_8002e0b4(0x43077);
        *(undefined *)(*(int *)(iVar8 + 0xb8) + 0x27d) = 1;
      }
      if (-1 < *(char *)((int)DAT_803dd588 + 0x15)) {
        *(short *)((int)DAT_803dd588 + 10) = *(short *)((int)DAT_803dd588 + 10) + -1;
        if (*(short *)((int)DAT_803dd588 + 10) < 1) {
          *(undefined2 *)((int)DAT_803dd588 + 10) = 1;
        }
        sVar10 = FUN_800217c0((double)(*(float *)(iVar5 + 0x18) - *(float *)(iVar14 + 0x18)),
                              (double)(*(float *)(iVar5 + 0x20) - *(float *)(iVar14 + 0x20)));
        sVar11 = (-sVar10 + -0x308f) - *psVar4;
        if (0x8000 < sVar11) {
          sVar11 = sVar11 + 1;
        }
        if (sVar11 < -0x8000) {
          sVar11 = sVar11 + -1;
        }
        *psVar4 = *psVar4 + sVar11 / *(short *)((int)DAT_803dd588 + 10);
        sVar11 = -psVar4[1] + 2000;
        if (0x8000 < sVar11) {
          sVar11 = -psVar4[1] + 0x7d1;
        }
        if (sVar11 < -0x8000) {
          sVar11 = sVar11 + -1;
        }
        psVar4[1] = psVar4[1] + sVar11 / *(short *)((int)DAT_803dd588 + 10);
        dVar20 = (double)((FLOAT_803e1a48 *
                          (float)((double)CONCAT44(0x43300000,(uint)(ushort)(-sVar10 + 0xc624)) -
                                 DOUBLE_803e1a78)) / FLOAT_803e1a4c);
        dVar21 = (double)FUN_80294204(dVar20);
        dVar21 = -dVar21;
        dVar16 = (double)FUN_80293e80(dVar20);
        dVar19 = (double)FUN_80294204((double)FLOAT_803e1a54);
        dVar17 = (double)FUN_80293e80((double)FLOAT_803e1a54);
        dVar20 = DOUBLE_803e1a70;
        dVar19 = (double)(float)((double)FLOAT_803e1a58 * dVar19);
        fVar2 = FLOAT_803e1a5c +
                *(float *)(iVar14 + 0x1c) + (float)((double)FLOAT_803e1a58 * dVar17);
        fVar1 = *(float *)(iVar14 + 0x20);
        *(float *)(psVar4 + 0xc) =
             *(float *)(psVar4 + 0xc) -
             (*(float *)(psVar4 + 0xc) - (*(float *)(iVar14 + 0x18) + (float)(dVar19 * dVar16))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803dd588 + 10) ^ 0x80000000) -
                    DOUBLE_803e1a70);
        *(float *)(psVar4 + 0xe) =
             *(float *)(psVar4 + 0xe) -
             (*(float *)(psVar4 + 0xe) - fVar2) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803dd588 + 10) ^ 0x80000000) - dVar20
                    );
        *(float *)(psVar4 + 0x10) =
             *(float *)(psVar4 + 0x10) -
             (*(float *)(psVar4 + 0x10) - (fVar1 + (float)(dVar19 * dVar21))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803dd588 + 10) ^ 0x80000000) - dVar20
                    );
        uVar7 = (int)*psVar4 + 5000U & 0xffff;
        iVar5 = FUN_8005cdb0();
        if (iVar5 != 0) {
          uVar7 = uVar7 + 0x514 & 0xffff;
        }
        local_88 = (double)CONCAT44(0x43300000,uVar7);
        dVar21 = (double)((FLOAT_803e1a48 * (float)(local_88 - DOUBLE_803e1a78)) / FLOAT_803e1a4c);
        dVar20 = (double)FUN_80294204(dVar21);
        dVar21 = (double)FUN_80293e80(dVar21);
        dVar16 = (double)FLOAT_803e1a60;
        *(float *)(psVar9 + 6) = (float)(dVar16 * -dVar21 + (double)*(float *)(psVar4 + 0xc));
        *(float *)(psVar9 + 8) =
             *(float *)(psVar4 + 0xe) +
             *(float *)(&DAT_80319df8 + *(char *)((int)psVar9 + 0xad) * 4);
        *(float *)(psVar9 + 10) = (float)(dVar16 * dVar20 + (double)*(float *)(psVar4 + 0x10));
        *psVar9 = -3000 - (short)uVar7;
      }
    }
    else {
      (**(code **)(*DAT_803dca4c + 8))(0xc,1);
      *(undefined2 *)((int)DAT_803dd588 + 10) = 2;
      *(byte *)((int)DAT_803dd588 + 0x15) = *(byte *)((int)DAT_803dd588 + 0x15) & 0x7f | 0x80;
    }
  }
  else if (*(char *)(DAT_803dd588 + 2) == '\0') {
    if (*(char *)((int)DAT_803dd588 + 9) == '\0') {
      if ((*(char *)((int)DAT_803dd588 + 0x15) < '\0') &&
         (iVar8 = (**(code **)(*DAT_803dca4c + 0x14))(), iVar8 != 0)) {
        FUN_8012ddb8(0);
        (**(code **)(*DAT_803dca4c + 0xc))(0xc,1);
        *(byte *)((int)DAT_803dd588 + 0x15) = *(byte *)((int)DAT_803dd588 + 0x15) & 0x7f;
        iVar8 = FUN_8002e0b4(0x43077);
        *(undefined *)(*(int *)(iVar8 + 0xb8) + 0x27d) = 0;
      }
      if (-1 < *(char *)((int)DAT_803dd588 + 0x15)) {
        *(short *)((int)DAT_803dd588 + 10) = *(short *)((int)DAT_803dd588 + 10) + -1;
        if (*(short *)((int)DAT_803dd588 + 10) < 1) {
          *(undefined2 *)((int)DAT_803dd588 + 10) = 1;
        }
        if ((uVar7 & 8) != 0) {
          dVar20 = (double)(FLOAT_803e1a2c * *DAT_803dd588);
        }
        if ((uVar7 & 4) != 0) {
          dVar20 = (double)(FLOAT_803e1a30 * *DAT_803dd588);
        }
        dVar21 = dVar20;
        if (dVar20 < (double)FLOAT_803e1a28) {
          dVar21 = -dVar20;
        }
        dVar19 = (double)DAT_803dd588[1];
        dVar16 = dVar19;
        if (dVar19 < (double)FLOAT_803e1a28) {
          dVar16 = -dVar19;
        }
        fVar1 = FLOAT_803e1a38;
        if (dVar21 < dVar16) {
          fVar1 = FLOAT_803e1a34;
        }
        DAT_803dd588[1] = fVar1 * (float)(dVar20 - dVar19) + DAT_803dd588[1];
        *DAT_803dd588 = *DAT_803dd588 + DAT_803dd588[1];
        if (*DAT_803dd588 < FLOAT_803e1a3c) {
          *DAT_803dd588 = FLOAT_803e1a3c;
        }
        if (FLOAT_803e1a40 < *DAT_803dd588) {
          *DAT_803dd588 = FLOAT_803e1a40;
        }
        cVar12 = FUN_80014c18(0);
        cVar13 = FUN_80014bc4(0);
        if (*(char *)(DAT_803dd588 + 5) != '\0') {
          iVar8 = FUN_8002e0b4(DAT_803dd588[4]);
          dVar20 = (double)(*(float *)(iVar8 + 0x18) - *(float *)(iVar5 + 0x18));
          dVar21 = (double)(*(float *)(iVar8 + 0x20) - *(float *)(iVar5 + 0x20));
          sVar11 = FUN_800217c0(dVar20,dVar21);
          *(short *)(DAT_803dd588 + 3) = -0x8000 - sVar11;
          sVar11 = *(short *)(DAT_803dd588 + 3) - *psVar4;
          if (0x8000 < sVar11) {
            sVar11 = sVar11 + 1;
          }
          if (sVar11 < -0x8000) {
            sVar11 = sVar11 + -1;
          }
          *psVar4 = *psVar4 + (short)((int)sVar11 / (int)(uint)*(byte *)(DAT_803dd588 + 5));
          uVar18 = FUN_802931a0((double)(float)(dVar20 * dVar20 + (double)(float)(dVar21 * dVar21)))
          ;
          sVar11 = FUN_800217c0(uVar18,(double)(*(float *)(iVar8 + 0x1c) - *(float *)(iVar5 + 0x1c))
                               );
          *(short *)(DAT_803dd588 + 3) = 0x47d0 - sVar11;
          sVar11 = *(short *)(DAT_803dd588 + 3) - psVar4[1];
          if (0x8000 < sVar11) {
            sVar11 = sVar11 + 1;
          }
          if (sVar11 < -0x8000) {
            sVar11 = sVar11 + -1;
          }
          psVar4[1] = psVar4[1] + (short)((int)sVar11 / (int)(uint)*(byte *)(DAT_803dd588 + 5));
          *DAT_803dd588 =
               *DAT_803dd588 +
               (float)((double)CONCAT44(0x43300000,
                                        (int)(short)(int)(FLOAT_803e1a44 - *DAT_803dd588) /
                                        (int)(uint)*(byte *)(DAT_803dd588 + 5) ^ 0x80000000) -
                      DOUBLE_803e1a70);
          *(char *)(DAT_803dd588 + 5) = *(char *)(DAT_803dd588 + 5) + -1;
        }
        *psVar4 = *psVar4 + cVar12 * 3;
        psVar4[1] = psVar4[1] + cVar13 * 3;
        if (12000 < psVar4[1]) {
          psVar4[1] = 12000;
        }
        if (psVar4[1] < -12000) {
          psVar4[1] = -12000;
        }
        dVar21 = (double)FUN_80294204((double)((FLOAT_803e1a48 *
                                               (float)((double)CONCAT44(0x43300000,
                                                                        (int)*psVar4 ^ 0x80000000) -
                                                      DOUBLE_803e1a70)) / FLOAT_803e1a4c));
        dVar21 = -dVar21;
        local_98 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
        dVar16 = (double)FUN_80293e80((double)((FLOAT_803e1a48 * (float)(local_98 - DOUBLE_803e1a70)
                                               ) / FLOAT_803e1a4c));
        local_88 = (double)CONCAT44(0x43300000,(int)psVar4[1] + 800U ^ 0x80000000);
        dVar19 = (double)FUN_80294204((double)((FLOAT_803e1a48 * (float)(local_88 - DOUBLE_803e1a70)
                                               ) / FLOAT_803e1a4c));
        dVar17 = (double)FUN_80293e80((double)((FLOAT_803e1a48 *
                                               (float)((double)CONCAT44(0x43300000,
                                                                        (int)psVar4[1] + 800U ^
                                                                        0x80000000) -
                                                      DOUBLE_803e1a70)) / FLOAT_803e1a4c));
        dVar20 = DOUBLE_803e1a70;
        fVar1 = *DAT_803dd588;
        dVar19 = (double)(float)((double)fVar1 * dVar19);
        fVar3 = FLOAT_803e1a50 + *(float *)(iVar14 + 0x1c);
        fVar2 = *(float *)(iVar14 + 0x20);
        *(float *)(psVar4 + 0xc) =
             *(float *)(psVar4 + 0xc) -
             (*(float *)(psVar4 + 0xc) - (*(float *)(iVar14 + 0x18) + (float)(dVar19 * dVar16))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803dd588 + 10) ^ 0x80000000) -
                    DOUBLE_803e1a70);
        *(float *)(psVar4 + 0xe) =
             *(float *)(psVar4 + 0xe) -
             (*(float *)(psVar4 + 0xe) - (fVar3 + (float)((double)fVar1 * dVar17))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803dd588 + 10) ^ 0x80000000) - dVar20
                    );
        *(float *)(psVar4 + 0x10) =
             *(float *)(psVar4 + 0x10) -
             (*(float *)(psVar4 + 0x10) - (fVar2 + (float)(dVar19 * dVar21))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803dd588 + 10) ^ 0x80000000) - dVar20
                    );
      }
    }
    else {
      *(undefined *)(DAT_803dd588 + 5) = 1;
      (**(code **)(*DAT_803dca4c + 8))(0xc,1);
      *(undefined2 *)((int)DAT_803dd588 + 10) = 2;
      *(byte *)((int)DAT_803dd588 + 0x15) = *(byte *)((int)DAT_803dd588 + 0x15) & 0x7f | 0x80;
    }
  }
  *(undefined *)((int)DAT_803dd588 + 9) = *(undefined *)(DAT_803dd588 + 2);
  psVar9 = (short *)FUN_8002e0b4(0x431dc);
  dVar20 = (double)(*(float *)(psVar9 + 0xc) - *(float *)(psVar4 + 0xc));
  dVar21 = (double)(*(float *)(psVar9 + 0x10) - *(float *)(psVar4 + 0x10));
  sVar11 = FUN_800217c0(dVar20,dVar21);
  *psVar9 = sVar11 + -0x8000;
  uVar18 = FUN_802931a0((double)(float)(dVar20 * dVar20 + (double)(float)(dVar21 * dVar21)));
  sVar11 = FUN_800217c0(uVar18,(double)(*(float *)(psVar9 + 0xe) - *(float *)(psVar4 + 0xe)));
  psVar9[1] = -0x8000 - sVar11;
  *(float *)(psVar9 + 4) = FLOAT_803e1a64 + FLOAT_803e1a68 / *DAT_803dd588;
  *psVar6 = *psVar9;
  psVar6[1] = psVar9[1];
  *(undefined4 *)(psVar6 + 4) = *(undefined4 *)(psVar9 + 4);
  if (((short)(*psVar6 + -0x2198) < -0x1fff) || (0x1fff < (short)(*psVar6 + -0x2198))) {
    *(undefined *)(psVar6 + 0x1b) = 0;
  }
  else {
    dVar20 = (double)FUN_80294204((double)((FLOAT_803e1a48 *
                                           (float)((double)CONCAT44(0x43300000,
                                                                    (psVar6[1] + -0x4000) * 2 ^
                                                                    0x80000000) - DOUBLE_803e1a70))
                                          / FLOAT_803e1a4c));
    dVar21 = (double)FUN_80294204((double)((FLOAT_803e1a48 *
                                           (float)((double)CONCAT44(0x43300000,
                                                                    (*psVar6 + -0x2198) * 2 ^
                                                                    0x80000000) - DOUBLE_803e1a70))
                                          / FLOAT_803e1a4c));
    fVar1 = FLOAT_803e1a28;
    if (FLOAT_803e1a28 <= FLOAT_803e1a6c * (float)(dVar21 * dVar20)) {
      dVar20 = (double)FUN_80294204((double)((FLOAT_803e1a48 *
                                             (float)((double)CONCAT44(0x43300000,
                                                                      (psVar6[1] + -0x4000) * 2 ^
                                                                      0x80000000) - DOUBLE_803e1a70)
                                             ) / FLOAT_803e1a4c));
      dVar21 = (double)FUN_80294204((double)((FLOAT_803e1a48 *
                                             (float)((double)CONCAT44(0x43300000,
                                                                      (*psVar6 + -0x2198) * 2 ^
                                                                      0x80000000) - DOUBLE_803e1a70)
                                             ) / FLOAT_803e1a4c));
      fVar1 = FLOAT_803e1a6c * (float)(dVar21 * dVar20);
    }
    *(char *)(psVar6 + 0x1b) = (char)(int)fVar1;
  }
  FUN_8000e034((double)*(float *)(psVar4 + 0xc),(double)*(float *)(psVar4 + 0xe),
               (double)*(float *)(psVar4 + 0x10),psVar4 + 6,psVar4 + 8,psVar4 + 10,
               *(undefined4 *)(psVar4 + 0x18));
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  __psq_l0(auStack40,uVar15);
  __psq_l1(auStack40,uVar15);
  __psq_l0(auStack56,uVar15);
  __psq_l1(auStack56,uVar15);
  FUN_80286120();
  return;
}

