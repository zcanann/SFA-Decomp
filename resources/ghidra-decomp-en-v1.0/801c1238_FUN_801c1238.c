// Function: FUN_801c1238
// Entry: 801c1238
// Size: 992 bytes

/* WARNING: Removing unreachable block (ram,0x801c15f0) */
/* WARNING: Removing unreachable block (ram,0x801c15e0) */
/* WARNING: Removing unreachable block (ram,0x801c15d0) */
/* WARNING: Removing unreachable block (ram,0x801c15c0) */
/* WARNING: Removing unreachable block (ram,0x801c15b0) */
/* WARNING: Removing unreachable block (ram,0x801c15a8) */
/* WARNING: Removing unreachable block (ram,0x801c15b8) */
/* WARNING: Removing unreachable block (ram,0x801c15c8) */
/* WARNING: Removing unreachable block (ram,0x801c15d8) */
/* WARNING: Removing unreachable block (ram,0x801c15e8) */
/* WARNING: Removing unreachable block (ram,0x801c15f8) */

void FUN_801c1238(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined8 param_7,double param_8)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  float **ppfVar5;
  float *pfVar6;
  int iVar7;
  float *pfVar8;
  float *pfVar9;
  int iVar10;
  undefined4 uVar11;
  double extraout_f1;
  double dVar12;
  undefined8 in_f21;
  double dVar13;
  undefined8 in_f22;
  undefined8 in_f23;
  undefined8 in_f24;
  undefined8 in_f25;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar14;
  undefined8 in_f29;
  double dVar15;
  undefined8 in_f30;
  double dVar16;
  undefined8 in_f31;
  undefined auStack168 [16];
  undefined auStack152 [16];
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
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
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  __psq_st0(auStack152,(int)((ulonglong)in_f22 >> 0x20),0);
  __psq_st1(auStack152,(int)in_f22,0);
  __psq_st0(auStack168,(int)((ulonglong)in_f21 >> 0x20),0);
  __psq_st1(auStack168,(int)in_f21,0);
  iVar3 = FUN_802860d0();
  dVar16 = (double)(float)(param_4 - extraout_f1);
  dVar15 = (double)(float)(param_5 - param_2);
  dVar14 = (double)(float)(param_6 - param_3);
  dVar13 = extraout_f1;
  dVar12 = (double)FUN_802931a0((double)(float)(dVar14 * dVar14 +
                                               (double)(float)(dVar16 * dVar16 +
                                                              (double)(float)(dVar15 * dVar15))));
  uVar4 = iVar3 - 1U ^ 0x80000000;
  dVar16 = (double)(float)(dVar16 / (double)(float)((double)CONCAT44(0x43300000,uVar4) -
                                                   DOUBLE_803e4df0));
  dVar15 = (double)(float)(dVar15 / (double)(float)((double)CONCAT44(0x43300000,uVar4) -
                                                   DOUBLE_803e4df0));
  dVar14 = (double)(float)(dVar14 / (double)(float)((double)CONCAT44(0x43300000,uVar4) -
                                                   DOUBLE_803e4df0));
  ppfVar5 = (float **)FUN_80023cc8(iVar3 * 0x34 + (iVar3 - 1U) * 0x24 + 0x44,0xff,0);
  *ppfVar5 = (float *)(ppfVar5 + 0x11);
  ppfVar5[1] = (float *)(ppfVar5 + iVar3 * 0xd + 0x11);
  *(char *)(ppfVar5 + 2) = (char)iVar3;
  ppfVar5[9] = (float *)(float)dVar12;
  ppfVar5[3] = (float *)(float)dVar13;
  ppfVar5[4] = (float *)(float)param_2;
  ppfVar5[5] = (float *)(float)param_3;
  ppfVar5[6] = (float *)(float)param_4;
  ppfVar5[7] = (float *)(float)param_5;
  ppfVar5[8] = (float *)(float)param_6;
  *(undefined *)(ppfVar5 + 0xd) = 0;
  *(undefined *)((int)ppfVar5 + 0x35) = 1;
  ppfVar5[0xe] = (float *)FLOAT_803e4e00;
  ppfVar5[10] = (float *)0x1;
  ppfVar5[0xc] = (float *)FLOAT_803e4df8;
  if ((double)FLOAT_803e4e04 < (double)(float)((double)(float)ppfVar5[0xc] * dVar12)) {
    ppfVar5[0xc] = (float *)(float)((double)FLOAT_803e4e04 / dVar12);
  }
  ppfVar5[0xb] = (float *)FLOAT_803e4e08;
  ppfVar5[0x10] = (float *)(float)((double)(float)ppfVar5[0xc] / param_8);
  ppfVar5[0xf] = (float *)(float)((double)FLOAT_803e4e0c / param_8);
  fVar1 = FLOAT_803e4dfc;
  dVar13 = DOUBLE_803e4df0;
  pfVar9 = *ppfVar5;
  uVar4 = 0;
  pfVar6 = pfVar9;
  iVar10 = iVar3;
  if (0 < iVar3) {
    do {
      uVar2 = uVar4 ^ 0x80000000;
      *pfVar6 = (float)((double)(float)((double)CONCAT44(0x43300000,uVar2) - dVar13) * dVar16 +
                       (double)(float)ppfVar5[3]);
      pfVar6[1] = (float)((double)(float)((double)CONCAT44(0x43300000,uVar2) - dVar13) * dVar15 +
                         (double)(float)ppfVar5[4]);
      pfVar6[2] = (float)((double)(float)((double)CONCAT44(0x43300000,uVar2) - dVar13) * dVar14 +
                         (double)(float)ppfVar5[5]);
      pfVar6[5] = fVar1;
      pfVar6[4] = fVar1;
      pfVar6[3] = fVar1;
      pfVar6[8] = fVar1;
      pfVar6[7] = fVar1;
      pfVar6[6] = fVar1;
      *(undefined *)(pfVar6 + 0xc) = 0;
      if ((uVar4 == 0) || (uVar4 == iVar3 - 1U)) {
        *(undefined *)(pfVar6 + 9) = 1;
      }
      else if ((uVar4 == 1) || (uVar4 == iVar3 - 2U)) {
        *(undefined *)(pfVar6 + 9) = 2;
      }
      else {
        *(undefined *)(pfVar6 + 9) = 2;
      }
      pfVar8 = pfVar6;
      for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(pfVar6 + 9); iVar7 = iVar7 + 1) {
        pfVar8[10] = 0.0;
        pfVar8 = pfVar8 + 1;
      }
      pfVar6 = pfVar6 + 0xd;
      uVar4 = uVar4 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
  }
  *(undefined *)(pfVar9 + iVar3 * 0xd + -1) = 1;
  *(undefined *)(pfVar9 + 0xc) = 1;
  pfVar8 = ppfVar5[1];
  dVar15 = (double)FLOAT_803e4e10;
  dVar14 = (double)FLOAT_803e4dfc;
  dVar12 = (double)FLOAT_803e4e14;
  pfVar6 = pfVar9;
  dVar13 = DOUBLE_803e4df0;
  for (iVar10 = 0; iVar10 < (int)(iVar3 - 1U); iVar10 = iVar10 + 1) {
    pfVar8[3] = (float)ppfVar5[9] /
                (float)((double)CONCAT44(0x43300000,iVar3 - 1U ^ 0x80000000) - dVar13);
    pfVar8[4] = (float)dVar15;
    pfVar8[8] = (float)dVar14;
    pfVar8[7] = (float)dVar14;
    pfVar8[6] = (float)dVar14;
    pfVar8[5] = (float)(dVar12 * (double)pfVar8[3]);
    FUN_801c11b8(pfVar8,pfVar6,pfVar9 + (iVar10 + 1) * 0xd);
    pfVar8 = pfVar8 + 9;
    pfVar6 = pfVar6 + 0xd;
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  __psq_l0(auStack56,uVar11);
  __psq_l1(auStack56,uVar11);
  __psq_l0(auStack72,uVar11);
  __psq_l1(auStack72,uVar11);
  __psq_l0(auStack88,uVar11);
  __psq_l1(auStack88,uVar11);
  __psq_l0(auStack104,uVar11);
  __psq_l1(auStack104,uVar11);
  __psq_l0(auStack120,uVar11);
  __psq_l1(auStack120,uVar11);
  __psq_l0(auStack136,uVar11);
  __psq_l1(auStack136,uVar11);
  __psq_l0(auStack152,uVar11);
  __psq_l1(auStack152,uVar11);
  __psq_l0(auStack168,uVar11);
  __psq_l1(auStack168,uVar11);
  FUN_8028611c(ppfVar5);
  return;
}

