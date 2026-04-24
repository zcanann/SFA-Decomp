// Function: FUN_801091d8
// Entry: 801091d8
// Size: 1384 bytes

/* WARNING: Removing unreachable block (ram,0x80109710) */
/* WARNING: Removing unreachable block (ram,0x80109700) */
/* WARNING: Removing unreachable block (ram,0x801096f8) */
/* WARNING: Removing unreachable block (ram,0x80109708) */
/* WARNING: Removing unreachable block (ram,0x80109718) */

void FUN_801091d8(short *param_1,int param_2,undefined4 *param_3)

{
  float fVar1;
  short sVar3;
  undefined4 uVar2;
  uint uVar4;
  int iVar5;
  short *psVar6;
  undefined4 uVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
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
  psVar6 = *(short **)(param_1 + 0x52);
  if (DAT_803dd548 == (undefined4 *)0x0) {
    DAT_803dd548 = (undefined4 *)FUN_80023cc8(0x134,0xf,0);
  }
  FUN_800033a8(DAT_803dd548,0,0x134);
  *DAT_803dd548 = *param_3;
  DAT_803dd548[0x45] =
       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_3 + 2)) - DOUBLE_803e1838);
  DAT_803dd548[1] = param_3[1];
  DAT_803dd548[0x47] = FLOAT_803e17c4;
  sVar3 = (-0x8000 - *param_1) - *psVar6;
  uVar4 = (uint)sVar3;
  if ((int)uVar4 < 0) {
    sVar3 = -sVar3;
  }
  dVar11 = (double)((float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e17d8) /
                   FLOAT_803e17e4);
  dVar10 = (double)((float)((double)CONCAT44(0x43300000,(int)sVar3 ^ 0x80000000) - DOUBLE_803e17d8)
                   / FLOAT_803e1830);
  DAT_803dd548[0x3f] = DAT_803dd548 + 4;
  DAT_803dd548[0x40] = DAT_803dd548 + 8;
  DAT_803dd548[0x41] = DAT_803dd548 + 0xc;
  DAT_803dd548[0x42] = 4;
  DAT_803dd548[0x3e] = 0;
  DAT_803dd548[0x43] = FUN_80010dc0;
  DAT_803dd548[0x44] = &LAB_80010d54;
  dVar13 = (double)(*(float *)(param_1 + 0xc) - *(float *)(psVar6 + 0xc));
  dVar12 = (double)(*(float *)(param_1 + 0x10) - *(float *)(psVar6 + 0x10));
  dVar8 = (double)FUN_802931a0((double)(float)(dVar13 * dVar13 + (double)(float)(dVar12 * dVar12)));
  if ((double)FLOAT_803e17c4 != dVar8) {
    dVar13 = (double)(float)(dVar13 / dVar8);
    dVar12 = (double)(float)(dVar12 / dVar8);
  }
  FUN_80108010(psVar6,1);
  dVar8 = (double)FUN_80293e80((double)((FLOAT_803e1834 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*psVar6 ^ 0x80000000) -
                                               DOUBLE_803e17d8)) / FLOAT_803e17c8));
  dVar8 = -dVar8;
  dVar9 = (double)FUN_80294204((double)((FLOAT_803e1834 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*psVar6 ^ 0x80000000) -
                                               DOUBLE_803e17d8)) / FLOAT_803e17c8));
  DAT_803dd548[4] = *(undefined4 *)(param_1 + 0xc);
  DAT_803dd548[5] = DAT_803dd548[0x48];
  DAT_803dd548[6] = (float)(-dVar12 * dVar11);
  DAT_803dd548[7] = (float)(dVar8 * dVar10);
  DAT_803dd548[8] = *(undefined4 *)(param_1 + 0xe);
  DAT_803dd548[9] = DAT_803dd548[0x49];
  fVar1 = FLOAT_803e17c4;
  DAT_803dd548[10] = FLOAT_803e17c4;
  DAT_803dd548[0xb] = fVar1;
  DAT_803dd548[0xc] = *(undefined4 *)(param_1 + 0x10);
  DAT_803dd548[0xd] = DAT_803dd548[0x4a];
  DAT_803dd548[0xe] = (float)(dVar13 * dVar11);
  DAT_803dd548[0xf] = (float)(-dVar9 * dVar10);
  DAT_803dd548[6] = fVar1;
  DAT_803dd548[7] = fVar1;
  DAT_803dd548[10] = fVar1;
  DAT_803dd548[0xb] = fVar1;
  DAT_803dd548[0xe] = fVar1;
  DAT_803dd548[0xf] = fVar1;
  FUN_80010a6c(DAT_803dd548 + 0x1e);
  sVar3 = FUN_800217c0((double)(*(float *)(param_1 + 0xc) - (float)DAT_803dd548[5]),
                       (double)(*(float *)(param_1 + 0x10) - (float)DAT_803dd548[0xd]));
  sVar3 = *param_1 - (-0x8000 - sVar3);
  if (0x8000 < sVar3) {
    sVar3 = sVar3 + 1;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  DAT_803dd548[0x10] =
       (float)((double)CONCAT44(0x43300000,(int)sVar3 ^ 0x80000000) - DOUBLE_803e17d8);
  fVar1 = FLOAT_803e17c4;
  DAT_803dd548[0x11] = FLOAT_803e17c4;
  DAT_803dd548[0x12] = fVar1;
  DAT_803dd548[0x13] = fVar1;
  fVar1 = (float)DAT_803dd548[0x10] - (float)DAT_803dd548[0x11];
  if ((FLOAT_803e17c8 < fVar1) || (fVar1 < FLOAT_803e17cc)) {
    if (FLOAT_803e17c4 <= (float)DAT_803dd548[0x10]) {
      if ((float)DAT_803dd548[0x11] < FLOAT_803e17c4) {
        DAT_803dd548[0x11] = (float)DAT_803dd548[0x11] + FLOAT_803e17d0;
      }
    }
    else {
      DAT_803dd548[0x10] = (float)DAT_803dd548[0x10] + FLOAT_803e17d0;
    }
  }
  DAT_803dd548[0x14] =
       (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) - DOUBLE_803e17d8);
  fVar1 = FLOAT_803e17c4;
  DAT_803dd548[0x15] = FLOAT_803e17c4;
  DAT_803dd548[0x16] = fVar1;
  DAT_803dd548[0x17] = fVar1;
  *(undefined *)(param_1 + 0x9f) = 1;
  iVar5 = FUN_8001ffb4(0xc64);
  if (iVar5 != 0) {
    *(byte *)((int)DAT_803dd548 + 0x12d) = *(byte *)((int)DAT_803dd548 + 0x12d) & 0x7f | 0x80;
  }
  if (param_2 == 1) {
    *(undefined *)(DAT_803dd548 + 0x4b) = 5;
  }
  else {
    *(undefined *)(DAT_803dd548 + 0x4b) = 0;
    *(byte *)((int)DAT_803dd548 + 0x12d) = *(byte *)((int)DAT_803dd548 + 0x12d) & 0xbf | 0x40;
    if (*(char *)((int)DAT_803dd548 + 0x12d) < '\0') {
      uVar2 = 0x3f4;
    }
    else {
      uVar2 = 0x28b;
    }
    FUN_8000bb18(0,uVar2);
  }
  *(byte *)((int)DAT_803dd548 + 0x12d) = *(byte *)((int)DAT_803dd548 + 0x12d) & 0xdf;
  DAT_803dd548[0x4c] = DAT_803dd548[0x49];
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  __psq_l0(auStack56,uVar7);
  __psq_l1(auStack56,uVar7);
  __psq_l0(auStack72,uVar7);
  __psq_l1(auStack72,uVar7);
  return;
}

