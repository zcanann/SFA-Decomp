// Function: FUN_8010747c
// Entry: 8010747c
// Size: 1640 bytes

/* WARNING: Removing unreachable block (ram,0x80107abc) */
/* WARNING: Removing unreachable block (ram,0x80107aac) */
/* WARNING: Removing unreachable block (ram,0x80107aa4) */
/* WARNING: Removing unreachable block (ram,0x80107ab4) */
/* WARNING: Removing unreachable block (ram,0x80107ac4) */

void FUN_8010747c(undefined4 param_1,undefined4 param_2,short *param_3)

{
  float fVar1;
  int iVar2;
  int iVar3;
  short sVar4;
  short sVar5;
  short *psVar6;
  undefined4 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar12;
  short *local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  undefined4 local_98;
  uint uStack148;
  undefined4 local_90;
  uint uStack140;
  undefined4 local_88;
  uint uStack132;
  undefined4 local_80;
  uint uStack124;
  double local_78;
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
  iVar2 = FUN_802860dc();
  *(undefined *)((int)param_3 + 3) = 1;
  psVar6 = *(short **)(iVar2 + 0xa4);
  if (DAT_803dd538 == (short **)0x0) {
    DAT_803dd538 = (short **)FUN_80023cc8(0x1c0,0xf,0);
  }
  FUN_800033a8(DAT_803dd538,0,0x1c0);
  iVar3 = (**(code **)(*DAT_803dca50 + 0x18))();
  (**(code **)(**(int **)(iVar3 + 4) + 0x20))
            (DAT_803dd538 + 1,DAT_803dd538 + 2,DAT_803dd538 + 3,0,DAT_803dd538 + 4);
  *(undefined *)(DAT_803dd538 + 0x6f) = 0;
  *DAT_803dd538 = *(short **)(iVar2 + 0x30);
  uStack148 = (int)*psVar6 ^ 0x80000000;
  local_98 = 0x43300000;
  dVar8 = (double)FUN_80293e80((double)((FLOAT_803e1760 *
                                        (float)((double)CONCAT44(0x43300000,uStack148) -
                                               DOUBLE_803e1750)) / FLOAT_803e1764));
  uStack140 = (int)*psVar6 ^ 0x80000000;
  local_90 = 0x43300000;
  dVar9 = (double)FUN_80294204((double)((FLOAT_803e1760 *
                                        (float)((double)CONCAT44(0x43300000,uStack140) -
                                               DOUBLE_803e1750)) / FLOAT_803e1764));
  if (*DAT_803dd538 == (short *)0x0) {
    uStack132 = (uint)*psVar6;
  }
  else {
    uStack132 = (int)*psVar6 - (int)**DAT_803dd538;
  }
  uStack132 = uStack132 ^ 0x80000000;
  local_88 = 0x43300000;
  dVar12 = (double)((FLOAT_803e1760 *
                    (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e1750)) /
                   FLOAT_803e1764);
  dVar10 = (double)FUN_80293e80(dVar12);
  dVar12 = (double)FUN_80294204(dVar12);
  sVar4 = FUN_800217c0((double)(*(float *)(iVar2 + 0x18) - *(float *)(psVar6 + 0xc)),
                       (double)(*(float *)(iVar2 + 0x20) - *(float *)(psVar6 + 0x10)));
  sVar4 = *psVar6 - sVar4;
  if (0x8000 < sVar4) {
    sVar4 = sVar4 + 1;
  }
  if (sVar4 < -0x8000) {
    sVar4 = sVar4 + -1;
  }
  if (sVar4 < 0) {
    sVar4 = -sVar4;
  }
  uStack124 = (int)*param_3 ^ 0x80000000;
  local_80 = 0x43300000;
  iVar3 = (int)(FLOAT_803e1768 * (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e1750));
  local_78 = (double)(longlong)iVar3;
  if (sVar4 < (short)iVar3) {
    *(undefined *)(DAT_803dd538 + 0x6f) = 1;
  }
  else {
    dVar11 = (double)((float)DAT_803dd538[1] * (float)DAT_803dd538[1] -
                     (float)DAT_803dd538[3] * (float)DAT_803dd538[3]);
    if (dVar11 < (double)FLOAT_803e176c) {
      dVar11 = (double)FLOAT_803e176c;
    }
    dVar11 = (double)FUN_802931a0(dVar11);
    local_a4 = (float)(dVar8 * dVar11 + (double)*(float *)(psVar6 + 0xc));
    local_a0 = (float)DAT_803dd538[3] + *(float *)(psVar6 + 0xe) + (float)DAT_803dd538[4];
    local_9c = (float)(dVar9 * dVar11 + (double)*(float *)(psVar6 + 0x10));
    if (*(char *)((int)param_3 + 3) != '\0') {
      FUN_80103708(iVar2,psVar6,&local_a4,0);
    }
    FUN_8000e034((double)local_a4,(double)local_a0,(double)local_9c,&local_a4,&local_a0,&local_9c,
                 *(undefined4 *)(iVar2 + 0x30));
    for (local_a8 = (short *)0x0; (int)local_a8 < 3; local_a8 = (short *)((int)local_a8 + 1)) {
      DAT_803dd538[(int)local_a8 + 7] = *(short **)(iVar2 + 0xc);
      DAT_803dd538[(int)local_a8 + 0x1b] = *(short **)(iVar2 + 0x10);
      DAT_803dd538[(int)local_a8 + 0x2f] = *(short **)(iVar2 + 0x14);
    }
    dVar11 = (double)(*(float *)(iVar2 + 0xc) - local_a4);
    dVar9 = (double)(*(float *)(iVar2 + 0x14) - local_9c);
    dVar8 = (double)FUN_802931a0((double)(float)(dVar11 * dVar11 + (double)(float)(dVar9 * dVar9)));
    dVar8 = (double)(float)((double)FLOAT_803e1770 * dVar8);
    sVar4 = FUN_800217c0(-dVar10,-dVar12);
    sVar5 = FUN_800217c0(dVar11,dVar9);
    sVar4 = sVar4 - sVar5;
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    sVar5 = sVar4;
    if (sVar4 < 0) {
      sVar5 = -sVar4;
    }
    if (sVar5 < 0x4001) {
      sVar5 = 0x4000 - sVar5;
    }
    else {
      sVar5 = 0;
    }
    if (sVar4 < 0) {
      sVar4 = -(short)((int)sVar5 << 1);
    }
    else {
      sVar4 = (short)((int)sVar5 << 1);
    }
    fVar1 = FLOAT_803e1740;
    if ((int)sVar5 != 0) {
      local_78 = (double)CONCAT44(0x43300000,(int)sVar5 ^ 0x80000000);
      dVar9 = (double)FUN_80293e80((double)((FLOAT_803e1760 * (float)(local_78 - DOUBLE_803e1750)) /
                                           FLOAT_803e1764));
      fVar1 = (float)(dVar8 / dVar9);
    }
    DAT_803dd538[0x69] = (short *)(DAT_803dd538 + 7);
    DAT_803dd538[0x6a] = (short *)(DAT_803dd538 + 0x1b);
    DAT_803dd538[0x6b] = (short *)(DAT_803dd538 + 0x2f);
    DAT_803dd538[0x6d] = (short *)FUN_80010ee0;
    DAT_803dd538[0x6e] = (short *)&LAB_80010e2c;
    FUN_80106d84(-(double)(float)(dVar10 * (double)fVar1 - (double)local_a4),
                 -(double)(float)(dVar12 * (double)fVar1 - (double)local_9c),
                 (double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x10),
                 (double)*(float *)(iVar2 + 0x14),(double)local_a0,(int)sVar4,0x1555,&local_a8);
    iVar2 = (int)local_a8 << 2;
    for (psVar6 = local_a8; (int)psVar6 < (int)local_a8 + 3; psVar6 = (short *)((int)psVar6 + 1)) {
      *(float *)((int)DAT_803dd538 + iVar2 + 0x1c) = local_a4;
      *(float *)((int)DAT_803dd538 + iVar2 + 0x6c) = local_a0;
      *(float *)((int)DAT_803dd538 + iVar2 + 0xbc) = local_9c;
      iVar2 = iVar2 + 4;
    }
    DAT_803dd538[0x6c] = psVar6;
    DAT_803dd538[0x68] = (short *)0x0;
    FUN_80010a6c(DAT_803dd538 + 0x48);
    if (sVar4 < 0) {
      sVar4 = -sVar4;
    }
    if ((0x2000 < sVar4) && (*(char *)(param_3 + 1) != '\0')) {
      FUN_8000bb18(0,0x286);
    }
    (**(code **)(*DAT_803dca50 + 0x34))
              ((double)(float)DAT_803dd538[0x4b],(double)FLOAT_803e1774,(double)FLOAT_803e1770,
               (double)FLOAT_803e1744,(double)FLOAT_803e1778,DAT_803dd538 + 0x43);
    DAT_803dd538[5] = (short *)FLOAT_803e1758;
    DAT_803dd538[6] = (short *)FLOAT_803e175c;
  }
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
  FUN_80286128();
  return;
}

