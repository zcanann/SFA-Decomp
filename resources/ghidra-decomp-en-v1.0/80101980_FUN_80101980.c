// Function: FUN_80101980
// Entry: 80101980
// Size: 1340 bytes

/* WARNING: Removing unreachable block (ram,0x80101e9c) */

void FUN_80101980(short *param_1)

{
  int iVar1;
  float fVar2;
  float fVar3;
  short *psVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f31;
  float local_38;
  float local_34;
  float local_30;
  double local_28;
  double local_20;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FUN_8000f458(0);
  psVar4 = (short *)FUN_8000faac();
  *psVar4 = *param_1;
  psVar4[1] = param_1[1];
  psVar4[2] = param_1[2];
  if (*(char *)((int)param_1 + 0x143) < '\0') {
    FUN_80247754(param_1 + 0xc,psVar4 + 6,&local_38);
    dVar6 = (double)FUN_802477f0(&local_38);
    if ((double)FLOAT_803e1630 < dVar6) {
      FUN_80247794(&local_38,&local_38);
    }
    dVar7 = (double)FUN_80021370(dVar6,(double)FLOAT_803e1668,(double)FLOAT_803db414);
    dVar6 = (double)FLOAT_803e1630;
    if ((dVar6 <= dVar7) && (dVar6 = dVar7, (double)(FLOAT_803e166c * FLOAT_803db414) < dVar7)) {
      dVar6 = (double)(FLOAT_803e166c * FLOAT_803db414);
    }
    *(float *)(psVar4 + 6) = (float)(dVar6 * (double)local_38 + (double)*(float *)(psVar4 + 6));
    *(float *)(psVar4 + 8) = (float)(dVar6 * (double)local_34 + (double)*(float *)(psVar4 + 8));
    *(float *)(psVar4 + 10) = (float)(dVar6 * (double)local_30 + (double)*(float *)(psVar4 + 10));
  }
  else {
    *(undefined4 *)(psVar4 + 6) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(psVar4 + 8) = *(undefined4 *)(param_1 + 0xe);
    *(undefined4 *)(psVar4 + 10) = *(undefined4 *)(param_1 + 0x10);
  }
  fVar3 = FLOAT_803e1630;
  FLOAT_803dd4d0 = *(float *)(param_1 + 0x5a);
  if (FLOAT_803e1630 < *(float *)(param_1 + 0x7a)) {
    *(float *)(param_1 + 0x7a) =
         -(*(float *)(param_1 + 0x7c) * FLOAT_803db414 - *(float *)(param_1 + 0x7a));
    fVar2 = *(float *)(param_1 + 0x7a);
    if ((fVar3 <= fVar2) && (fVar3 = fVar2, FLOAT_803e162c < fVar2)) {
      fVar3 = FLOAT_803e162c;
    }
    *(float *)(param_1 + 0x7a) = fVar3;
    if (*(char *)(DAT_803dd524 + 0x139) == '\x02') {
      fVar3 = *(float *)(param_1 + 0x7a);
      dVar6 = (double)(FLOAT_803e162c - fVar3 * fVar3 * fVar3);
    }
    else if (*(char *)(DAT_803dd524 + 0x139) == '\x01') {
      dVar6 = (double)(FLOAT_803e162c - *(float *)(param_1 + 0x7a) * *(float *)(param_1 + 0x7a));
    }
    else {
      dVar6 = (double)(FLOAT_803e162c - *(float *)(param_1 + 0x7a));
    }
    dVar7 = (double)FLOAT_803e1630;
    if ((dVar7 <= dVar6) && (dVar7 = dVar6, (double)FLOAT_803e162c < dVar6)) {
      dVar7 = (double)FLOAT_803e162c;
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 8) != 0) {
      *(float *)(psVar4 + 6) =
           (float)(dVar7 * (double)(float)((double)*(float *)(psVar4 + 6) -
                                          (double)*(float *)(param_1 + 0x86)) +
                  (double)*(float *)(param_1 + 0x86));
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 0x10) != 0) {
      *(float *)(psVar4 + 8) =
           (float)(dVar7 * (double)(float)((double)*(float *)(psVar4 + 8) -
                                          (double)*(float *)(param_1 + 0x88)) +
                  (double)*(float *)(param_1 + 0x88));
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 0x20) != 0) {
      *(float *)(psVar4 + 10) =
           (float)(dVar7 * (double)(float)((double)*(float *)(psVar4 + 10) -
                                          (double)*(float *)(param_1 + 0x8a)) +
                  (double)*(float *)(param_1 + 0x8a));
    }
    FUN_8007d6dc(dVar7,&DAT_803db994);
    if ((*(byte *)((int)param_1 + 0x13f) & 1) != 0) {
      param_1[0x80] = param_1[0x83] - *psVar4;
      if (0x8000 < param_1[0x80]) {
        param_1[0x80] = param_1[0x80] + 1;
      }
      if (param_1[0x80] < -0x8000) {
        param_1[0x80] = param_1[0x80] + -1;
      }
      local_28 = (double)CONCAT44(0x43300000,(int)param_1[0x80] ^ 0x80000000);
      iVar1 = (int)((double)(float)(local_28 - DOUBLE_803e1650) * dVar7);
      local_20 = (double)(longlong)iVar1;
      *psVar4 = param_1[0x83] - (short)iVar1;
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 2) != 0) {
      param_1[0x81] = param_1[0x84] - psVar4[1];
      if (0x8000 < param_1[0x81]) {
        param_1[0x81] = param_1[0x81] + 1;
      }
      if (param_1[0x81] < -0x8000) {
        param_1[0x81] = param_1[0x81] + -1;
      }
      local_20 = (double)CONCAT44(0x43300000,(int)param_1[0x81] ^ 0x80000000);
      iVar1 = (int)((double)(float)(local_20 - DOUBLE_803e1650) * dVar7);
      local_28 = (double)(longlong)iVar1;
      psVar4[1] = param_1[0x84] - (short)iVar1;
    }
    if ((*(byte *)((int)param_1 + 0x13f) & 4) != 0) {
      param_1[0x82] = param_1[0x85] - psVar4[2];
      if (0x8000 < param_1[0x82]) {
        param_1[0x82] = param_1[0x82] + 1;
      }
      if (param_1[0x82] < -0x8000) {
        param_1[0x82] = param_1[0x82] + -1;
      }
      local_20 = (double)CONCAT44(0x43300000,(int)param_1[0x82] ^ 0x80000000);
      iVar1 = (int)((double)(float)(local_20 - DOUBLE_803e1650) * dVar7);
      local_28 = (double)(longlong)iVar1;
      psVar4[2] = param_1[0x85] - (short)iVar1;
    }
  }
  FUN_8000fc3c((double)FLOAT_803dd4d0);
  FUN_8000dde8(psVar4);
  FUN_80058cdc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10));
  DAT_803dd4c0 = FUN_8000fae4();
  if ((int)DAT_803dd4c0 != (int)*(char *)((int)param_1 + 0x13b)) {
    if ((int)DAT_803dd4c0 < (int)*(char *)((int)param_1 + 0x13b)) {
      local_20 = (double)(longlong)(int)FLOAT_803db414;
      DAT_803dd4c0 = DAT_803dd4c0 + (short)*(char *)(param_1 + 0x9e) * (short)(int)FLOAT_803db414;
      if ((int)*(char *)((int)param_1 + 0x13b) < (int)DAT_803dd4c0) {
        DAT_803dd4c0 = (short)*(char *)((int)param_1 + 0x13b);
      }
    }
    else {
      local_20 = (double)(longlong)(int)FLOAT_803db414;
      DAT_803dd4c0 = DAT_803dd4c0 - (short)*(char *)(param_1 + 0x9e) * (short)(int)FLOAT_803db414;
      if ((int)DAT_803dd4c0 < (int)*(char *)((int)param_1 + 0x13b)) {
        DAT_803dd4c0 = (short)*(char *)((int)param_1 + 0x13b);
      }
    }
    FUN_8000faec((int)DAT_803dd4c0);
  }
  *(undefined *)((int)param_1 + 0x13b) = 0;
  FUN_8000f564();
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

