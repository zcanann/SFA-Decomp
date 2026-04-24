// Function: FUN_8016f260
// Entry: 8016f260
// Size: 748 bytes

/* WARNING: Removing unreachable block (ram,0x8016f51c) */
/* WARNING: Removing unreachable block (ram,0x8016f514) */
/* WARNING: Removing unreachable block (ram,0x8016f524) */

void FUN_8016f260(int param_1,int param_2,int param_3)

{
  float fVar1;
  ushort uVar2;
  float *pfVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  undefined4 uVar8;
  undefined8 uVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  pfVar3 = (float *)(*(int *)(param_3 + 0x74) + (uint)*(byte *)(param_3 + 0xe4) * 0x18);
  if (pfVar3 != (float *)0x0) {
    dVar12 = (double)(*pfVar3 - *(float *)(param_2 + 0x24));
    dVar11 = (double)((pfVar3[1] - FLOAT_803e3334) - *(float *)(param_2 + 0x28));
    dVar10 = (double)(pfVar3[2] - *(float *)(param_2 + 0x2c));
    sVar4 = FUN_800217c0((double)*(float *)(param_1 + 0x24),(double)*(float *)(param_1 + 0x2c));
    uVar9 = FUN_802931a0((double)(*(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24) +
                                 *(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c)));
    sVar5 = FUN_800217c0((double)*(float *)(param_1 + 0x28),uVar9);
    sVar6 = FUN_800217c0(dVar12,dVar10);
    uVar9 = FUN_802931a0((double)(float)(dVar12 * dVar12 + (double)(float)(dVar10 * dVar10)));
    sVar7 = FUN_800217c0(dVar11,uVar9);
    sVar6 = sVar6 - sVar4;
    if (0x8000 < sVar6) {
      sVar6 = sVar6 + 1;
    }
    if (sVar6 < -0x8000) {
      sVar6 = sVar6 + -1;
    }
    sVar7 = sVar7 - sVar5;
    if (0x8000 < sVar7) {
      sVar7 = sVar7 + 1;
    }
    if (sVar7 < -0x8000) {
      sVar7 = sVar7 + -1;
    }
    sVar6 = sVar6 >> 5;
    if (0x16c < sVar6) {
      sVar6 = 0x16c;
    }
    if (sVar6 < -0x16c) {
      sVar6 = -0x16c;
    }
    sVar7 = sVar7 >> 4;
    if (0x2d8 < sVar7) {
      sVar7 = 0x2d8;
    }
    if (sVar7 < -0x2d8) {
      sVar7 = -0x2d8;
    }
    uVar2 = (ushort)DAT_803db410;
    dVar11 = (double)((FLOAT_803e3338 *
                      (float)((double)CONCAT44(0x43300000,
                                               (int)(short)(sVar4 + (ushort)DAT_803db410 * sVar6) ^
                                               0x80000000) - DOUBLE_803e3348)) / FLOAT_803e333c);
    dVar10 = (double)FUN_80293e80(dVar11);
    *(float *)(param_1 + 0x24) = (float)dVar10;
    dVar10 = (double)FUN_80294204(dVar11);
    *(float *)(param_1 + 0x2c) = (float)dVar10;
    dVar11 = (double)((FLOAT_803e3338 *
                      (float)((double)CONCAT44(0x43300000,
                                               (int)(short)(sVar5 + uVar2 * sVar7) ^ 0x80000000) -
                             DOUBLE_803e3348)) / FLOAT_803e333c);
    dVar10 = (double)FUN_80293e80(dVar11);
    dVar11 = (double)FUN_80294204(dVar11);
    if ((double)FLOAT_803e3330 != dVar11) {
      dVar10 = (double)(float)(dVar10 / dVar11);
    }
    *(float *)(param_1 + 0x28) = (float)dVar10;
    dVar10 = (double)FUN_802931a0((double)(*(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c) +
                                          *(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24) +
                                          *(float *)(param_1 + 0x28) * *(float *)(param_1 + 0x28)));
    fVar1 = (float)((double)FLOAT_803e3340 / dVar10);
    *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * fVar1;
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * fVar1;
    *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar1;
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  return;
}

