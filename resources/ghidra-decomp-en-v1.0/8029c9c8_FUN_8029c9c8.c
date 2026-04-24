// Function: FUN_8029c9c8
// Entry: 8029c9c8
// Size: 1384 bytes

/* WARNING: Removing unreachable block (ram,0x8029cf00) */
/* WARNING: Removing unreachable block (ram,0x8029cef0) */
/* WARNING: Removing unreachable block (ram,0x8029cef8) */
/* WARNING: Removing unreachable block (ram,0x8029cf08) */

int FUN_8029c9c8(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f28;
  double dVar8;
  double dVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  undefined4 local_68 [2];
  double local_60;
  undefined4 local_58;
  uint uStack84;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  iVar5 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    DAT_803dc66c = 5;
  }
  iVar4 = FUN_8029b9fc(param_1,param_2);
  if (iVar4 == 0) {
    dVar7 = (double)((*(float *)(param_2 + 0x298) - FLOAT_803e7f14) / FLOAT_803e7f2c);
    dVar11 = (double)FLOAT_803e7ea4;
    if ((dVar11 <= dVar7) && (dVar11 = dVar7, (double)FLOAT_803e7ee0 < dVar7)) {
      dVar11 = (double)FLOAT_803e7ee0;
    }
    local_60 = (double)CONCAT44(0x43300000,*(uint *)(iVar5 + 0x474) ^ 0x80000000);
    dVar7 = (double)FUN_80293e80((double)((FLOAT_803e7f94 * (float)(local_60 - DOUBLE_803e7ec0)) /
                                         FLOAT_803e7f98));
    dVar8 = (double)(*(float *)(iVar5 + 0x404) * (float)(dVar11 * -dVar7));
    uStack84 = *(uint *)(iVar5 + 0x474) ^ 0x80000000;
    local_58 = 0x43300000;
    dVar7 = (double)FUN_80294204((double)((FLOAT_803e7f94 *
                                          (float)((double)CONCAT44(0x43300000,uStack84) -
                                                 DOUBLE_803e7ec0)) / FLOAT_803e7f98));
    dVar7 = (double)(*(float *)(iVar5 + 0x404) * (float)(dVar11 * -dVar7));
    dVar11 = (double)FUN_80021370((double)(float)(dVar8 - (double)*(float *)(iVar5 + 0x4c8)),
                                  (double)FLOAT_803e7f44,(double)FLOAT_803db414);
    dVar7 = (double)FUN_80021370((double)(float)(dVar7 - (double)*(float *)(iVar5 + 0x4cc)),
                                 (double)FLOAT_803e7f44,(double)FLOAT_803db414);
    *(float *)(iVar5 + 0x4c8) = (float)((double)*(float *)(iVar5 + 0x4c8) + dVar11);
    *(float *)(iVar5 + 0x4cc) = (float)((double)*(float *)(iVar5 + 0x4cc) + dVar7);
    dVar11 = (double)FUN_802931a0((double)(*(float *)(iVar5 + 0x4c8) * *(float *)(iVar5 + 0x4c8) +
                                          *(float *)(iVar5 + 0x4cc) * *(float *)(iVar5 + 0x4cc)));
    *(float *)(param_2 + 0x294) = (float)dVar11;
    fVar1 = *(float *)(param_2 + 0x294);
    fVar2 = **(float **)(iVar5 + 0x400);
    if ((fVar2 <= fVar1) && (fVar2 = fVar1, *(float *)(iVar5 + 0x404) < fVar1)) {
      fVar2 = *(float *)(iVar5 + 0x404);
    }
    *(float *)(param_2 + 0x294) = fVar2;
    uStack84 = (int)*(short *)(iVar5 + 0x478) ^ 0x80000000;
    local_58 = 0x43300000;
    dVar11 = (double)FUN_80293e80((double)((FLOAT_803e7f94 *
                                           (float)((double)CONCAT44(0x43300000,uStack84) -
                                                  DOUBLE_803e7ec0)) / FLOAT_803e7f98));
    local_60 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x478) ^ 0x80000000);
    dVar7 = (double)FUN_80294204((double)((FLOAT_803e7f94 * (float)(local_60 - DOUBLE_803e7ec0)) /
                                         FLOAT_803e7f98));
    dVar10 = (double)*(float *)(iVar5 + 0x4cc);
    dVar9 = (double)*(float *)(iVar5 + 0x4c8);
    dVar8 = (double)FUN_80021370((double)((float)(-dVar10 * dVar7 - (double)(float)(dVar9 * dVar11))
                                         - *(float *)(param_2 + 0x280)),
                                 (double)*(float *)(iVar5 + 0x82c),(double)FLOAT_803db414);
    *(float *)(param_2 + 0x280) = (float)((double)*(float *)(param_2 + 0x280) + dVar8);
    dVar11 = (double)FUN_80021370((double)((float)(dVar9 * dVar7 - (double)(float)(dVar10 * dVar11))
                                          - *(float *)(param_2 + 0x284)),
                                  (double)*(float *)(iVar5 + 0x82c),(double)FLOAT_803db414);
    *(float *)(param_2 + 0x284) = (float)((double)*(float *)(param_2 + 0x284) + dVar11);
    dVar11 = (double)*(float *)(param_1 + 0x98);
    iVar4 = (int)*(char *)(iVar5 + 0x8cc);
    uVar3 = iVar4 >> 1 & 0xff;
    fVar1 = *(float *)(param_2 + 0x294);
    if (*(float *)(&DAT_80332fc0 + uVar3 * 4) <= fVar1) {
      if (((float)(&DAT_80332fc4)[uVar3] <= fVar1) && (iVar4 < 8)) {
        if (iVar4 == 0) {
          dVar11 = (double)FLOAT_803e7ea4;
        }
        if (fVar1 < *(float *)(iVar5 + 0x404)) {
          *(char *)(iVar5 + 0x8cc) = *(char *)(iVar5 + 0x8cc) + '\x04';
        }
      }
    }
    else if (iVar4 == 4) {
      if (*(float *)(param_2 + 0x298) < FLOAT_803e7f14) {
        *(code **)(param_2 + 0x308) = FUN_8029c8c8;
        iVar4 = 0x25;
        goto LAB_8029cef0;
      }
    }
    else {
      *(char *)(iVar5 + 0x8cc) = *(char *)(iVar5 + 0x8cc) + -4;
    }
    dVar7 = (double)*(float *)(param_2 + 0x284);
    if (dVar7 < (double)FLOAT_803e7ea4) {
      dVar7 = -dVar7;
    }
    dVar8 = (double)*(float *)(param_2 + 0x280);
    if (dVar8 < (double)FLOAT_803e7ea4) {
      dVar8 = -dVar8;
    }
    iVar4 = FUN_8002f5d4((double)*(float *)(param_2 + 0x294),param_1,local_68);
    if (iVar4 != 0) {
      *(undefined4 *)(param_2 + 0x2a0) = local_68[0];
    }
    if (dVar8 <= dVar7) {
      if (FLOAT_803e7ea4 <= *(float *)(param_2 + 0x284)) {
        *(float *)(param_2 + 0x2a0) = -*(float *)(param_2 + 0x2a0);
      }
      if (((*(short *)(param_1 + 0xa0) != *(short *)(&DAT_80333214 + *(char *)(iVar5 + 0x8cc) * 2))
          && (iVar4 = FUN_8002f50c(param_1), iVar4 == 0)) &&
         (FUN_80030334(dVar11,param_1,(int)*(short *)(&DAT_80333214 + *(char *)(iVar5 + 0x8cc) * 2),
                       0), *(char *)(param_2 + 0x27a) == '\0')) {
        FUN_8002f574(param_1,0xc);
      }
    }
    else {
      if (*(float *)(param_2 + 0x280) < FLOAT_803e7ea4) {
        *(float *)(param_2 + 0x2a0) = -*(float *)(param_2 + 0x2a0);
      }
      if (((*(short *)(param_1 + 0xa0) != *(short *)(&DAT_80333210 + *(char *)(iVar5 + 0x8cc) * 2))
          && (iVar4 = FUN_8002f50c(param_1), iVar4 == 0)) &&
         (FUN_80030334(dVar11,param_1,(int)*(short *)(&DAT_80333210 + *(char *)(iVar5 + 0x8cc) * 2),
                       0), *(char *)(param_2 + 0x27a) == '\0')) {
        FUN_8002f574(param_1,0xc);
      }
    }
    uStack84 = *(uint *)(iVar5 + 0x4a4) ^ 0x80000000;
    local_58 = 0x43300000;
    iVar4 = (int)((float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e7ec0) / FLOAT_803e7fc0)
    ;
    local_60 = (double)(longlong)iVar4;
    *(short *)(iVar5 + 0x478) = *(short *)(iVar5 + 0x478) + (short)iVar4;
    *(undefined2 *)(iVar5 + 0x484) = *(undefined2 *)(iVar5 + 0x478);
    *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x2000000;
    FUN_802abfbc(param_1,param_2,iVar5);
    iVar4 = 0;
  }
LAB_8029cef0:
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  __psq_l0(auStack56,uVar6);
  __psq_l1(auStack56,uVar6);
  return iVar4;
}

