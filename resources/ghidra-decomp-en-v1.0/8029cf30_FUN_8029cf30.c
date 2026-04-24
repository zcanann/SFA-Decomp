// Function: FUN_8029cf30
// Entry: 8029cf30
// Size: 800 bytes

/* WARNING: Removing unreachable block (ram,0x8029d224) */
/* WARNING: Removing unreachable block (ram,0x8029d21c) */
/* WARNING: Removing unreachable block (ram,0x8029d22c) */

int FUN_8029cf30(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  double local_58;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  fVar1 = FLOAT_803e7ea4;
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar4 = *(int *)(param_1 + 0xb8);
  *(float *)(param_2 + 0x280) = FLOAT_803e7ea4;
  *(float *)(param_2 + 0x284) = fVar1;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(float *)(iVar4 + 0x404) = FLOAT_803e7fc4;
    *(undefined *)(iVar4 + 0x8cc) = 0;
    *(float *)(iVar4 + 0x4c8) = fVar1;
    *(float *)(iVar4 + 0x4cc) = fVar1;
    *(float *)(param_2 + 0x2a0) = FLOAT_803e7f84;
    *(float *)(param_2 + 0x294) = fVar1;
    DAT_803dc66c = 5;
  }
  iVar3 = FUN_8029b9fc(param_1,param_2);
  if (iVar3 == 0) {
    dVar6 = (double)((*(float *)(param_2 + 0x298) - FLOAT_803e7f14) / FLOAT_803e7f2c);
    dVar8 = (double)FLOAT_803e7ea4;
    if ((dVar8 <= dVar6) && (dVar8 = dVar6, (double)FLOAT_803e7ee0 < dVar6)) {
      dVar8 = (double)FLOAT_803e7ee0;
    }
    local_58 = (double)CONCAT44(0x43300000,*(uint *)(iVar4 + 0x474) ^ 0x80000000);
    dVar6 = (double)FUN_80293e80((double)((FLOAT_803e7f94 * (float)(local_58 - DOUBLE_803e7ec0)) /
                                         FLOAT_803e7f98));
    dVar7 = (double)(*(float *)(iVar4 + 0x404) * (float)(dVar8 * -dVar6));
    dVar6 = (double)FUN_80294204((double)((FLOAT_803e7f94 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   *(uint *)(iVar4 + 0x474) ^
                                                                   0x80000000) - DOUBLE_803e7ec0)) /
                                         FLOAT_803e7f98));
    dVar6 = (double)(*(float *)(iVar4 + 0x404) * (float)(dVar8 * -dVar6));
    dVar8 = (double)FUN_80021370((double)(float)(dVar7 - (double)*(float *)(iVar4 + 0x4c8)),
                                 (double)FLOAT_803e7f44,(double)FLOAT_803db414);
    dVar6 = (double)FUN_80021370((double)(float)(dVar6 - (double)*(float *)(iVar4 + 0x4cc)),
                                 (double)FLOAT_803e7f44,(double)FLOAT_803db414);
    *(float *)(iVar4 + 0x4c8) = (float)((double)*(float *)(iVar4 + 0x4c8) + dVar8);
    *(float *)(iVar4 + 0x4cc) = (float)((double)*(float *)(iVar4 + 0x4cc) + dVar6);
    dVar8 = (double)FUN_802931a0((double)(*(float *)(iVar4 + 0x4c8) * *(float *)(iVar4 + 0x4c8) +
                                         *(float *)(iVar4 + 0x4cc) * *(float *)(iVar4 + 0x4cc)));
    *(float *)(param_2 + 0x294) = (float)dVar8;
    fVar1 = *(float *)(param_2 + 0x294);
    fVar2 = FLOAT_803e7ea4;
    if ((FLOAT_803e7ea4 <= fVar1) && (fVar2 = fVar1, *(float *)(iVar4 + 0x404) < fVar1)) {
      fVar2 = *(float *)(iVar4 + 0x404);
    }
    *(float *)(param_2 + 0x294) = fVar2;
    if (((*(float *)(param_2 + 0x29c) < FLOAT_803e7fc8) ||
        (*(float *)(param_2 + 0x298) < FLOAT_803e7fc8)) ||
       (*(float *)(param_2 + 0x294) < DAT_80332fc4)) {
      if (*(short *)(param_1 + 0xa0) != 0x8c) {
        FUN_80030334((double)FLOAT_803e7ea4,param_1,0x8c,0);
        if (*(short *)(param_2 + 0x276) == 0x39) {
          FUN_8002f574(param_1,8);
        }
        *(float *)(param_2 + 0x2a0) = FLOAT_803e7f84;
      }
      *(short *)(iVar4 + 0x478) =
           *(short *)(iVar4 + 0x478) +
           (short)(int)((float)((double)CONCAT44(0x43300000,*(uint *)(iVar4 + 0x4a4) ^ 0x80000000) -
                               DOUBLE_803e7ec0) / FLOAT_803e7fc0);
      *(undefined2 *)(iVar4 + 0x484) = *(undefined2 *)(iVar4 + 0x478);
      *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x2000000;
      FUN_802abfbc(param_1,param_2,iVar4);
      iVar3 = 0;
    }
    else {
      *(code **)(param_2 + 0x308) = FUN_8029c8c8;
      iVar3 = 0x26;
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  return iVar3;
}

