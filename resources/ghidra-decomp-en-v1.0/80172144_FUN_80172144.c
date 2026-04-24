// Function: FUN_80172144
// Entry: 80172144
// Size: 664 bytes

/* WARNING: Removing unreachable block (ram,0x801723b4) */
/* WARNING: Removing unreachable block (ram,0x801723ac) */
/* WARNING: Removing unreachable block (ram,0x801723bc) */

void FUN_80172144(int param_1)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0x46) == 0x6a6) {
    FUN_8002b95c((double)FLOAT_803e345c,
                 (double)(*(float *)(param_1 + 0x28) *
                         (float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) - DOUBLE_803e3470))
                 ,(double)FLOAT_803e345c);
  }
  else {
    uVar3 = (uint)DAT_803db410;
    FUN_8002b95c((double)(*(float *)(param_1 + 0x24) *
                         (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e3470)),
                 (double)(*(float *)(param_1 + 0x28) *
                         (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e3470)),
                 (double)(*(float *)(param_1 + 0x2c) *
                         (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e3470)));
  }
  (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1,iVar4 + 0x50);
  (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,iVar4 + 0x50);
  (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,iVar4 + 0x50);
  if (*(char *)(iVar4 + 0x2b1) == '\0') {
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * FLOAT_803e3468;
    *(float *)(param_1 + 0x28) = -(FLOAT_803e346c * FLOAT_803db414 - *(float *)(param_1 + 0x28));
  }
  else {
    dVar9 = -(double)*(float *)(param_1 + 0x24);
    dVar8 = -(double)*(float *)(param_1 + 0x28);
    dVar10 = -(double)*(float *)(param_1 + 0x2c);
    dVar7 = (double)FUN_802931a0((double)(float)(dVar10 * dVar10 +
                                                (double)(float)(dVar9 * dVar9 +
                                                               (double)(float)(dVar8 * dVar8))));
    if ((double)FLOAT_803e345c != dVar7) {
      dVar6 = (double)(float)((double)FLOAT_803e3454 / dVar7);
      dVar9 = (double)(float)(dVar9 * dVar6);
      dVar8 = (double)(float)(dVar8 * dVar6);
      dVar10 = (double)(float)(dVar10 * dVar6);
    }
    fVar1 = *(float *)(iVar4 + 0xbc);
    fVar2 = *(float *)(iVar4 + 0xc0);
    dVar6 = (double)(FLOAT_803e3460 *
                    (float)(dVar10 * (double)fVar2 +
                           (double)(float)(dVar9 * (double)*(float *)(iVar4 + 0xb8) +
                                          (double)(float)(dVar8 * (double)fVar1))));
    *(float *)(param_1 + 0x24) = (float)((double)*(float *)(iVar4 + 0xb8) * dVar6);
    *(float *)(param_1 + 0x28) = (float)((double)fVar1 * dVar6);
    *(float *)(param_1 + 0x2c) = (float)((double)fVar2 * dVar6);
    *(float *)(param_1 + 0x24) = (float)((double)*(float *)(param_1 + 0x24) - dVar9);
    *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) - dVar8);
    *(float *)(param_1 + 0x2c) = (float)((double)*(float *)(param_1 + 0x2c) - dVar10);
    *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) * dVar7);
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * FLOAT_803e3464;
    *(float *)(param_1 + 0x24) = (float)((double)*(float *)(param_1 + 0x24) * dVar7);
    *(float *)(param_1 + 0x2c) = (float)((double)*(float *)(param_1 + 0x2c) * dVar7);
    *(char *)(iVar4 + 0x1d) = *(char *)(iVar4 + 0x1d) + -1;
    if (*(char *)(iVar4 + 0x1d) == '\0') {
      *(undefined *)(iVar4 + 0x1d) = 0;
      fVar1 = FLOAT_803e345c;
      *(float *)(param_1 + 0x24) = FLOAT_803e345c;
      *(float *)(param_1 + 0x28) = fVar1;
      *(float *)(param_1 + 0x2c) = fVar1;
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  return;
}

