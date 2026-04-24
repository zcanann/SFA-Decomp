// Function: FUN_801725f0
// Entry: 801725f0
// Size: 664 bytes

/* WARNING: Removing unreachable block (ram,0x80172868) */
/* WARNING: Removing unreachable block (ram,0x80172860) */
/* WARNING: Removing unreachable block (ram,0x80172858) */
/* WARNING: Removing unreachable block (ram,0x80172610) */
/* WARNING: Removing unreachable block (ram,0x80172608) */
/* WARNING: Removing unreachable block (ram,0x80172600) */

void FUN_801725f0(int param_1)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0x46) == 0x6a6) {
    FUN_8002ba34((double)FLOAT_803e40f4,
                 (double)(*(float *)(param_1 + 0x28) *
                         (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e4108))
                 ,(double)FLOAT_803e40f4,param_1);
  }
  else {
    uVar3 = (uint)DAT_803dc070;
    FUN_8002ba34((double)(*(float *)(param_1 + 0x24) *
                         (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4108)),
                 (double)(*(float *)(param_1 + 0x28) *
                         (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4108)),
                 (double)(*(float *)(param_1 + 0x2c) *
                         (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4108)),param_1);
  }
  (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_1,iVar4 + 0x50);
  (**(code **)(*DAT_803dd728 + 0x14))(param_1,iVar4 + 0x50);
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_1,iVar4 + 0x50);
  if (*(char *)(iVar4 + 0x2b1) == '\0') {
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * FLOAT_803e4100;
    *(float *)(param_1 + 0x28) = -(FLOAT_803e4104 * FLOAT_803dc074 - *(float *)(param_1 + 0x28));
  }
  else {
    dVar8 = -(double)*(float *)(param_1 + 0x24);
    dVar7 = -(double)*(float *)(param_1 + 0x28);
    dVar9 = -(double)*(float *)(param_1 + 0x2c);
    dVar6 = FUN_80293900((double)(float)(dVar9 * dVar9 +
                                        (double)(float)(dVar8 * dVar8 +
                                                       (double)(float)(dVar7 * dVar7))));
    if ((double)FLOAT_803e40f4 != dVar6) {
      dVar5 = (double)(float)((double)FLOAT_803e40ec / dVar6);
      dVar8 = (double)(float)(dVar8 * dVar5);
      dVar7 = (double)(float)(dVar7 * dVar5);
      dVar9 = (double)(float)(dVar9 * dVar5);
    }
    fVar1 = *(float *)(iVar4 + 0xbc);
    fVar2 = *(float *)(iVar4 + 0xc0);
    dVar5 = (double)(FLOAT_803e40f8 *
                    (float)(dVar9 * (double)fVar2 +
                           (double)(float)(dVar8 * (double)*(float *)(iVar4 + 0xb8) +
                                          (double)(float)(dVar7 * (double)fVar1))));
    *(float *)(param_1 + 0x24) = (float)((double)*(float *)(iVar4 + 0xb8) * dVar5);
    *(float *)(param_1 + 0x28) = (float)((double)fVar1 * dVar5);
    *(float *)(param_1 + 0x2c) = (float)((double)fVar2 * dVar5);
    *(float *)(param_1 + 0x24) = (float)((double)*(float *)(param_1 + 0x24) - dVar8);
    *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) - dVar7);
    *(float *)(param_1 + 0x2c) = (float)((double)*(float *)(param_1 + 0x2c) - dVar9);
    *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) * dVar6);
    *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * FLOAT_803e40fc;
    *(float *)(param_1 + 0x24) = (float)((double)*(float *)(param_1 + 0x24) * dVar6);
    *(float *)(param_1 + 0x2c) = (float)((double)*(float *)(param_1 + 0x2c) * dVar6);
    *(char *)(iVar4 + 0x1d) = *(char *)(iVar4 + 0x1d) + -1;
    if (*(char *)(iVar4 + 0x1d) == '\0') {
      *(undefined *)(iVar4 + 0x1d) = 0;
      fVar1 = FLOAT_803e40f4;
      *(float *)(param_1 + 0x24) = FLOAT_803e40f4;
      *(float *)(param_1 + 0x28) = fVar1;
      *(float *)(param_1 + 0x2c) = fVar1;
    }
  }
  return;
}

