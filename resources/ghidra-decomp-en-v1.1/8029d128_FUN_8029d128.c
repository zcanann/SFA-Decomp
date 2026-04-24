// Function: FUN_8029d128
// Entry: 8029d128
// Size: 1384 bytes

/* WARNING: Removing unreachable block (ram,0x8029d668) */
/* WARNING: Removing unreachable block (ram,0x8029d660) */
/* WARNING: Removing unreachable block (ram,0x8029d658) */
/* WARNING: Removing unreachable block (ram,0x8029d650) */
/* WARNING: Removing unreachable block (ram,0x8029d150) */
/* WARNING: Removing unreachable block (ram,0x8029d148) */
/* WARNING: Removing unreachable block (ram,0x8029d140) */
/* WARNING: Removing unreachable block (ram,0x8029d138) */

int FUN_8029d128(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  short sVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  float local_68 [2];
  undefined8 local_60;
  undefined4 local_58;
  uint uStack_54;
  
  iVar6 = *(int *)(param_9 + 0x5c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    DAT_803dd2d4 = 5;
  }
  iVar4 = FUN_8029c15c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  if (iVar4 == 0) {
    dVar7 = (double)((*(float *)(param_10 + 0x298) - FLOAT_803e8bac) / FLOAT_803e8bc4);
    dVar12 = (double)FLOAT_803e8b3c;
    if ((dVar12 <= dVar7) && (dVar12 = dVar7, (double)FLOAT_803e8b78 < dVar7)) {
      dVar12 = (double)FLOAT_803e8b78;
    }
    local_60 = CONCAT44(0x43300000,*(uint *)(iVar6 + 0x474) ^ 0x80000000);
    dVar7 = (double)FUN_802945e0();
    dVar9 = (double)(*(float *)(iVar6 + 0x404) * (float)(dVar12 * -dVar7));
    uStack_54 = *(uint *)(iVar6 + 0x474) ^ 0x80000000;
    local_58 = 0x43300000;
    dVar7 = (double)FUN_80294964();
    dVar7 = (double)(*(float *)(iVar6 + 0x404) * (float)(dVar12 * -dVar7));
    dVar12 = FUN_80021434((double)(float)(dVar9 - (double)*(float *)(iVar6 + 0x4c8)),
                          (double)FLOAT_803e8bdc,(double)FLOAT_803dc074);
    dVar7 = FUN_80021434((double)(float)(dVar7 - (double)*(float *)(iVar6 + 0x4cc)),
                         (double)FLOAT_803e8bdc,(double)FLOAT_803dc074);
    *(float *)(iVar6 + 0x4c8) = (float)((double)*(float *)(iVar6 + 0x4c8) + dVar12);
    *(float *)(iVar6 + 0x4cc) = (float)((double)*(float *)(iVar6 + 0x4cc) + dVar7);
    dVar12 = FUN_80293900((double)(*(float *)(iVar6 + 0x4c8) * *(float *)(iVar6 + 0x4c8) +
                                  *(float *)(iVar6 + 0x4cc) * *(float *)(iVar6 + 0x4cc)));
    *(float *)(param_10 + 0x294) = (float)dVar12;
    fVar1 = *(float *)(param_10 + 0x294);
    fVar2 = **(float **)(iVar6 + 0x400);
    if ((fVar2 <= fVar1) && (fVar2 = fVar1, *(float *)(iVar6 + 0x404) < fVar1)) {
      fVar2 = *(float *)(iVar6 + 0x404);
    }
    *(float *)(param_10 + 0x294) = fVar2;
    uStack_54 = (int)*(short *)(iVar6 + 0x478) ^ 0x80000000;
    local_58 = 0x43300000;
    dVar12 = (double)FUN_802945e0();
    local_60 = CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x478) ^ 0x80000000);
    dVar7 = (double)FUN_80294964();
    dVar11 = (double)*(float *)(iVar6 + 0x4cc);
    dVar10 = (double)*(float *)(iVar6 + 0x4c8);
    dVar9 = FUN_80021434((double)((float)(-dVar11 * dVar7 - (double)(float)(dVar10 * dVar12)) -
                                 *(float *)(param_10 + 0x280)),(double)*(float *)(iVar6 + 0x82c),
                         (double)FLOAT_803dc074);
    *(float *)(param_10 + 0x280) = (float)((double)*(float *)(param_10 + 0x280) + dVar9);
    dVar9 = (double)*(float *)(iVar6 + 0x82c);
    dVar8 = (double)FLOAT_803dc074;
    dVar12 = FUN_80021434((double)((float)(dVar10 * dVar7 - (double)(float)(dVar11 * dVar12)) -
                                  *(float *)(param_10 + 0x284)),dVar9,dVar8);
    *(float *)(param_10 + 0x284) = (float)((double)*(float *)(param_10 + 0x284) + dVar12);
    dVar12 = (double)*(float *)(param_9 + 0x4c);
    iVar4 = (int)*(char *)(iVar6 + 0x8cc);
    uVar3 = iVar4 >> 1 & 0xff;
    fVar1 = *(float *)(param_10 + 0x294);
    if (*(float *)(&DAT_80333c20 + uVar3 * 4) <= fVar1) {
      if (((float)(&DAT_80333c24)[uVar3] <= fVar1) && (iVar4 < 8)) {
        if (iVar4 == 0) {
          dVar12 = (double)FLOAT_803e8b3c;
        }
        if (fVar1 < *(float *)(iVar6 + 0x404)) {
          *(char *)(iVar6 + 0x8cc) = *(char *)(iVar6 + 0x8cc) + '\x04';
        }
      }
    }
    else if (iVar4 == 4) {
      if (*(float *)(param_10 + 0x298) < FLOAT_803e8bac) {
        *(code **)(param_10 + 0x308) = FUN_8029d028;
        return 0x25;
      }
    }
    else {
      *(char *)(iVar6 + 0x8cc) = *(char *)(iVar6 + 0x8cc) + -4;
    }
    dVar7 = (double)*(float *)(param_10 + 0x284);
    if (dVar7 < (double)FLOAT_803e8b3c) {
      dVar7 = -dVar7;
    }
    dVar10 = (double)*(float *)(param_10 + 0x280);
    if (dVar10 < (double)FLOAT_803e8b3c) {
      dVar10 = -dVar10;
    }
    iVar4 = FUN_8002f6cc((double)*(float *)(param_10 + 0x294),(int)param_9,local_68);
    if (iVar4 != 0) {
      *(float *)(param_10 + 0x2a0) = local_68[0];
    }
    if (dVar10 <= dVar7) {
      if (FLOAT_803e8b3c <= *(float *)(param_10 + 0x284)) {
        *(float *)(param_10 + 0x2a0) = -*(float *)(param_10 + 0x2a0);
      }
      if (((param_9[0x50] != *(short *)(&DAT_80333e74 + *(char *)(iVar6 + 0x8cc) * 2)) &&
          (sVar5 = FUN_8002f604((int)param_9), sVar5 == 0)) &&
         (FUN_8003042c(dVar12,dVar9,dVar8,param_4,param_5,param_6,param_7,param_8,param_9,
                       (int)*(short *)(&DAT_80333e74 + *(char *)(iVar6 + 0x8cc) * 2),0,param_12,
                       param_13,param_14,param_15,param_16), *(char *)(param_10 + 0x27a) == '\0')) {
        FUN_8002f66c((int)param_9,0xc);
      }
    }
    else {
      if (*(float *)(param_10 + 0x280) < FLOAT_803e8b3c) {
        *(float *)(param_10 + 0x2a0) = -*(float *)(param_10 + 0x2a0);
      }
      if (((param_9[0x50] != *(short *)(&DAT_80333e70 + *(char *)(iVar6 + 0x8cc) * 2)) &&
          (sVar5 = FUN_8002f604((int)param_9), sVar5 == 0)) &&
         (FUN_8003042c(dVar12,dVar9,dVar8,param_4,param_5,param_6,param_7,param_8,param_9,
                       (int)*(short *)(&DAT_80333e70 + *(char *)(iVar6 + 0x8cc) * 2),0,param_12,
                       param_13,param_14,param_15,param_16), *(char *)(param_10 + 0x27a) == '\0')) {
        FUN_8002f66c((int)param_9,0xc);
      }
    }
    uStack_54 = *(uint *)(iVar6 + 0x4a4) ^ 0x80000000;
    local_58 = 0x43300000;
    iVar4 = (int)((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e8b58) / FLOAT_803e8c58
                 );
    local_60 = (longlong)iVar4;
    *(short *)(iVar6 + 0x478) = *(short *)(iVar6 + 0x478) + (short)iVar4;
    *(undefined2 *)(iVar6 + 0x484) = *(undefined2 *)(iVar6 + 0x478);
    *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) | 0x2000000;
    FUN_802ac71c(param_9,param_10,iVar6);
    iVar4 = 0;
  }
  return iVar4;
}

