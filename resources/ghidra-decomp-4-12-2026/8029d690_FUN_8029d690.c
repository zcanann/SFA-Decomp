// Function: FUN_8029d690
// Entry: 8029d690
// Size: 800 bytes

/* WARNING: Removing unreachable block (ram,0x8029d98c) */
/* WARNING: Removing unreachable block (ram,0x8029d984) */
/* WARNING: Removing unreachable block (ram,0x8029d97c) */
/* WARNING: Removing unreachable block (ram,0x8029d6b0) */
/* WARNING: Removing unreachable block (ram,0x8029d6a8) */
/* WARNING: Removing unreachable block (ram,0x8029d6a0) */

int FUN_8029d690(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  
  fVar1 = FLOAT_803e8b3c;
  iVar4 = *(int *)(param_9 + 0x5c);
  dVar6 = (double)FLOAT_803e8b3c;
  *(float *)(param_10 + 0x280) = FLOAT_803e8b3c;
  *(float *)(param_10 + 0x284) = fVar1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(float *)(iVar4 + 0x404) = FLOAT_803e8c5c;
    *(undefined *)(iVar4 + 0x8cc) = 0;
    *(float *)(iVar4 + 0x4c8) = fVar1;
    *(float *)(iVar4 + 0x4cc) = fVar1;
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8c1c;
    *(float *)(param_10 + 0x294) = fVar1;
    DAT_803dd2d4 = 5;
  }
  iVar3 = FUN_8029c15c(param_1,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  if (iVar3 == 0) {
    dVar5 = (double)((*(float *)(param_10 + 0x298) - FLOAT_803e8bac) / FLOAT_803e8bc4);
    dVar6 = (double)FLOAT_803e8b3c;
    if ((dVar6 <= dVar5) && (dVar6 = dVar5, (double)FLOAT_803e8b78 < dVar5)) {
      dVar6 = (double)FLOAT_803e8b78;
    }
    dVar5 = (double)FUN_802945e0();
    dVar8 = (double)(*(float *)(iVar4 + 0x404) * (float)(dVar6 * -dVar5));
    dVar5 = (double)FUN_80294964();
    dVar5 = (double)(*(float *)(iVar4 + 0x404) * (float)(dVar6 * -dVar5));
    dVar6 = FUN_80021434((double)(float)(dVar8 - (double)*(float *)(iVar4 + 0x4c8)),
                         (double)FLOAT_803e8bdc,(double)FLOAT_803dc074);
    dVar8 = (double)FLOAT_803e8bdc;
    dVar7 = (double)FLOAT_803dc074;
    dVar5 = FUN_80021434((double)(float)(dVar5 - (double)*(float *)(iVar4 + 0x4cc)),dVar8,dVar7);
    *(float *)(iVar4 + 0x4c8) = (float)((double)*(float *)(iVar4 + 0x4c8) + dVar6);
    *(float *)(iVar4 + 0x4cc) = (float)((double)*(float *)(iVar4 + 0x4cc) + dVar5);
    dVar6 = FUN_80293900((double)(*(float *)(iVar4 + 0x4c8) * *(float *)(iVar4 + 0x4c8) +
                                 *(float *)(iVar4 + 0x4cc) * *(float *)(iVar4 + 0x4cc)));
    *(float *)(param_10 + 0x294) = (float)dVar6;
    fVar1 = *(float *)(param_10 + 0x294);
    fVar2 = FLOAT_803e8b3c;
    if ((FLOAT_803e8b3c <= fVar1) && (fVar2 = fVar1, *(float *)(iVar4 + 0x404) < fVar1)) {
      fVar2 = *(float *)(iVar4 + 0x404);
    }
    *(float *)(param_10 + 0x294) = fVar2;
    if (((*(float *)(param_10 + 0x29c) < FLOAT_803e8c60) ||
        (*(float *)(param_10 + 0x298) < FLOAT_803e8c60)) ||
       (*(float *)(param_10 + 0x294) < DAT_80333c24)) {
      if (param_9[0x50] != 0x8c) {
        FUN_8003042c((double)FLOAT_803e8b3c,dVar8,dVar7,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x8c,0,param_12,param_13,param_14,param_15,param_16);
        if (*(short *)(param_10 + 0x276) == 0x39) {
          FUN_8002f66c((int)param_9,8);
        }
        *(float *)(param_10 + 0x2a0) = FLOAT_803e8c1c;
      }
      *(short *)(iVar4 + 0x478) =
           *(short *)(iVar4 + 0x478) +
           (short)(int)((float)((double)CONCAT44(0x43300000,*(uint *)(iVar4 + 0x4a4) ^ 0x80000000) -
                               DOUBLE_803e8b58) / FLOAT_803e8c58);
      *(undefined2 *)(iVar4 + 0x484) = *(undefined2 *)(iVar4 + 0x478);
      *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x2000000;
      FUN_802ac71c(param_9,param_10,iVar4);
      iVar3 = 0;
    }
    else {
      *(code **)(param_10 + 0x308) = FUN_8029d028;
      iVar3 = 0x26;
    }
  }
  return iVar3;
}

