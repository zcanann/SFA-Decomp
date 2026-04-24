// Function: FUN_800ded20
// Entry: 800ded20
// Size: 956 bytes

/* WARNING: Removing unreachable block (ram,0x800df0c0) */
/* WARNING: Removing unreachable block (ram,0x800ded30) */

undefined4
FUN_800ded20(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,float param_10,undefined4 param_11,undefined4 param_12,
            undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  float fVar2;
  uint uVar3;
  undefined4 extraout_r4;
  double dVar4;
  double dVar5;
  double dVar6;
  
  if (param_10 == param_9[0x20]) {
    uVar1 = 0;
  }
  else if ((param_9[0x28] == 0.0) || (param_9[0x27] == 0.0)) {
    uVar1 = 1;
  }
  else {
    dVar6 = (double)*param_9;
    param_9[0x20] = param_10;
    fVar2 = param_9[0x27];
    param_9[0x27] = param_9[0x29];
    param_9[0x29] = fVar2;
    param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
    param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
    dVar4 = (double)FUN_802945e0();
    param_9[0x30] =
         FLOAT_803e1290 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                DOUBLE_803e12a8) * dVar4);
    dVar4 = (double)FUN_802945e0();
    param_9[0x31] =
         FLOAT_803e1290 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                DOUBLE_803e12a8) * dVar4);
    param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
    param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
    dVar4 = (double)FUN_802945e0();
    param_9[0x38] =
         FLOAT_803e1290 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                DOUBLE_803e12a8) * dVar4);
    dVar4 = (double)FUN_802945e0();
    param_9[0x39] =
         FLOAT_803e1290 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                DOUBLE_803e12a8) * dVar4);
    param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
    param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
    dVar4 = (double)FUN_80294964();
    param_9[0x40] =
         FLOAT_803e1290 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                DOUBLE_803e12a8) * dVar4);
    dVar5 = (double)FUN_80294964();
    dVar4 = DOUBLE_803e12a8;
    dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                             (uint)*(byte *)((int)param_9[0x29] +
                                                                            0x2e)) - DOUBLE_803e12a8
                                           ) * dVar5);
    param_9[0x41] = (float)((double)FLOAT_803e1290 * dVar5);
    uVar1 = extraout_r4;
    uVar3 = FUN_800df0dc(dVar5,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    if ((uVar3 & 0xff) == 0) {
      param_9[0x25] = (float)FUN_80010de0;
      param_9[0x26] = (float)&LAB_80010d74;
      param_9[0x21] = (float)(param_9 + 0x2a);
      param_9[0x22] = (float)(param_9 + 0x32);
      param_9[0x23] = (float)(param_9 + 0x3a);
      param_9[0x24] = 1.12104e-44;
      FUN_80010a8c(dVar5,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar1,
                   param_11,param_12,param_13,param_14,param_15,param_16);
      *param_9 = (float)dVar6;
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  return uVar1;
}

