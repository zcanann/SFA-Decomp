// Function: FUN_800dac0c
// Entry: 800dac0c
// Size: 1628 bytes

bool FUN_800dac0c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 float *param_9,float param_10,float param_11,float param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  float fVar2;
  double dVar3;
  double dVar4;
  
  fVar2 = param_12;
  if (param_9[0x20] == 0.0) {
    param_9[0x28] = param_10;
    param_9[0x29] = param_11;
    param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
    param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
    dVar3 = (double)FUN_802945e0();
    param_9[0x30] =
         FLOAT_803e1250 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                DOUBLE_803e1268) * dVar3);
    dVar3 = (double)FUN_802945e0();
    param_9[0x31] =
         FLOAT_803e1250 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                DOUBLE_803e1268) * dVar3);
    param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
    param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
    dVar3 = (double)FUN_802945e0();
    param_9[0x38] =
         FLOAT_803e1250 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                DOUBLE_803e1268) * dVar3);
    dVar3 = (double)FUN_802945e0();
    param_9[0x39] =
         FLOAT_803e1250 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                DOUBLE_803e1268) * dVar3);
    param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
    param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
    dVar3 = (double)FUN_80294964();
    param_9[0x40] =
         FLOAT_803e1250 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                DOUBLE_803e1268) * dVar3);
    dVar4 = (double)FUN_80294964();
    dVar3 = DOUBLE_803e1268;
    dVar4 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                             (uint)*(byte *)((int)param_9[0x29] +
                                                                            0x2e)) - DOUBLE_803e1268
                                           ) * dVar4);
    param_9[0x41] = (float)((double)FLOAT_803e1250 * dVar4);
  }
  else {
    param_9[0x28] = param_10;
    param_9[0x29] = param_11;
    param_9[0x2a] = *(float *)((int)param_9[0x29] + 8);
    param_9[0x2b] = *(float *)((int)param_9[0x28] + 8);
    dVar3 = (double)FUN_802945e0();
    param_9[0x2c] =
         FLOAT_803e1250 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                DOUBLE_803e1268) * dVar3);
    dVar3 = (double)FUN_802945e0();
    param_9[0x2d] =
         FLOAT_803e1250 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                DOUBLE_803e1268) * dVar3);
    param_9[0x32] = *(float *)((int)param_9[0x29] + 0xc);
    param_9[0x33] = *(float *)((int)param_9[0x28] + 0xc);
    dVar3 = (double)FUN_802945e0();
    param_9[0x34] =
         FLOAT_803e1250 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                DOUBLE_803e1268) * dVar3);
    dVar3 = (double)FUN_802945e0();
    param_9[0x35] =
         FLOAT_803e1250 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                DOUBLE_803e1268) * dVar3);
    param_9[0x3a] = *(float *)((int)param_9[0x29] + 0x10);
    param_9[0x3b] = *(float *)((int)param_9[0x28] + 0x10);
    dVar3 = (double)FUN_80294964();
    param_9[0x3c] =
         FLOAT_803e1250 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                DOUBLE_803e1268) * dVar3);
    dVar4 = (double)FUN_80294964();
    dVar3 = DOUBLE_803e1268;
    dVar4 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                             (uint)*(byte *)((int)param_9[0x28] +
                                                                            0x2e)) - DOUBLE_803e1268
                                           ) * dVar4);
    param_9[0x3d] = (float)((double)FLOAT_803e1250 * dVar4);
  }
  iVar1 = FUN_800da4c8(dVar4,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_12,
                       param_11,fVar2,param_13,param_14,param_15,param_16);
  if (iVar1 == 0) {
    param_9[0x25] = (float)FUN_80010de0;
    param_9[0x26] = (float)&LAB_80010d74;
    param_9[0x21] = (float)(param_9 + 0x2a);
    param_9[0x22] = (float)(param_9 + 0x32);
    param_9[0x23] = (float)(param_9 + 0x3a);
    param_9[0x24] = 1.12104e-44;
    FUN_80010a8c(dVar4,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_12,
                 param_11,fVar2,param_13,param_14,param_15,param_16);
  }
  return iVar1 != 0;
}

