// Function: FUN_800da4c8
// Entry: 800da4c8
// Size: 1772 bytes

undefined4
FUN_800da4c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,float param_10,undefined4 param_11,undefined4 param_12,
            undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  undefined4 uVar2;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  double dVar3;
  double dVar4;
  
  fVar1 = param_9[0x28];
  if (((fVar1 == 0.0) || (param_9[0x29] == 0.0)) || (param_10 == 0.0)) {
    uVar2 = 1;
  }
  else {
    if (param_9[0x20] == 0.0) {
      param_9[0x27] = fVar1;
      param_9[0x28] = param_9[0x29];
      param_9[0x29] = param_10;
      FUN_80003494((uint)(param_9 + 0x2a),(uint)(param_9 + 0x2e),0x10);
      FUN_80003494((uint)(param_9 + 0x32),(uint)(param_9 + 0x36),0x10);
      uVar2 = 0x10;
      FUN_80003494((uint)(param_9 + 0x3a),(uint)(param_9 + 0x3e),0x10);
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
                                                                              0x2e)) -
                                             DOUBLE_803e1268) * dVar4);
      param_9[0x41] = (float)((double)FLOAT_803e1250 * dVar4);
      if (param_9[0x24] != 0.0) {
        FUN_80010924(dVar4,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                     extraout_r4_00,uVar2,param_12,param_13,param_14,param_15,param_16);
        if (FLOAT_803e1248 <= *param_9) {
          *param_9 = FLOAT_803e124c;
        }
      }
    }
    else {
      param_9[0x27] = fVar1;
      param_9[0x28] = param_9[0x29];
      param_9[0x29] = param_10;
      FUN_80003494((uint)(param_9 + 0x2e),(uint)(param_9 + 0x2a),0x10);
      FUN_80003494((uint)(param_9 + 0x36),(uint)(param_9 + 0x32),0x10);
      uVar2 = 0x10;
      FUN_80003494((uint)(param_9 + 0x3e),(uint)(param_9 + 0x3a),0x10);
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
                                                                              0x2e)) -
                                             DOUBLE_803e1268) * dVar4);
      param_9[0x3d] = (float)((double)FLOAT_803e1250 * dVar4);
      if (param_9[0x24] != 0.0) {
        FUN_80010924(dVar4,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                     extraout_r4,uVar2,param_12,param_13,param_14,param_15,param_16);
        if (*param_9 <= FLOAT_803e1270) {
          *param_9 = FLOAT_803e1274;
        }
      }
    }
    uVar2 = 0;
  }
  return uVar2;
}

