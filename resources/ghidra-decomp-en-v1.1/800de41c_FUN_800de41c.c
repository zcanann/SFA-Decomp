// Function: FUN_800de41c
// Entry: 800de41c
// Size: 1876 bytes

undefined4
FUN_800de41c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,uint param_10,undefined4 param_11,int param_12,int param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  undefined4 uVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  
  if (((param_9 != (float *)0x0) && (param_9[0x28] != 0.0)) && (param_9[0x29] != 0.0)) {
    param_9[0x27] = param_9[0x28];
    param_9[0x28] = param_9[0x29];
    FUN_80003494((uint)(param_9 + 0x2a),(uint)(param_9 + 0x2e),0x10);
    FUN_80003494((uint)(param_9 + 0x32),(uint)(param_9 + 0x36),0x10);
    FUN_80003494((uint)(param_9 + 0x3a),(uint)(param_9 + 0x3e),0x10);
    if (param_9[0x20] == 0.0) {
      uVar1 = FUN_800de2c4((int)param_9[0x28],-1,param_10);
    }
    else {
      uVar1 = FUN_800de16c((int)param_9[0x28],-1,param_10);
    }
    if (uVar1 == 0xffffffff) {
      param_9[0x29] = 0.0;
    }
    else {
      if ((int)uVar1 < 0) {
        fVar3 = 0.0;
      }
      else {
        param_13 = DAT_803de0f0 + -1;
        param_12 = 0;
        while (param_12 <= param_13) {
          param_10 = param_13 + param_12 >> 1;
          fVar3 = (float)(&DAT_803a2448)[param_10];
          if (*(uint *)((int)fVar3 + 0x14) < uVar1) {
            param_12 = param_10 + 1;
          }
          else {
            if (*(uint *)((int)fVar3 + 0x14) <= uVar1) goto LAB_800de544;
            param_13 = param_10 - 1;
          }
        }
        fVar3 = 0.0;
      }
LAB_800de544:
      param_9[0x29] = fVar3;
      if (param_9[0x29] != 0.0) {
        if (param_9[0x20] == 0.0) {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
          dVar4 = (double)FUN_802945e0();
          param_9[0x30] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar4 = (double)FUN_802945e0();
          param_9[0x31] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x29] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
          dVar4 = (double)FUN_802945e0();
          param_9[0x38] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar4 = (double)FUN_802945e0();
          param_9[0x39] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x29] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
          dVar4 = (double)FUN_80294964();
          param_9[0x40] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar5 = (double)FUN_80294964();
          dVar4 = DOUBLE_803e12a8;
          dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (uint)*(byte *)((int)param_9[0x29
                                                  ] + 0x2e)) - DOUBLE_803e12a8) * dVar5);
          param_9[0x41] = (float)((double)FLOAT_803e1290 * dVar5);
          uVar2 = extraout_r4_00;
        }
        else {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x27] + 8);
          dVar4 = (double)FUN_802945e0();
          param_9[0x30] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar4 = (double)FUN_802945e0();
          param_9[0x31] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x27] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x27] + 0xc);
          dVar4 = (double)FUN_802945e0();
          param_9[0x38] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar4 = (double)FUN_802945e0();
          param_9[0x39] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x27] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x27] + 0x10);
          dVar4 = (double)FUN_80294964();
          param_9[0x40] =
               FLOAT_803e1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar5 = (double)FUN_80294964();
          dVar4 = DOUBLE_803e12a8;
          dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (uint)*(byte *)((int)param_9[0x27
                                                  ] + 0x2e)) - DOUBLE_803e12a8) * dVar5);
          param_9[0x41] = (float)((double)FLOAT_803e1290 * dVar5);
          uVar2 = extraout_r4;
        }
        if (param_9[0x24] != 0.0) {
          FUN_80010924(dVar5,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                       uVar2,param_10,param_12,param_13,fVar3,param_15,param_16);
        }
        if (param_9[0x20] == 0.0) {
          FUN_80010340((double)FLOAT_803e12b4,param_9);
        }
        else {
          FUN_80010340((double)FLOAT_803e12b0,param_9);
        }
        return 0;
      }
    }
  }
  return 1;
}

