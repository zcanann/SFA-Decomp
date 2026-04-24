// Function: FUN_8021bf40
// Entry: 8021bf40
// Size: 1796 bytes

undefined4
FUN_8021bf40(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,uint param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13
            ,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  float fVar2;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  
  if (((param_9 != (float *)0x0) && (param_9[0x28] != 0.0)) && (param_9[0x29] != 0.0)) {
    param_9[0x27] = param_9[0x28];
    param_9[0x28] = param_9[0x29];
    FUN_80003494((uint)(param_9 + 0x2a),(uint)(param_9 + 0x2e),0x10);
    FUN_80003494((uint)(param_9 + 0x32),(uint)(param_9 + 0x36),0x10);
    FUN_80003494((uint)(param_9 + 0x3a),(uint)(param_9 + 0x3e),0x10);
    if (param_9[0x20] == 0.0) {
      iVar1 = FUN_8021bde0((int)param_9[0x28],-1,param_10);
    }
    else {
      iVar1 = FUN_8021bc80((int)param_9[0x28],-1,param_10);
    }
    if (iVar1 == -1) {
      param_9[0x29] = 0.0;
    }
    else {
      fVar2 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      param_9[0x29] = fVar2;
      if (param_9[0x29] != 0.0) {
        if (param_9[0x20] == 0.0) {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
          dVar4 = (double)FUN_802945e0();
          param_9[0x30] =
               FLOAT_803e76d0 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e7700) * dVar4);
          dVar4 = (double)FUN_802945e0();
          param_9[0x31] =
               FLOAT_803e76d0 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x29] + 0x2e))
                                      - DOUBLE_803e7700) * dVar4);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
          dVar4 = (double)FUN_802945e0();
          param_9[0x38] =
               FLOAT_803e76d0 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e7700) * dVar4);
          dVar4 = (double)FUN_802945e0();
          param_9[0x39] =
               FLOAT_803e76d0 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x29] + 0x2e))
                                      - DOUBLE_803e7700) * dVar4);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
          dVar4 = (double)FUN_80294964();
          param_9[0x40] =
               FLOAT_803e76d0 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e7700) * dVar4);
          dVar5 = (double)FUN_80294964();
          dVar4 = DOUBLE_803e7700;
          dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (uint)*(byte *)((int)param_9[0x29
                                                  ] + 0x2e)) - DOUBLE_803e7700) * dVar5);
          param_9[0x41] = (float)((double)FLOAT_803e76d0 * dVar5);
          uVar3 = extraout_r4_00;
        }
        else {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x27] + 8);
          dVar4 = (double)FUN_802945e0();
          param_9[0x30] =
               FLOAT_803e76d0 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e7700) * dVar4);
          dVar4 = (double)FUN_802945e0();
          param_9[0x31] =
               FLOAT_803e76d0 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x27] + 0x2e))
                                      - DOUBLE_803e7700) * dVar4);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x27] + 0xc);
          dVar4 = (double)FUN_802945e0();
          param_9[0x38] =
               FLOAT_803e76d0 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e7700) * dVar4);
          dVar4 = (double)FUN_802945e0();
          param_9[0x39] =
               FLOAT_803e76d0 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x27] + 0x2e))
                                      - DOUBLE_803e7700) * dVar4);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x27] + 0x10);
          dVar4 = (double)FUN_80294964();
          param_9[0x40] =
               FLOAT_803e76d0 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e7700) * dVar4);
          dVar5 = (double)FUN_80294964();
          dVar4 = DOUBLE_803e7700;
          dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (uint)*(byte *)((int)param_9[0x27
                                                  ] + 0x2e)) - DOUBLE_803e7700) * dVar5);
          param_9[0x41] = (float)((double)FLOAT_803e76d0 * dVar5);
          uVar3 = extraout_r4;
        }
        if (param_9[0x24] != 0.0) {
          FUN_80010924(dVar5,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                       uVar3,param_10,param_12,param_13,param_14,param_15,param_16);
        }
        if (param_9[0x20] == 0.0) {
          FUN_80010340((double)FLOAT_803e76e0,param_9);
        }
        else {
          FUN_80010340((double)FLOAT_803e7708,param_9);
        }
        return 0;
      }
    }
  }
  return 1;
}

