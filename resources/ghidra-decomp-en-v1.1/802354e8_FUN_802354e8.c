// Function: FUN_802354e8
// Entry: 802354e8
// Size: 216 bytes

void FUN_802354e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  if ((DAT_803dea18 == 0) && (*(char *)(*(int *)(param_9 + 0x4c) + 0x1f) == '\0')) {
    DAT_803dea18 = param_9;
  }
  if (param_9 == DAT_803dea18) {
    param_2 = (double)FLOAT_803dc074;
    for (FLOAT_803dea20 = (float)((double)FLOAT_803e7f24 * param_2 + (double)FLOAT_803dea20);
        FLOAT_803e7f20 < FLOAT_803dea20; FLOAT_803dea20 = FLOAT_803dea20 - FLOAT_803e7f20) {
    }
    for (FLOAT_803dea1c = (float)((double)FLOAT_803e7f28 * param_2 + (double)FLOAT_803dea1c);
        FLOAT_803e7f20 < FLOAT_803dea1c; FLOAT_803dea1c = FLOAT_803dea1c - FLOAT_803e7f20) {
    }
  }
  if ((*(short *)(param_9 + 0x46) < 0x6b2) && (0x6ae < *(short *)(param_9 + 0x46))) {
    FUN_8003042c((double)FLOAT_803dea20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  else {
    FUN_8003042c((double)FLOAT_803dea1c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

