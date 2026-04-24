// Function: FUN_801a0e30
// Entry: 801a0e30
// Size: 216 bytes

void FUN_801a0e30(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  
  FUN_80037a5c((int)param_9,1);
  *param_9 = (ushort)*(byte *)(param_10 + 0x1a) << 8;
  param_9[0x7a] = 0;
  param_9[0x7b] = 1;
  *(code **)(param_9 + 0x5e) = FUN_801a0b90;
  if (param_9[0x23] == 0x128) {
    uVar1 = FUN_80020078((int)*(short *)(param_10 + 0x18));
    if (uVar1 == 0) {
      FUN_8003042c((double)FLOAT_803e4f4c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    }
    else {
      FUN_8003042c((double)FLOAT_803e4f4c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,0,param_12,param_13,param_14,param_15,param_16);
    }
  }
  else {
    uVar1 = FUN_80020078((int)*(short *)(param_10 + 0x18));
    if (uVar1 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x54))(param_9,0x3c);
    }
  }
  return;
}

