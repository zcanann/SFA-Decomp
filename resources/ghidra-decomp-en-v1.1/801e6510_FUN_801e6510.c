// Function: FUN_801e6510
// Entry: 801e6510
// Size: 76 bytes

void FUN_801e6510(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  if (param_9[0x23] != 0x803) {
    *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
    FUN_8003042c((double)FLOAT_803e6630,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

