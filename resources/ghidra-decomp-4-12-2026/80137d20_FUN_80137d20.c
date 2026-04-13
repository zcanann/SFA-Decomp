// Function: FUN_80137d20
// Entry: 80137d20
// Size: 104 bytes

void FUN_80137d20(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  FUN_80070050();
  FLOAT_803de658 = FLOAT_803e3048;
  FLOAT_803de65c = FLOAT_803e3048;
  DAT_803de660 = 0;
  DAT_803de661 = 0;
  DAT_803de6a4 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x25d,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803de6a0 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,1,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803de69c = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,2,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803dc87c = &DAT_803aac78;
  return;
}

