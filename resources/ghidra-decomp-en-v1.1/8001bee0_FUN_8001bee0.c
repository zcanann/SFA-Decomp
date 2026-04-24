// Function: FUN_8001bee0
// Entry: 8001bee0
// Size: 100 bytes

void FUN_8001bee0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  if (param_9 == 3) {
    DAT_8033cab4 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                0x43b,param_10,param_11,param_12,param_13,param_14,param_15,param_16
                               );
    DAT_8033cab8 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                0x43e,&DAT_8033cab4,param_11,param_12,param_13,param_14,param_15,
                                param_16);
    DAT_8033cabc = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                0x43d,&DAT_8033cab4,param_11,param_12,param_13,param_14,param_15,
                                param_16);
  }
  return;
}

