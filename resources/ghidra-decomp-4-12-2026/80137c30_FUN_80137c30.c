// Function: FUN_80137c30
// Entry: 80137c30
// Size: 160 bytes

void FUN_80137c30(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte in_cr1;
  char *local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  char local_18 [4];
  undefined *local_14;
  char **local_10;
  
  if ((bool)(in_cr1 >> 1 & 1)) {
    local_58 = param_1;
    local_50 = param_2;
    local_48 = param_3;
    local_40 = param_4;
    local_38 = param_5;
    local_30 = param_6;
    local_28 = param_7;
    local_20 = param_8;
  }
  if (DAT_803dc87c + 0x7fc55388 < 0x1001) {
    local_18[0] = '\x01';
    local_18[1] = '\0';
    local_18[2] = '\0';
    local_18[3] = '\0';
    local_14 = &stack0x00000008;
    local_10 = &local_78;
    local_78 = param_9;
    local_74 = param_10;
    local_70 = param_11;
    local_6c = param_12;
    local_68 = param_13;
    local_64 = param_14;
    local_60 = param_15;
    local_5c = param_16;
    FUN_8028fec8(DAT_803dc87c,param_9,local_18);
  }
  return;
}

