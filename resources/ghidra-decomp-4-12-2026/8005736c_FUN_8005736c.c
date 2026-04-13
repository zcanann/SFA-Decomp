// Function: FUN_8005736c
// Entry: 8005736c
// Size: 104 bytes

void FUN_8005736c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char param_9)

{
  if (((DAT_803ddb48 != -1) &&
      (((DAT_803ddb48 != DAT_803ddb44 || (param_9 != '\0')) &&
       (DAT_803ddb44 = DAT_803ddb48, DAT_803ddb48 < 0x76)))) &&
     ((char)(&DAT_8030f11c)[DAT_803ddb48] != -1)) {
    FUN_800199a8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)(char)(&DAT_8030f11c)[DAT_803ddb48]);
  }
  return;
}

