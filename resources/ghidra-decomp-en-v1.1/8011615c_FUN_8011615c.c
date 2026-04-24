// Function: FUN_8011615c
// Entry: 8011615c
// Size: 96 bytes

void FUN_8011615c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined8 uVar1;
  
  DAT_803de268 = 1;
  FLOAT_803de26c = FLOAT_803e2980;
  FUN_80043938(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar1 = FUN_80041f28();
  FUN_80043070(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3f);
  uVar1 = FUN_80041f1c();
  uVar1 = FUN_80088e98(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar1 = FUN_8011dc94(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar1 = FUN_8010123c(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_80055464(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x12,'\0',param_11,
               param_12,param_13,param_14,param_15,param_16);
  return;
}

