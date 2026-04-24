// Function: FUN_8011a254
// Entry: 8011a254
// Size: 304 bytes

void FUN_8011a254(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined param_10)

{
  undefined8 uVar1;
  
  if (param_9 == 0) {
    if (DAT_803dc084 == '\0') {
      FUN_8000bb38(0,0x100);
      (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
      DAT_803de34f = 0x23;
      DAT_803de34c = 1;
    }
    else {
      uVar1 = FUN_8000bb38(0,0x419);
      FUN_8011aa8c(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  }
  else {
    DAT_803de34d = 1;
    FUN_8000bb38(0,0x418);
    (**(code **)(*DAT_803dd6cc + 8))(0x14,1);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(0);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(1);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(2);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(3);
    DAT_803de34f = 0x23;
    DAT_803de344 = param_10;
  }
  return;
}

