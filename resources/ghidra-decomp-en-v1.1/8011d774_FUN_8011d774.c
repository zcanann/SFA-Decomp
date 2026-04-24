// Function: FUN_8011d774
// Entry: 8011d774
// Size: 140 bytes

void FUN_8011d774(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined8 uVar1;
  
  uVar1 = (**(code **)(*DAT_803dd6cc + 0xc))(0x14,5);
  FUN_800199a8(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x15);
  DAT_803de38c = 0;
  DAT_803de388 = FUN_800e81bc();
  if (DAT_803de378 == '\0') {
    FUN_8011cd58();
  }
  else if (DAT_803de378 == '\x01') {
    FUN_8011ca98();
  }
  else {
    FUN_8011c8b0();
  }
  DAT_803de386 = 2;
  DAT_803de385 = 0;
  DAT_803de379 = 0;
  return;
}

