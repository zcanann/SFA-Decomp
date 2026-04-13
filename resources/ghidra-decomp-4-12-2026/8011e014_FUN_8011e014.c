// Function: FUN_8011e014
// Entry: 8011e014
// Size: 88 bytes

void FUN_8011e014(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  double dVar1;
  undefined8 uVar2;
  
  FUN_800207ac(1);
  dVar1 = (double)FUN_800206ec(0xff);
  uVar2 = FUN_8012c894(dVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  DAT_803de400 = 0xb;
  DAT_803de55c = FUN_80019c28();
  FUN_800199a8(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
  FLOAT_803de3e4 = FLOAT_803e2ae0;
  DAT_803de458 = 1;
  return;
}

