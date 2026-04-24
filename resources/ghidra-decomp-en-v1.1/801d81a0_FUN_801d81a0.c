// Function: FUN_801d81a0
// Entry: 801d81a0
// Size: 100 bytes

void FUN_801d81a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  
  FUN_80088a84(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
  uVar1 = FUN_80020078(0x13f);
  if (uVar1 == 0) {
    (**(code **)(*DAT_803dd6e8 + 100))();
  }
  uVar1 = FUN_80020078(0x193);
  if (uVar1 != 0) {
    FUN_800201ac(0x194,0);
  }
  return;
}

