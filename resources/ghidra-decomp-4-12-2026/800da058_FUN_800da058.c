// Function: FUN_800da058
// Entry: 800da058
// Size: 128 bytes

void FUN_800da058(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11)

{
  byte bVar1;
  
  bVar1 = FUN_80014074();
  if (bVar1 != 0) {
    param_1 = FUN_800140dc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  FUN_80014080(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  (**(code **)(*DAT_803dd6e8 + 0xc))(param_9,param_10,param_11);
  return;
}

