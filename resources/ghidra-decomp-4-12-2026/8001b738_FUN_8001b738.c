// Function: FUN_8001b738
// Entry: 8001b738
// Size: 124 bytes

void FUN_8001b738(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  
  if (DAT_803dd670 == 0) {
    iVar1 = FUN_80019c44(0);
    if (((iVar1 == 2) && (iVar1 = FUN_80019c28(), DAT_803dd678 == iVar1)) && (DAT_803dd684 == 1)) {
      FUN_8001b86c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  }
  else {
    iVar1 = FUN_80019c44(1);
    if ((iVar1 == 2) && (DAT_803dd684 == 1)) {
      FUN_8001b86c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  }
  return;
}

