// Function: FUN_8001bd8c
// Entry: 8001bd8c
// Size: 60 bytes

undefined4
FUN_8001bd8c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)

{
  undefined4 uVar1;
  
  uVar1 = DAT_803dd680;
  DAT_803dd680 = param_9;
  if (param_9 == 0) {
    FUN_8001b7b4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return uVar1;
}

