// Function: FUN_80054ed0
// Entry: 80054ed0
// Size: 92 bytes

undefined4
FUN_80054ed0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  undefined4 local_18 [5];
  
  local_18[0] = 0;
  uVar1 = FUN_800431a4();
  if ((uVar1 & 0x100000) == 0) {
    FUN_8001f79c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_18,param_9,
                 param_11,param_12,param_13,param_14,param_15,param_16);
  }
  else {
    local_18[0] = 0;
  }
  return local_18[0];
}

