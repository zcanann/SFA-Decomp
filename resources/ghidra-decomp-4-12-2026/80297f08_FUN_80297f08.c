// Function: FUN_80297f08
// Entry: 80297f08
// Size: 124 bytes

undefined4
FUN_80297f08(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xe,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e8ba0;
  if (*(char *)(param_10 + 0x346) == '\0') {
    uVar1 = 0;
  }
  else {
    *(undefined4 *)(param_10 + 0x308) = 0;
    uVar1 = 0x41;
  }
  return uVar1;
}

