// Function: FUN_80168370
// Entry: 80168370
// Size: 148 bytes

undefined4
FUN_80168370(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  
  if ((*(char *)(param_10 + 0x27a) != '\0') &&
     (FUN_80036018(param_9), *(char *)(param_10 + 0x27a) != '\0')) {
    uVar1 = FUN_80022264(6,7);
    FUN_8003042c((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,uVar1,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3d2c;
  *(undefined *)(param_10 + 0x34d) = 1;
  return 0;
}

