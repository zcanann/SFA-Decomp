// Function: FUN_8015e9cc
// Entry: 8015e9cc
// Size: 188 bytes

undefined4
FUN_8015e9cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80036018(param_9);
  }
  uVar1 = 0xffffffff;
  FUN_80035eec(param_9,10,1,-1);
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6c) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6d) = 1;
  FUN_80033a34(param_9);
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3a70;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3a60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,5,0,uVar1,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  return 0;
}

