// Function: FUN_801bb864
// Entry: 801bb864
// Size: 120 bytes

undefined4
FUN_801bb864(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  float fVar2;
  
  bVar1 = *(char *)(param_10 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    fVar2 = FLOAT_803e5870;
    *(float *)(param_10 + 0x280) = FLOAT_803e5870;
    *(float *)(param_10 + 0x284) = fVar2;
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
  }
  return 0;
}

