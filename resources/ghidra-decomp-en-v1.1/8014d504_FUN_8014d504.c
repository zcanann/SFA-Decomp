// Function: FUN_8014d504
// Entry: 8014d504
// Size: 128 bytes

void FUN_8014d504(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
                 uint param_11,uint param_12,undefined4 param_13,undefined4 param_14,
                 undefined4 param_15,undefined4 param_16)

{
  if ((double)FLOAT_803e31fc == param_1) {
    *(float *)(param_10 + 0x308) = FLOAT_803e3208;
  }
  else {
    param_2 = (double)FLOAT_803e3200;
    *(float *)(param_10 + 0x308) =
         (float)(param_2 / (double)(float)((double)FLOAT_803e3204 * param_1));
  }
  *(char *)(param_10 + 0x323) = (char)param_13;
  FUN_8003042c((double)FLOAT_803e31fc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,param_11 & 0xff,param_12,param_12,param_13,param_14,param_15,param_16);
  if (*(int *)(param_9 + 0x54) != 0) {
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
  }
  return;
}

