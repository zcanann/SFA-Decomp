// Function: FUN_80235cac
// Entry: 80235cac
// Size: 200 bytes

void FUN_80235cac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  param_9[2] = (ushort)*(byte *)(param_10 + 0x18) << 8;
  param_9[1] = (ushort)*(byte *)(param_10 + 0x19) << 8;
  *param_9 = (ushort)*(byte *)(param_10 + 0x1a) << 8;
  if (*(byte *)(param_10 + 0x1b) != 0) {
    *(float *)(param_9 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_10 + 0x1b)) - DOUBLE_803e7f70) /
         FLOAT_803e7f8c;
    if (*(float *)(param_9 + 4) == FLOAT_803e7f48) {
      *(float *)(param_9 + 4) = FLOAT_803e7f80;
    }
    *(float *)(param_9 + 4) = *(float *)(param_9 + 4) * *(float *)(*(int *)(param_9 + 0x28) + 4);
  }
  param_9[0x58] = param_9[0x58] | 0x2000;
  FUN_8003042c((double)FLOAT_803e7f48,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  return;
}

