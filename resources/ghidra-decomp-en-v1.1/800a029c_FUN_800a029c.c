// Function: FUN_800a029c
// Entry: 800a029c
// Size: 336 bytes

void FUN_800a029c(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
                 undefined2 *param_10,int param_11,undefined2 *param_12,int param_13,uint param_14,
                 int param_15)

{
  int iVar1;
  
  DAT_8039caf8 = &DAT_8039cb58;
  iVar1 = (DAT_803ddf0c - DAT_803ddf10) / 0x18 + (DAT_803ddf0c - DAT_803ddf10 >> 0x1f);
  DAT_8039cb55 = (char)iVar1 - (char)(iVar1 >> 0x1f);
  if ((param_15 == 0) && (param_14 == 0)) {
    DAT_8039cb4c = DAT_8039cb4c | 0x2000000;
  }
  else {
    DAT_8039cb4c = DAT_8039cb4c | 0x4000000;
  }
  if ((DAT_8039cb4c & 1) != 0) {
    if (DAT_8039cafc == 0) {
      DAT_8039cb24 = DAT_8039cb24 + *(float *)(param_9 + 0xc);
      DAT_8039cb28 = DAT_8039cb28 + *(float *)(param_9 + 0x10);
      param_1 = (double)DAT_8039cb2c;
      DAT_8039cb2c = (float)(param_1 + (double)*(float *)(param_9 + 0x14));
    }
    else {
      DAT_8039cb24 = DAT_8039cb24 + *(float *)(DAT_8039cafc + 0x18);
      DAT_8039cb28 = DAT_8039cb28 + *(float *)(DAT_8039cafc + 0x1c);
      param_1 = (double)DAT_8039cb2c;
      DAT_8039cb2c = (float)(param_1 + (double)*(float *)(DAT_8039cafc + 0x20));
    }
  }
  DAT_803ddf08 = FUN_800a30e8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              &DAT_8039caf8,0,param_11,param_10,param_13,param_12,param_14,param_15)
  ;
  return;
}

