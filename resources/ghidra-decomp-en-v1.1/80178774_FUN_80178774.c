// Function: FUN_80178774
// Entry: 80178774
// Size: 112 bytes

void FUN_80178774(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_9 + 0xb8);
  FUN_80178508(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,(int)pfVar1);
  *pfVar1 = FLOAT_803e42d0 *
            (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_10 + 0x1a) ^ 0x80000000) -
                   DOUBLE_803e42d8);
  *(undefined *)((int)pfVar1 + 0x11) = 2;
  return;
}

