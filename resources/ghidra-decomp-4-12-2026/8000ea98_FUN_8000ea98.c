// Function: FUN_8000ea98
// Entry: 8000ea98
// Size: 272 bytes

void FUN_8000ea98(double param_1,double param_2,double param_3,int *param_4,int *param_5,
                 int *param_6)

{
  undefined8 local_18;
  undefined8 local_8;
  
  if (param_4 != (int *)0x0) {
    local_18 = (double)CONCAT44(0x43300000,(int)DAT_802c6650 >> 2 ^ 0x80000000);
    *param_4 = (int)((float)(param_1 * (double)(float)(local_18 - DOUBLE_803df298)) +
                    (float)((double)CONCAT44(0x43300000,(int)DAT_802c6658 >> 2 ^ 0x80000000) -
                           DOUBLE_803df298));
  }
  if (param_5 != (int *)0x0) {
    local_8 = (double)CONCAT44(0x43300000,(int)DAT_802c6652 >> 2 ^ 0x80000000);
    *param_5 = (int)((float)(param_2 * (double)(float)(local_8 - DOUBLE_803df298)) +
                    (float)((double)CONCAT44(0x43300000,(int)DAT_802c665a >> 2 ^ 0x80000000) -
                           DOUBLE_803df298));
    *param_5 = 0x1e0 - *param_5;
  }
  if (param_6 != (int *)0x0) {
    *param_6 = (int)(FLOAT_803df2a0 * (float)((double)FLOAT_803df270 + param_3));
  }
  return;
}

