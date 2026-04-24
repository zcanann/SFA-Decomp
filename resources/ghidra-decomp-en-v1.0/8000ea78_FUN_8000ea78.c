// Function: FUN_8000ea78
// Entry: 8000ea78
// Size: 272 bytes

void FUN_8000ea78(double param_1,double param_2,double param_3,int *param_4,int *param_5,
                 int *param_6)

{
  double local_18;
  double local_8;
  
  if (param_4 != (int *)0x0) {
    local_18 = (double)CONCAT44(0x43300000,(int)DAT_802c5ed0 >> 2 ^ 0x80000000);
    *param_4 = (int)((float)(param_1 * (double)(float)(local_18 - DOUBLE_803de618)) +
                    (float)((double)CONCAT44(0x43300000,(int)DAT_802c5ed8 >> 2 ^ 0x80000000) -
                           DOUBLE_803de618));
  }
  if (param_5 != (int *)0x0) {
    local_8 = (double)CONCAT44(0x43300000,(int)DAT_802c5ed2 >> 2 ^ 0x80000000);
    *param_5 = (int)((float)(param_2 * (double)(float)(local_8 - DOUBLE_803de618)) +
                    (float)((double)CONCAT44(0x43300000,(int)DAT_802c5eda >> 2 ^ 0x80000000) -
                           DOUBLE_803de618));
    *param_5 = 0x1e0 - *param_5;
  }
  if (param_6 != (int *)0x0) {
    *param_6 = (int)(FLOAT_803de620 * (float)((double)FLOAT_803de5f0 + param_3));
  }
  return;
}

