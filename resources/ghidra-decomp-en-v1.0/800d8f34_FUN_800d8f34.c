// Function: FUN_800d8f34
// Entry: 800d8f34
// Size: 92 bytes

void FUN_800d8f34(double param_1,double param_2,double param_3,short *param_4,int param_5)

{
  if (FLOAT_803e05b4 < *(float *)(param_5 + 0x298)) {
    *param_4 = (short)(int)(FLOAT_803e05b8 * (float)((double)(float)(param_2 * param_1) / param_3) +
                           (float)((double)CONCAT44(0x43300000,(int)*param_4 ^ 0x80000000) -
                                  DOUBLE_803e0598));
  }
  return;
}

