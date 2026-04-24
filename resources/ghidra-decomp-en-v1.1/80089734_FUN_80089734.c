// Function: FUN_80089734
// Entry: 80089734
// Size: 104 bytes

void FUN_80089734(double param_1,double param_2,double param_3,uint param_4)

{
  if (DAT_803dddac == 0) {
    return;
  }
  if ((param_4 & 1) != 0) {
    *(float *)(DAT_803dddac + 0xa8) = (float)param_1;
    *(float *)(DAT_803dddac + 0xac) = (float)param_2;
    *(float *)(DAT_803dddac + 0xb0) = (float)param_3;
  }
  if ((param_4 & 2) == 0) {
    return;
  }
  *(float *)(DAT_803dddac + 0x14c) = (float)param_1;
  *(float *)(DAT_803dddac + 0x150) = (float)param_2;
  *(float *)(DAT_803dddac + 0x154) = (float)param_3;
  return;
}

