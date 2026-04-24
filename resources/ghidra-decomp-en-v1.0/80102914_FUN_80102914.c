// Function: FUN_80102914
// Entry: 80102914
// Size: 240 bytes

void FUN_80102914(double param_1,int param_2,float *param_3,float *param_4,float *param_5,
                 float *param_6,int param_7)

{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(DAT_803dd524 + 0xa4);
  if (param_7 == 0) {
    *param_3 = *(float *)(param_2 + 0x18) - *(float *)(iVar1 + 0x18);
    *param_4 = *(float *)(param_2 + 0x1c) - (float)((double)*(float *)(iVar1 + 0x1c) + param_1);
    *param_5 = *(float *)(param_2 + 0x20) - *(float *)(iVar1 + 0x20);
  }
  else {
    *param_3 = *(float *)(param_2 + 0xc) - *(float *)(iVar1 + 0xc);
    *param_4 = *(float *)(param_2 + 0x10) - (float)((double)*(float *)(iVar1 + 0x10) + param_1);
    *param_5 = *(float *)(param_2 + 0x14) - *(float *)(iVar1 + 0x14);
  }
  if (param_6 != (float *)0x0) {
    *param_6 = *param_3 * *param_3 + *param_5 * *param_5;
    if (FLOAT_803e1630 < *param_6) {
      dVar2 = (double)FUN_802931a0();
      *param_6 = (float)dVar2;
    }
    if (*param_6 < FLOAT_803e1680) {
      *param_6 = FLOAT_803e1680;
    }
  }
  return;
}

