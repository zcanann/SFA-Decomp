// Function: FUN_80042734
// Entry: 80042734
// Size: 184 bytes

void FUN_80042734(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x10000) == 0) {
      if ((DAT_803dd900 & 0x40000) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x40000;
        DAT_80346cec = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x10000;
      DAT_80346c64 = 0;
    }
  }
  return;
}

