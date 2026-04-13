// Function: FUN_80042c8c
// Entry: 80042c8c
// Size: 184 bytes

void FUN_80042c8c(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x10) == 0) {
      if ((DAT_803dd900 & 0x20) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x20;
        DAT_80346cf8 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x10;
      DAT_80346c90 = 0;
    }
  }
  return;
}

