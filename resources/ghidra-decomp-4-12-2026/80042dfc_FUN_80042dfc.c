// Function: FUN_80042dfc
// Entry: 80042dfc
// Size: 184 bytes

void FUN_80042dfc(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x40) == 0) {
      if ((DAT_803dd900 & 0x80) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x80;
        DAT_80346cf4 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x40;
      DAT_80346c8c = 0;
    }
  }
  return;
}

