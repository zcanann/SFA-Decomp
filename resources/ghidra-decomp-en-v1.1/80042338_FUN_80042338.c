// Function: FUN_80042338
// Entry: 80042338
// Size: 184 bytes

void FUN_80042338(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x10000000) == 0) {
      if ((DAT_803dd900 & 0x40000000) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x40000000;
        DAT_80346d24 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x10000000;
      DAT_80346c04 = 0;
    }
  }
  return;
}

