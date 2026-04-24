// Function: FUN_800423f0
// Entry: 800423f0
// Size: 184 bytes

void FUN_800423f0(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x20000000) == 0) {
      if ((DAT_803dd900 & 0x80000000) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x80000000;
        DAT_80346d28 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x20000000;
      DAT_80346c08 = 0;
    }
  }
  return;
}

