// Function: FUN_800424a8
// Entry: 800424a8
// Size: 184 bytes

void FUN_800424a8(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x1000000) == 0) {
      if ((DAT_803dd900 & 0x4000000) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x4000000;
        DAT_80346d20 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x1000000;
      DAT_80346c3c = 0;
    }
  }
  return;
}

