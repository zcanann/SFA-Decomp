// Function: FUN_80042bd4
// Entry: 80042bd4
// Size: 184 bytes

void FUN_80042bd4(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x100) == 0) {
      if ((DAT_803dd900 & 0x200) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x200;
        DAT_80346d04 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x100;
      DAT_80346c5c = 0;
    }
  }
  return;
}

