// Function: FUN_80042b08
// Entry: 80042b08
// Size: 204 bytes

void FUN_80042b08(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    FUN_800238c4(DAT_803600d8);
    DAT_803600d8 = 0;
    DAT_80346c60 = 0;
    if ((DAT_803dd900 & 0x400) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x400;
      DAT_80346c60 = 0;
    }
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x400) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x400;
      DAT_80346c60 = 0;
    }
  }
  return;
}

