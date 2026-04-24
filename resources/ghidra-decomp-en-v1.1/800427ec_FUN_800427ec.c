// Function: FUN_800427ec
// Entry: 800427ec
// Size: 204 bytes

void FUN_800427ec(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    FUN_800238c4(DAT_80360180);
    DAT_80360180 = 0;
    DAT_80346d08 = 0;
    if ((DAT_803dd900 & 0x8000) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x8000;
      DAT_80346d00 = 0;
    }
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x8000) != 0) {
      DAT_803dd904 = DAT_803dd904 | 0x8000;
      DAT_80346d00 = 0;
    }
  }
  return;
}

