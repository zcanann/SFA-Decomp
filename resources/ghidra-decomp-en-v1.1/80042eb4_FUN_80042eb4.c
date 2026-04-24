// Function: FUN_80042eb4
// Entry: 80042eb4
// Size: 184 bytes

void FUN_80042eb4(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 4) == 0) {
      if ((DAT_803dd900 & 8) != 0) {
        DAT_803dd904 = DAT_803dd904 | 8;
        DAT_80346ce4 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 4;
      DAT_80346c78 = 0;
    }
  }
  return;
}

