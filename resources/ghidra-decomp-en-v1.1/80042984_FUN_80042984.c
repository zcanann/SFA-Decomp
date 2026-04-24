// Function: FUN_80042984
// Entry: 80042984
// Size: 184 bytes

void FUN_80042984(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 0x1000) == 0) {
      if ((DAT_803dd900 & 0x2000) != 0) {
        DAT_803dd904 = DAT_803dd904 | 0x2000;
        DAT_80346cfc = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 0x1000;
      DAT_80346c50 = 0;
    }
  }
  return;
}

