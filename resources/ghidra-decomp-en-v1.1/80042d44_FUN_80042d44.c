// Function: FUN_80042d44
// Entry: 80042d44
// Size: 184 bytes

void FUN_80042d44(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    if ((DAT_803dd900 & 1) == 0) {
      if ((DAT_803dd900 & 2) != 0) {
        DAT_803dd904 = DAT_803dd904 | 2;
        DAT_80346ce8 = 0;
      }
    }
    else {
      DAT_803dd904 = DAT_803dd904 | 1;
      DAT_80346c7c = 0;
    }
  }
  return;
}

