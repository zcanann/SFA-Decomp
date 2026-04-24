// Function: FUN_80117b68
// Entry: 80117b68
// Size: 268 bytes

undefined4 FUN_80117b68(uint param_1,int param_2)

{
  undefined4 uVar1;
  
  if ((DAT_803a5df8 == 0) || (DAT_803a5dff == '\0')) {
    uVar1 = 0;
  }
  else {
    if (0x7f < (int)param_1) {
      param_1 = 0x7f;
    }
    if ((int)param_1 < 0) {
      param_1 = 0;
    }
    if (60000 < param_2) {
      param_2 = 60000;
    }
    if (param_2 < 0) {
      param_2 = 0;
    }
    FUN_8024377c();
    DAT_803a5e38 = (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803e1d48);
    if (param_2 == 0) {
      DAT_803a5e40 = 0;
      DAT_803a5e34 = DAT_803a5e38;
    }
    else {
      DAT_803a5e40 = param_2 << 5;
      DAT_803a5e3c = (DAT_803a5e38 - DAT_803a5e34) /
                     (float)((double)CONCAT44(0x43300000,DAT_803a5e40 ^ 0x80000000) -
                            DOUBLE_803e1d48);
    }
    FUN_802437a4();
    uVar1 = 1;
  }
  return uVar1;
}

