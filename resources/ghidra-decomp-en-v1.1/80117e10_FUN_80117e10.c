// Function: FUN_80117e10
// Entry: 80117e10
// Size: 268 bytes

undefined4 FUN_80117e10(uint param_1,int param_2)

{
  undefined4 uVar1;
  
  if ((DAT_803a6a58 == 0) || (DAT_803a6a5f == '\0')) {
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
    FUN_80243e74();
    DAT_803a6a98 = (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803e29c8);
    if (param_2 == 0) {
      DAT_803a6aa0 = 0;
      DAT_803a6a94 = DAT_803a6a98;
    }
    else {
      DAT_803a6aa0 = param_2 << 5;
      DAT_803a6a9c = (DAT_803a6a98 - DAT_803a6a94) /
                     (float)((double)CONCAT44(0x43300000,DAT_803a6aa0 ^ 0x80000000) -
                            DOUBLE_803e29c8);
    }
    FUN_80243e9c();
    uVar1 = 1;
  }
  return uVar1;
}

