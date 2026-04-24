// Function: FUN_80102f88
// Entry: 80102f88
// Size: 204 bytes

void FUN_80102f88(undefined4 param_1,undefined4 param_2,undefined param_3,undefined4 param_4,
                 int param_5,undefined4 param_6,undefined param_7)

{
  int iVar1;
  undefined extraout_r4;
  
  iVar1 = FUN_802860d4();
  if (DAT_803dd504 != 0) {
    FUN_80023800();
    DAT_803dd504 = 0;
    DAT_803dd502 = 0;
  }
  DAT_803dd4fc = param_6;
  DAT_803dd510 = iVar1;
  if (param_5 == 0) {
    DAT_803dd504 = 0;
  }
  else {
    DAT_803dd504 = FUN_80023cc8(param_4,0xf,0);
    FUN_80003494(DAT_803dd504,param_5,param_4);
  }
  DAT_803dd500 = extraout_r4;
  if (iVar1 == 0x42) {
    DAT_803dd500 = 0;
  }
  DAT_803dd502 = 1;
  DAT_803dd4f8 = param_7;
  DAT_803dd501 = param_3;
  FUN_80286120();
  return;
}

