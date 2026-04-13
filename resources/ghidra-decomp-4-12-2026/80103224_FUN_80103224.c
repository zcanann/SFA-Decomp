// Function: FUN_80103224
// Entry: 80103224
// Size: 204 bytes

void FUN_80103224(undefined4 param_1,undefined4 param_2,undefined param_3,int param_4,uint param_5,
                 undefined4 param_6,undefined param_7)

{
  int iVar1;
  undefined extraout_r4;
  
  iVar1 = FUN_80286838();
  if (DAT_803de17c != 0) {
    FUN_800238c4(DAT_803de17c);
    DAT_803de17c = 0;
    DAT_803de17a = 0;
  }
  DAT_803de174 = param_6;
  DAT_803de188 = iVar1;
  if (param_5 == 0) {
    DAT_803de17c = 0;
  }
  else {
    DAT_803de17c = FUN_80023d8c(param_4,0xf);
    FUN_80003494(DAT_803de17c,param_5,param_4);
  }
  DAT_803de178 = extraout_r4;
  if (iVar1 == 0x42) {
    DAT_803de178 = 0;
  }
  DAT_803de17a = 1;
  DAT_803de170 = param_7;
  DAT_803de179 = param_3;
  FUN_80286884();
  return;
}

