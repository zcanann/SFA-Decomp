// Function: FUN_800a04c0
// Entry: 800a04c0
// Size: 168 bytes

void FUN_800a04c0(undefined4 param_1,undefined4 param_2,undefined param_3,undefined4 param_4,
                 undefined4 param_5)

{
  undefined4 uVar1;
  ushort extraout_r4;
  
  uVar1 = FUN_80286840();
  FUN_800033a8(-0x7fc63508,0,0x60);
  DAT_8039cb50 = (undefined)extraout_r4;
  DAT_8039cb3c = extraout_r4 & 0xff;
  DAT_8039cb24 = FLOAT_803e00b0;
  DAT_8039cb28 = FLOAT_803e00b0;
  DAT_8039cb2c = FLOAT_803e00b0;
  DAT_8039cb18 = FLOAT_803e00b0;
  DAT_8039cb1c = FLOAT_803e00b0;
  DAT_8039cb20 = FLOAT_803e00b0;
  DAT_8039cb30 = FLOAT_803e00b4;
  DAT_8039cb52 = 0;
  DAT_8039cb53 = 0;
  DAT_8039cafc = uVar1;
  DAT_8039cb34 = param_5;
  DAT_8039cb38 = param_4;
  DAT_8039cb51 = param_3;
  FUN_8028688c();
  return;
}

