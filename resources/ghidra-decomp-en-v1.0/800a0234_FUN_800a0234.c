// Function: FUN_800a0234
// Entry: 800a0234
// Size: 168 bytes

void FUN_800a0234(undefined4 param_1,undefined4 param_2,undefined param_3,undefined4 param_4,
                 undefined4 param_5)

{
  undefined4 uVar1;
  ushort extraout_r4;
  
  uVar1 = FUN_802860dc();
  FUN_800033a8(&DAT_8039be98,0,0x60);
  DAT_8039bef0 = (undefined)extraout_r4;
  DAT_8039bedc = extraout_r4 & 0xff;
  DAT_8039bec4 = FLOAT_803df430;
  DAT_8039bec8 = FLOAT_803df430;
  DAT_8039becc = FLOAT_803df430;
  DAT_8039beb8 = FLOAT_803df430;
  DAT_8039bebc = FLOAT_803df430;
  DAT_8039bec0 = FLOAT_803df430;
  DAT_8039bed0 = FLOAT_803df434;
  DAT_8039bef2 = 0;
  DAT_8039bef3 = 0;
  DAT_8039be9c = uVar1;
  DAT_8039bed4 = param_5;
  DAT_8039bed8 = param_4;
  DAT_8039bef1 = param_3;
  FUN_80286128();
  return;
}

