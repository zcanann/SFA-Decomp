// Function: FUN_80248a90
// Entry: 80248a90
// Size: 164 bytes

undefined4 FUN_80248a90(undefined4 param_1,undefined4 param_2)

{
  uint uVar1;
  undefined4 extraout_r4;
  
  DAT_803deb20 = 0;
  DAT_cc006008 = 0xa8000040;
  DAT_cc00600c = 0;
  DAT_cc006010 = 0x20;
  DAT_cc006014 = param_1;
  DAT_cc006018 = 0x20;
  DAT_cc00601c = 3;
  uVar1 = DAT_800000f8 >> 2;
  DAT_803deb28 = param_2;
  FUN_80241478((undefined4 *)&DAT_803aeae8);
  FUN_802416d4((undefined4 *)&DAT_803aeae8,extraout_r4,0,uVar1 * 10,&LAB_80248538);
  return 1;
}

