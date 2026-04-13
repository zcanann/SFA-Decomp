// Function: FUN_80248bc0
// Entry: 80248bc0
// Size: 140 bytes

undefined4 FUN_80248bc0(undefined4 param_1)

{
  uint uVar1;
  undefined4 extraout_r4;
  
  DAT_803deb20 = 0;
  DAT_cc006008 = 0xe0000000;
  DAT_cc00601c = 1;
  uVar1 = DAT_800000f8 >> 2;
  DAT_803deb28 = param_1;
  FUN_80241478((undefined4 *)&DAT_803aeae8);
  FUN_802416d4((undefined4 *)&DAT_803aeae8,extraout_r4,0,uVar1 * 10,&LAB_80248538);
  return 1;
}

