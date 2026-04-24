// Function: FUN_802483d0
// Entry: 802483d0
// Size: 140 bytes

undefined4 FUN_802483d0(undefined4 param_1)

{
  uint uVar1;
  undefined4 extraout_r4;
  
  DAT_803ddea0 = 0;
  write_volatile_4(DAT_cc006008,0xe3000000);
  write_volatile_4(DAT_cc00601c,1);
  uVar1 = DAT_800000f8 >> 2;
  DAT_803ddea8 = param_1;
  FUN_80240d80(&DAT_803ade88);
  FUN_80240fdc(&DAT_803ade88,extraout_r4,0,uVar1 * 10,&LAB_80247dd4);
  return 1;
}

