// Function: FUN_8024832c
// Entry: 8024832c
// Size: 164 bytes

undefined4 FUN_8024832c(undefined4 param_1,undefined4 param_2)

{
  uint uVar1;
  undefined4 extraout_r4;
  
  DAT_803ddea0 = 0;
  write_volatile_4(DAT_cc006008,0xa8000040);
  write_volatile_4(DAT_cc00600c,0);
  write_volatile_4(DAT_cc006010,0x20);
  write_volatile_4(DAT_cc006014,param_1);
  write_volatile_4(DAT_cc006018,0x20);
  write_volatile_4(DAT_cc00601c,3);
  uVar1 = DAT_800000f8 >> 2;
  DAT_803ddea8 = param_2;
  FUN_80240d80(&DAT_803ade88);
  FUN_80240fdc(&DAT_803ade88,extraout_r4,0,uVar1 * 10,&LAB_80247dd4);
  return 1;
}

