// Function: FUN_80248584
// Entry: 80248584
// Size: 152 bytes

undefined4 FUN_80248584(uint param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  uint uVar1;
  undefined4 extraout_r4;
  
  DAT_803ddea0 = 0;
  write_volatile_4(DAT_cc006008,param_1 | 0xe1000000);
  write_volatile_4(DAT_cc00600c,param_3 >> 2);
  write_volatile_4(DAT_cc006010,param_2);
  write_volatile_4(DAT_cc00601c,1);
  uVar1 = DAT_800000f8 >> 2;
  DAT_803ddea8 = param_4;
  FUN_80240d80(&DAT_803ade88);
  FUN_80240fdc(&DAT_803ade88,extraout_r4,0,uVar1 * 10,&LAB_80247dd4);
  return 1;
}

