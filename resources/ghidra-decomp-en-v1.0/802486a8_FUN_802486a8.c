// Function: FUN_802486a8
// Entry: 802486a8
// Size: 156 bytes

undefined4 FUN_802486a8(int param_1,uint param_2,undefined4 param_3)

{
  uint uVar1;
  undefined4 extraout_r4;
  
  uVar1 = 0;
  DAT_803ddea0 = 0;
  if (param_1 != 0) {
    uVar1 = 0x10000;
  }
  write_volatile_4(DAT_cc006008,param_2 | uVar1 | 0xe4000000);
  write_volatile_4(DAT_cc00601c,1);
  uVar1 = DAT_800000f8 >> 2;
  DAT_803ddea8 = param_3;
  FUN_80240d80(&DAT_803ade88);
  FUN_80240fdc(&DAT_803ade88,extraout_r4,0,uVar1 * 10,&LAB_80247dd4);
  return 1;
}

