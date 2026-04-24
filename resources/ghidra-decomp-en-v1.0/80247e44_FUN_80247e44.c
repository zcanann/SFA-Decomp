// Function: FUN_80247e44
// Entry: 80247e44
// Size: 272 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80247e44(undefined4 param_1,uint param_2,uint param_3,undefined4 param_4)

{
  uint uVar1;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  
  DAT_803ddea0 = 0;
  DAT_803ddee0 = 1;
  DAT_803ddea8 = param_4;
  _DAT_803dded8 = FUN_80246c70();
  write_volatile_4(DAT_cc006008,0xa8000000);
  write_volatile_4(DAT_cc00600c,param_3 >> 2);
  write_volatile_4(DAT_cc006010,param_2);
  write_volatile_4(DAT_cc006014,param_1);
  write_volatile_4(DAT_cc006018,param_2);
  write_volatile_4(DAT_cc00601c,3);
  DAT_803ddea4 = param_2;
  if (param_2 < 0xa00001) {
    uVar1 = DAT_800000f8 >> 2;
    FUN_80240d80(&DAT_803ade88);
    FUN_80240fdc(&DAT_803ade88,extraout_r4_00,0,uVar1 * 10,&LAB_80247dd4);
  }
  else {
    uVar1 = DAT_800000f8 >> 2;
    FUN_80240d80(&DAT_803ade88);
    FUN_80240fdc(&DAT_803ade88,extraout_r4,0,uVar1 * 0x14,&LAB_80247dd4);
  }
  DAT_803dded8 = (undefined4)((ulonglong)_DAT_803dded8 >> 0x20);
  return;
}

