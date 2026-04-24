// Function: FUN_80248ce8
// Entry: 80248ce8
// Size: 152 bytes

undefined4 FUN_80248ce8(uint param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  uint uVar1;
  undefined4 extraout_r4;
  
  DAT_803deb20 = 0;
  DAT_cc006008 = param_1 | 0xe1000000;
  DAT_cc00600c = param_3 >> 2;
  DAT_cc006010 = param_2;
  DAT_cc00601c = 1;
  uVar1 = DAT_800000f8 >> 2;
  DAT_803deb28 = param_4;
  FUN_80241478((undefined4 *)&DAT_803aeae8);
  FUN_802416d4((undefined4 *)&DAT_803aeae8,extraout_r4,0,uVar1 * 10,&LAB_80248538);
  return 1;
}

