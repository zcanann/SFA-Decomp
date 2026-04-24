// Function: FUN_80248e0c
// Entry: 80248e0c
// Size: 156 bytes

undefined4 FUN_80248e0c(int param_1,uint param_2,undefined4 param_3)

{
  uint uVar1;
  undefined4 extraout_r4;
  
  uVar1 = 0;
  DAT_803deb20 = 0;
  if (param_1 != 0) {
    uVar1 = 0x10000;
  }
  DAT_cc006008 = param_2 | uVar1 | 0xe4000000;
  DAT_cc00601c = 1;
  uVar1 = DAT_800000f8 >> 2;
  DAT_803deb28 = param_3;
  FUN_80241478((undefined4 *)&DAT_803aeae8);
  FUN_802416d4((undefined4 *)&DAT_803aeae8,extraout_r4,0,uVar1 * 10,&LAB_80248538);
  return 1;
}

