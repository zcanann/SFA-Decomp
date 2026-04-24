// Function: FUN_802485a8
// Entry: 802485a8
// Size: 272 bytes

void FUN_802485a8(undefined4 param_1,uint param_2,uint param_3,undefined4 param_4)

{
  uint uVar1;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  longlong lVar2;
  
  DAT_803deb20 = 0;
  DAT_803deb60 = 1;
  DAT_803deb28 = param_4;
  lVar2 = FUN_802473d4();
  DAT_803deb58 = (undefined4)((ulonglong)lVar2 >> 0x20);
  DAT_803deb5c = (undefined4)lVar2;
  DAT_cc006008 = 0xa8000000;
  DAT_cc00600c = param_3 >> 2;
  DAT_cc006010 = param_2;
  DAT_cc006014 = param_1;
  DAT_cc006018 = param_2;
  DAT_cc00601c = 3;
  DAT_803deb24 = param_2;
  if (param_2 < 0xa00001) {
    uVar1 = DAT_800000f8 >> 2;
    FUN_80241478((undefined4 *)&DAT_803aeae8);
    FUN_802416d4((undefined4 *)&DAT_803aeae8,extraout_r4_00,0,uVar1 * 10,&LAB_80248538);
  }
  else {
    uVar1 = DAT_800000f8 >> 2;
    FUN_80241478((undefined4 *)&DAT_803aeae8);
    FUN_802416d4((undefined4 *)&DAT_803aeae8,extraout_r4,0,uVar1 * 0x14,&LAB_80248538);
  }
  return;
}

