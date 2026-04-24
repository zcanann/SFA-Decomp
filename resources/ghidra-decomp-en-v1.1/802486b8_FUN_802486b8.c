// Function: FUN_802486b8
// Entry: 802486b8
// Size: 128 bytes

void FUN_802486b8(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  if ((param_3 & 0xffff8000) == 0) {
    DAT_803aea8c = 0;
  }
  else {
    DAT_803aea8c = (param_3 & 0xffff8000) + DAT_803deb48;
  }
  DAT_803aea80 = 2;
  DAT_803aea94 = 1;
  DAT_803aeaa8 = 0xffffffff;
  DAT_803deb64 = 0;
  DAT_803aea90 = param_4;
  DAT_803aea98 = param_1;
  DAT_803aea9c = param_2;
  DAT_803aeaa0 = param_3;
  DAT_803aeaa4 = param_4;
  FUN_802489d0(DAT_803aea8c,param_4);
  return;
}

