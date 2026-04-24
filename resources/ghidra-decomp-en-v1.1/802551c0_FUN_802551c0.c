// Function: FUN_802551c0
// Entry: 802551c0
// Size: 112 bytes

undefined4 FUN_802551c0(void)

{
  undefined4 uVar1;
  uint uVar2;
  
  if (DAT_803ded24 == -0x5a00ffa6) {
    uVar1 = 0;
  }
  else {
    uVar2 = FUN_80240ad0();
    if ((uVar2 & 0x10000000) == 0) {
      DAT_803ded20 = 0;
      uVar1 = 2;
    }
    else {
      DAT_803ded20 = 0xa5ff005a;
      DAT_803ded18 = 0;
      uVar1 = 0;
      DAT_803ded1c = 1;
    }
  }
  return uVar1;
}

