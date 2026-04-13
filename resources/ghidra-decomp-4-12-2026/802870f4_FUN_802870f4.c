// Function: FUN_802870f4
// Entry: 802870f4
// Size: 224 bytes

undefined4 FUN_802870f4(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  FUN_8028b660();
  if (DAT_803d7554 == 2) {
    uVar2 = 0x100;
  }
  else {
    iVar1 = DAT_803d7558 + DAT_803d7554 >> 0x1f;
    iVar1 = ((DAT_803d7558 + DAT_803d7554 & 1U ^ -iVar1) + iVar1) * 0xc;
    FUN_80003514(iVar1 + -0x7fc28aa4,param_1,0xc);
    *(uint *)(&DAT_803d7560 + iVar1) = DAT_803d7574;
    DAT_803d7574 = DAT_803d7574 + 1;
    if (DAT_803d7574 < 0x100) {
      DAT_803d7574 = 0x100;
    }
    DAT_803d7554 = DAT_803d7554 + 1;
  }
  FUN_8028b658();
  return uVar2;
}

