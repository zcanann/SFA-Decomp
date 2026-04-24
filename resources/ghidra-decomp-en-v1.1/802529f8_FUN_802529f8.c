// Function: FUN_802529f8
// Entry: 802529f8
// Size: 164 bytes

void FUN_802529f8(void)

{
  uint uVar1;
  
  DAT_803aeec0 = 0xffffffff;
  DAT_803aeea0 = 0xffffffff;
  DAT_803aee80 = 0xffffffff;
  DAT_803aee60 = 0xffffffff;
  DAT_8032ee9c = 0;
  FUN_802537e4(0);
  do {
    uVar1 = DAT_cc006434;
  } while ((uVar1 & 1) != 0);
  DAT_cc006434 = 0x80000000;
  FUN_80243ec0(0x14,&LAB_8025245c);
  FUN_802442c4(0x800);
  FUN_802534e4(0);
  FUN_802534e4(1);
  FUN_802534e4(2);
  FUN_802534e4(3);
  return;
}

