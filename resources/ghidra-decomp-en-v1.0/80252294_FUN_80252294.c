// Function: FUN_80252294
// Entry: 80252294
// Size: 164 bytes

void FUN_80252294(void)

{
  uint uVar1;
  
  DAT_803ae260 = 0xffffffff;
  DAT_803ae240 = 0xffffffff;
  DAT_803ae220 = 0xffffffff;
  DAT_803ae200 = 0xffffffff;
  DAT_8032e244 = 0;
  FUN_80253080(0);
  do {
    uVar1 = read_volatile_4(DAT_cc006434);
  } while ((uVar1 & 1) != 0);
  write_volatile_4(DAT_cc006434,0x80000000);
  FUN_802437c8(0x14,&LAB_80251cf8);
  FUN_80243bcc(0x800);
  FUN_80252d80(0);
  FUN_80252d80(1);
  FUN_80252d80(2);
  FUN_80252d80(3);
  return;
}

