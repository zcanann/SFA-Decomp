// Function: FUN_80258280
// Entry: 80258280
// Size: 156 bytes

void FUN_80258280(void)

{
  int iVar1;
  byte bVar2;
  
  bVar2 = 0;
  iVar1 = 0;
  while( true ) {
    if (7 < bVar2) break;
    if (((uint)*(byte *)(DAT_803dd210 + 0x4f2) & 1 << (uint)bVar2) != 0) {
      DAT_cc008000._0_1_ = 8;
      DAT_cc008000._0_1_ = bVar2 | 0x70;
      DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + iVar1 + 0x1c);
      DAT_cc008000._0_1_ = 8;
      DAT_cc008000._0_1_ = bVar2 | 0x80;
      DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + iVar1 + 0x3c);
      DAT_cc008000._0_1_ = 8;
      DAT_cc008000._0_1_ = bVar2 | 0x90;
      DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + iVar1 + 0x5c);
    }
    iVar1 = iVar1 + 4;
    bVar2 = bVar2 + 1;
  }
  *(undefined *)(DAT_803dd210 + 0x4f2) = 0;
  return;
}

