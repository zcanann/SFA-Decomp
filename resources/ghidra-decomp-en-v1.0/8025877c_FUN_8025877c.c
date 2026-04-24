// Function: FUN_8025877c
// Entry: 8025877c
// Size: 128 bytes

void FUN_8025877c(void)

{
  FUN_802437c8(0x12,&LAB_80258670);
  FUN_802437c8(0x13,&LAB_802586f8);
  FUN_80245d78(&DAT_803de0e4);
  FUN_80243bcc(0x2000);
  FUN_80243bcc(0x1000);
  *(ushort *)(DAT_803de0b0 + 10) = *(ushort *)(DAT_803de0b0 + 10) & 0xfff0 | 0xf;
  return;
}

