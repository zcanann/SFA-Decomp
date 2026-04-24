// Function: FUN_802587fc
// Entry: 802587fc
// Size: 160 bytes

void FUN_802587fc(void)

{
  if ((*(uint *)(DAT_803dc5a8 + 0x4f4) & 1) != 0) {
    FUN_8025ae2c();
  }
  if ((*(uint *)(DAT_803dc5a8 + 0x4f4) & 2) != 0) {
    FUN_8025b7ac();
  }
  if ((*(uint *)(DAT_803dc5a8 + 0x4f4) & 4) != 0) {
    FUN_80258bb8();
  }
  if ((*(uint *)(DAT_803dc5a8 + 0x4f4) & 8) != 0) {
    FUN_8025705c();
  }
  if ((*(uint *)(DAT_803dc5a8 + 0x4f4) & 0x10) != 0) {
    FUN_80257b1c();
  }
  if ((*(uint *)(DAT_803dc5a8 + 0x4f4) & 0x18) != 0) {
    FUN_802570b0();
  }
  *(undefined4 *)(DAT_803dc5a8 + 0x4f4) = 0;
  return;
}

