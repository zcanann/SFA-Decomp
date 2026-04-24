// Function: FUN_8006c830
// Entry: 8006c830
// Size: 236 bytes

void FUN_8006c830(void)

{
  FUN_80258c9c(0,0,0x280,0x1e0);
  FUN_80258da0(0x140,0xf0,4,1);
  FUN_802594a8(DAT_803dcf7c + 0x60,0);
  FUN_80258c9c(0,0,0x280,0x1e0);
  FUN_80258da0(0x140,0xf0,0x11,1);
  FUN_802594a8(DAT_803dcfdc + 0x60,0);
  if (*(char *)(DAT_803dcf7c + 0x48) != '\0') {
    FUN_8025ab1c(DAT_803dcf7c + 0x20,*(undefined4 *)(DAT_803dcf7c + 0x40));
  }
  if (*(char *)(DAT_803dcfdc + 0x48) != '\0') {
    FUN_8025ab1c(DAT_803dcfdc + 0x20,*(undefined4 *)(DAT_803dcfdc + 0x40));
  }
  if ((*(char *)(DAT_803dcf7c + 0x48) == '\0') || (*(char *)(DAT_803dcfdc + 0x48) == '\0')) {
    FUN_8025aaac();
  }
  FUN_802584c0();
  return;
}

