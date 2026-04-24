// Function: FUN_8012fcec
// Entry: 8012fcec
// Size: 204 bytes

void FUN_8012fcec(void)

{
  byte bVar1;
  
  FUN_802860d4();
  FUN_8011f250();
  for (bVar1 = 0; bVar1 < 0x40; bVar1 = bVar1 + 1) {
    if ((&DAT_803a91b8)[bVar1] != 0) {
      FUN_80054308();
      (&DAT_803a91b8)[bVar1] = 0;
    }
    (&DAT_803a9138)[bVar1] = 0xffff;
    (&DAT_803a8c38)[bVar1] = 1;
  }
  if (DAT_803dd7c8 != 0) {
    FUN_80054308();
    DAT_803dd7c8 = 0;
  }
  if (DAT_803dd834 != 0) {
    FUN_80054308();
  }
  DAT_803dd830 = 0xffff;
  DAT_803dd834 = 0;
  FUN_80286120();
  return;
}

