// Function: FUN_8006c9ac
// Entry: 8006c9ac
// Size: 236 bytes

void FUN_8006c9ac(void)

{
  FUN_80259400(0,0,0x280,0x1e0);
  FUN_80259504(0x140,0xf0,4,1);
  FUN_80259c0c(DAT_803ddbfc + 0x60,0);
  FUN_80259400(0,0,0x280,0x1e0);
  FUN_80259504(0x140,0xf0,0x11,1);
  FUN_80259c0c(DAT_803ddc5c + 0x60,0);
  if (*(char *)(DAT_803ddbfc + 0x48) != '\0') {
    FUN_8025b280(DAT_803ddbfc + 0x20,*(uint **)(DAT_803ddbfc + 0x40));
  }
  if (*(char *)(DAT_803ddc5c + 0x48) != '\0') {
    FUN_8025b280(DAT_803ddc5c + 0x20,*(uint **)(DAT_803ddc5c + 0x40));
  }
  if ((*(char *)(DAT_803ddbfc + 0x48) == '\0') || (*(char *)(DAT_803ddc5c + 0x48) == '\0')) {
    FUN_8025b210();
  }
  FUN_80258c24();
  return;
}

