// Function: FUN_800788bc
// Entry: 800788bc
// Size: 204 bytes

void FUN_800788bc(void)

{
  if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) || (DAT_803ddc92 != '\x01')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(1,3,1);
    DAT_803ddc98 = '\x01';
    DAT_803ddc94 = 3;
    DAT_803ddc92 = '\x01';
    DAT_803ddc9a = '\x01';
  }
  FUN_8025cce8(0,1,0,5);
  if ((DAT_803ddc91 != '\x01') || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(1);
    DAT_803ddc91 = '\x01';
    DAT_803ddc99 = '\x01';
  }
  FUN_8025c754(7,0,0,7,0);
  return;
}

