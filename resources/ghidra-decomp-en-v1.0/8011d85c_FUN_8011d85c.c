// Function: FUN_8011d85c
// Entry: 8011d85c
// Size: 116 bytes

undefined4 FUN_8011d85c(void)

{
  byte bVar1;
  
  FUN_8002b9ec();
  bVar1 = DAT_803db410;
  if (3 < DAT_803db410) {
    bVar1 = 3;
  }
  if (('\0' < DAT_803dd728) && (DAT_803dd728 = DAT_803dd728 - bVar1, DAT_803dd728 < '\x01')) {
    FUN_80014948(1);
    FUN_800552e8(0x60,1);
  }
  return 0;
}

