// Function: FUN_8008ed24
// Entry: 8008ed24
// Size: 100 bytes

void FUN_8008ed24(void)

{
  DAT_803db610 = 0xffffffff;
  uRam803db614 = 0xffffffff;
  if (DAT_803dd184 != 0) {
    FUN_80023800();
  }
  if (iRam803dd188 != 0) {
    FUN_80023800();
  }
  DAT_803dd184 = 0;
  iRam803dd188 = 0;
  return;
}

