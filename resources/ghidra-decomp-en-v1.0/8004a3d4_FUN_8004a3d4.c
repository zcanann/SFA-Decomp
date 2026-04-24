// Function: FUN_8004a3d4
// Entry: 8004a3d4
// Size: 104 bytes

void FUN_8004a3d4(void)

{
  if ((DAT_803dccf0 == &DAT_8032e65c) || (DAT_803dccf0[0x18] != '\0')) {
    FUN_802590f4(DAT_803dccf0[0x19],DAT_803dccf0 + 0x1a,0,DAT_803dccf0 + 0x32);
  }
  else {
    FUN_802590f4(DAT_803dccf0[0x19],DAT_803dccf0 + 0x1a,1,&DAT_803db5d4);
  }
  return;
}

