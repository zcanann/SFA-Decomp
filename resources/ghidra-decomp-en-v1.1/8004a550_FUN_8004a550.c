// Function: FUN_8004a550
// Entry: 8004a550
// Size: 104 bytes

void FUN_8004a550(void)

{
  if ((DAT_803dd970 == &DAT_8032f2b4) || (DAT_803dd970[0x18] != '\0')) {
    FUN_80259858(DAT_803dd970[0x19],DAT_803dd970 + 0x1a,'\0',DAT_803dd970 + 0x32);
  }
  else {
    FUN_80259858(DAT_803dd970[0x19],DAT_803dd970 + 0x1a,'\x01',&DAT_803dc234);
  }
  return;
}

