// Function: FUN_80043034
// Entry: 80043034
// Size: 64 bytes

void FUN_80043034(void)

{
  FUN_8024377c();
  if ((DAT_803dcc80 & 0x100000) != 0) {
    DAT_803dcc80 = DAT_803dcc80 ^ 0x100000;
  }
  FUN_802437a4();
  return;
}

