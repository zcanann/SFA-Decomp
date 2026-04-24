// Function: FUN_8005802c
// Entry: 8005802c
// Size: 52 bytes

void FUN_8005802c(void)

{
  DAT_803dcde1 = DAT_803dcde1 + -1;
  if (DAT_803dcde1 < -2) {
    DAT_803dcde1 = -2;
  }
  DAT_803dcde8 = DAT_803dcde8 | 0x4000;
  return;
}

