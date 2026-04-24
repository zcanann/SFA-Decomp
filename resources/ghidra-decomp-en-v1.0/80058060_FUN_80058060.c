// Function: FUN_80058060
// Entry: 80058060
// Size: 52 bytes

void FUN_80058060(void)

{
  DAT_803dcde1 = DAT_803dcde1 + '\x01';
  if ('\x02' < DAT_803dcde1) {
    DAT_803dcde1 = '\x02';
  }
  DAT_803dcde8 = DAT_803dcde8 | 0x4000;
  return;
}

