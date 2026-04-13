// Function: FUN_800581dc
// Entry: 800581dc
// Size: 52 bytes

void FUN_800581dc(void)

{
  DAT_803dda61 = DAT_803dda61 + '\x01';
  if ('\x02' < DAT_803dda61) {
    DAT_803dda61 = '\x02';
  }
  DAT_803dda68 = DAT_803dda68 | 0x4000;
  return;
}

