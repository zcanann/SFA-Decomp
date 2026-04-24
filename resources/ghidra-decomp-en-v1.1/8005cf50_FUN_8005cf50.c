// Function: FUN_8005cf50
// Entry: 8005cf50
// Size: 36 bytes

void FUN_8005cf50(int param_1)

{
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 | 0x2000;
  }
  else {
    DAT_803dda68 = DAT_803dda68 & 0xffffdfff;
  }
  return;
}

