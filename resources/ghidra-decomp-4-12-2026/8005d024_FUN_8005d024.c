// Function: FUN_8005d024
// Entry: 8005d024
// Size: 36 bytes

void FUN_8005d024(int param_1)

{
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xfffbffff;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x40000;
  }
  return;
}

