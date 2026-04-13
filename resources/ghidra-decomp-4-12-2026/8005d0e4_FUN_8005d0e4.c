// Function: FUN_8005d0e4
// Entry: 8005d0e4
// Size: 36 bytes

void FUN_8005d0e4(int param_1)

{
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xffffefff;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x1000;
  }
  return;
}

