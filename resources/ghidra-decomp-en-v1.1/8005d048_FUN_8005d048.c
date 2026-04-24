// Function: FUN_8005d048
// Entry: 8005d048
// Size: 36 bytes

void FUN_8005d048(int param_1)

{
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xfff7ffff;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x80000;
  }
  return;
}

