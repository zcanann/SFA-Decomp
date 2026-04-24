// Function: FUN_8005cecc
// Entry: 8005cecc
// Size: 36 bytes

void FUN_8005cecc(int param_1)

{
  if (param_1 == 0) {
    DAT_803dcde8 = DAT_803dcde8 & 0xfff7ffff;
  }
  else {
    DAT_803dcde8 = DAT_803dcde8 | 0x80000;
  }
  return;
}

