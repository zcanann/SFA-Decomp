// Function: FUN_8005cdd4
// Entry: 8005cdd4
// Size: 36 bytes

void FUN_8005cdd4(int param_1)

{
  if (param_1 == 0) {
    DAT_803dcde8 = DAT_803dcde8 | 0x2000;
  }
  else {
    DAT_803dcde8 = DAT_803dcde8 & 0xffffdfff;
  }
  return;
}

