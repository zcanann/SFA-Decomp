// Function: FUN_8005cea8
// Entry: 8005cea8
// Size: 36 bytes

void FUN_8005cea8(int param_1)

{
  if (param_1 == 0) {
    DAT_803dcde8 = DAT_803dcde8 & 0xfffbffff;
  }
  else {
    DAT_803dcde8 = DAT_803dcde8 | 0x40000;
  }
  return;
}

