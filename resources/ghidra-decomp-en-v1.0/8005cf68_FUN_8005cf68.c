// Function: FUN_8005cf68
// Entry: 8005cf68
// Size: 36 bytes

void FUN_8005cf68(int param_1)

{
  if (param_1 == 0) {
    DAT_803dcde8 = DAT_803dcde8 & 0xffffefff;
  }
  else {
    DAT_803dcde8 = DAT_803dcde8 | 0x1000;
  }
  return;
}

