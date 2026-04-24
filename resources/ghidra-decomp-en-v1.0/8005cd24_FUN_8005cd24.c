// Function: FUN_8005cd24
// Entry: 8005cd24
// Size: 36 bytes

void FUN_8005cd24(int param_1)

{
  if (param_1 == 0) {
    DAT_803dcde8 = DAT_803dcde8 & 0xfffdffff;
  }
  else {
    DAT_803dcde8 = DAT_803dcde8 | 0x20000;
  }
  return;
}

