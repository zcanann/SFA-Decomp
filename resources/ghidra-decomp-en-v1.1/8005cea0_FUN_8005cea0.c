// Function: FUN_8005cea0
// Entry: 8005cea0
// Size: 36 bytes

void FUN_8005cea0(int param_1)

{
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xfffdffff;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x20000;
  }
  return;
}

