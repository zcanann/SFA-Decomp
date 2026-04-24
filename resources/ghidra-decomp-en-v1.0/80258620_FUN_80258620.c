// Function: FUN_80258620
// Entry: 80258620
// Size: 40 bytes

void FUN_80258620(ushort param_1,int param_2,int param_3)

{
  *DAT_803de0b0 =
       (param_1 & 0xf1 | (ushort)(param_2 << 1)) & 0xffef | (ushort)(param_3 << 4) & 0xff0;
  return;
}

