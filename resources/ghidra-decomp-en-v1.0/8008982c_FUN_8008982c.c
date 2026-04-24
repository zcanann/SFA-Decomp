// Function: FUN_8008982c
// Entry: 8008982c
// Size: 156 bytes

void FUN_8008982c(int param_1,byte *param_2,byte *param_3,byte *param_4)

{
  if (DAT_803dd12c == 0) {
    *param_4 = 0xff;
    *param_3 = 0xff;
    *param_2 = 0xff;
  }
  else {
    param_1 = param_1 * 0xa4;
    *param_2 = *(byte *)(DAT_803dd12c + param_1 + 0x78);
    *param_3 = *(byte *)(DAT_803dd12c + param_1 + 0x79);
    *param_4 = *(byte *)(DAT_803dd12c + param_1 + 0x7a);
  }
  *param_2 = (byte)((uint)*param_2 * (uint)DAT_803db634 >> 8);
  *param_3 = (byte)((uint)*param_3 * (uint)DAT_803db634 >> 8);
  *param_4 = (byte)((uint)*param_4 * (uint)DAT_803db634 >> 8);
  return;
}

