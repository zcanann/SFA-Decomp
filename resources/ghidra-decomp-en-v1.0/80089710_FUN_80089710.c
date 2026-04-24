// Function: FUN_80089710
// Entry: 80089710
// Size: 196 bytes

void FUN_80089710(uint param_1,uint param_2,int param_3)

{
  if (DAT_803dd12c == 0) {
    return;
  }
  if ((param_1 & 1) != 0) {
    if ((*(byte *)(DAT_803dd12c + 0xc1) >> 6 & 1) != (param_2 & 0xff)) {
      if (param_3 == 0) {
        *(float *)(DAT_803dd12c + 0xbc) = FLOAT_803df058;
      }
      else {
        *(float *)(DAT_803dd12c + 0xbc) = FLOAT_803df05c;
      }
    }
    *(byte *)(DAT_803dd12c + 0xc1) =
         (byte)(param_2 << 6) & 0x40 | *(byte *)(DAT_803dd12c + 0xc1) & 0xbf;
  }
  if ((param_1 & 2) == 0) {
    return;
  }
  if ((*(byte *)(DAT_803dd12c + 0x165) >> 6 & 1) != (param_2 & 0xff)) {
    if (param_3 == 0) {
      *(float *)(DAT_803dd12c + 0x160) = FLOAT_803df058;
    }
    else {
      *(float *)(DAT_803dd12c + 0x160) = FLOAT_803df05c;
    }
  }
  *(byte *)(DAT_803dd12c + 0x165) =
       (byte)(param_2 << 6) & 0x40 | *(byte *)(DAT_803dd12c + 0x165) & 0xbf;
  return;
}

