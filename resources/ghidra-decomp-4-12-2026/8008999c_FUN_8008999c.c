// Function: FUN_8008999c
// Entry: 8008999c
// Size: 196 bytes

void FUN_8008999c(uint param_1,uint param_2,int param_3)

{
  if (DAT_803dddac == 0) {
    return;
  }
  if ((param_1 & 1) != 0) {
    if ((*(byte *)(DAT_803dddac + 0xc1) >> 6 & 1) != (param_2 & 0xff)) {
      if (param_3 == 0) {
        *(float *)(DAT_803dddac + 0xbc) = FLOAT_803dfcd8;
      }
      else {
        *(float *)(DAT_803dddac + 0xbc) = FLOAT_803dfcdc;
      }
    }
    *(byte *)(DAT_803dddac + 0xc1) =
         (byte)(param_2 << 6) & 0x40 | *(byte *)(DAT_803dddac + 0xc1) & 0xbf;
  }
  if ((param_1 & 2) == 0) {
    return;
  }
  if ((*(byte *)(DAT_803dddac + 0x165) >> 6 & 1) != (param_2 & 0xff)) {
    if (param_3 == 0) {
      *(float *)(DAT_803dddac + 0x160) = FLOAT_803dfcd8;
    }
    else {
      *(float *)(DAT_803dddac + 0x160) = FLOAT_803dfcdc;
    }
  }
  *(byte *)(DAT_803dddac + 0x165) =
       (byte)(param_2 << 6) & 0x40 | *(byte *)(DAT_803dddac + 0x165) & 0xbf;
  return;
}

