// Function: FUN_8008df3c
// Entry: 8008df3c
// Size: 160 bytes

void FUN_8008df3c(undefined4 param_1)

{
  if (DAT_803dde04 != 0) {
    DAT_803dde00 = 2;
    FUN_8005d238(param_1,(char)*(undefined4 *)(DAT_803dde04 + 0x24),
                 (char)*(undefined4 *)(DAT_803dde04 + 0x28),
                 (char)*(undefined4 *)(DAT_803dde04 + 0x2c));
    if (*(float *)(DAT_803dde04 + 0x14) == *(float *)(DAT_803dde04 + 0x18)) {
      *(float *)(DAT_803dde04 + 0x14) = *(float *)(DAT_803dde04 + 0x14) - FLOAT_803dfdcc;
    }
    if (*(float *)(DAT_803dde04 + 0x18) < *(float *)(DAT_803dde04 + 0x14)) {
      *(float *)(DAT_803dde04 + 0x14) = *(float *)(DAT_803dde04 + 0x18) - FLOAT_803dfdcc;
    }
    FUN_80070580((double)*(float *)(DAT_803dde04 + 0x14),(double)*(float *)(DAT_803dde04 + 0x18));
  }
  return;
}

