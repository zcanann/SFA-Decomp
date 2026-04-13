// Function: FUN_80070050
// Entry: 80070050
// Size: 36 bytes

uint FUN_80070050(void)

{
  if (DAT_803ddc84 != 0) {
    return DAT_803ddc84 | DAT_803ddc84 << 0x10;
  }
  return 0x1e00280;
}

