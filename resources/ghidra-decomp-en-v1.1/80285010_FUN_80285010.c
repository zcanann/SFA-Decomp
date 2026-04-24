// Function: FUN_80285010
// Entry: 80285010
// Size: 44 bytes

int FUN_80285010(void)

{
  return DAT_803df024 + (DAT_803df044 + 2 + ((int)(DAT_803df044 + 2) >> 2) * -4 & 0xff) * 0x280;
}

