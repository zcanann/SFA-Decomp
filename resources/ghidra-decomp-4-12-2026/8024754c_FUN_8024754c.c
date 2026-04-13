// Function: FUN_8024754c
// Entry: 8024754c
// Size: 28 bytes

uint FUN_8024754c(uint param_1)

{
  return *(uint *)(DAT_803deb18 + 4) & 1 << (param_1 & 0xff);
}

