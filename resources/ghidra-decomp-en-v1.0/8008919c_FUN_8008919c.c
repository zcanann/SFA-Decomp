// Function: FUN_8008919c
// Entry: 8008919c
// Size: 64 bytes

undefined FUN_8008919c(int param_1)

{
  if (DAT_803dd12c == 0) {
    return 0;
  }
  if (*(char *)(DAT_803dd12c + param_1 * 0xa4 + 0xc1) < '\0') {
    return 0;
  }
  return *(undefined *)(DAT_803dd148 + 0x37);
}

