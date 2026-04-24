// Function: FUN_80088e30
// Entry: 80088e30
// Size: 36 bytes

undefined FUN_80088e30(int param_1)

{
  if (DAT_803dd12c != 0) {
    return *(undefined *)(DAT_803dd12c + param_1 * 0xa4 + 0xc0);
  }
  return 0xff;
}

