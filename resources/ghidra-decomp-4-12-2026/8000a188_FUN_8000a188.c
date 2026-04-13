// Function: FUN_8000a188
// Entry: 8000a188
// Size: 48 bytes

uint FUN_8000a188(uint param_1)

{
  if ((DAT_803dd444 & param_1) == 0) {
    return 1;
  }
  return (-(DAT_803dd448 & param_1) | DAT_803dd448 & param_1) >> 0x1f;
}

