// Function: FUN_8000a188
// Entry: 8000a188
// Size: 48 bytes

uint FUN_8000a188(uint param_1)

{
  if ((DAT_803dc7c4 & param_1) == 0) {
    return 1;
  }
  return (-(DAT_803dc7c8 & param_1) | DAT_803dc7c8 & param_1) >> 0x1f;
}

