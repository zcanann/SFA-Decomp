// Function: FUN_8001461c
// Entry: 8001461c
// Size: 76 bytes

double FUN_8001461c(void)

{
  if ((DAT_803dc8f9 & 1) != 0) {
    return (double)(FLOAT_803de6e0 * ((FLOAT_803dc8fc - FLOAT_803dc900) / FLOAT_803de6d4));
  }
  return (double)(FLOAT_803de6e0 * (FLOAT_803dc900 / FLOAT_803de6d4));
}

