// Function: FUN_80272714
// Entry: 80272714
// Size: 40 bytes

void FUN_80272714(uint param_1,undefined param_2)

{
  if (DAT_803deeb8 == '\0') {
    return;
  }
  (&DAT_803bdff1)[(param_1 & 0xff) * 0x30] = param_2;
  return;
}

