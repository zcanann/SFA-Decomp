// Function: FUN_80271fb0
// Entry: 80271fb0
// Size: 40 bytes

void FUN_80271fb0(uint param_1,undefined param_2)

{
  if (DAT_803de238 == '\0') {
    return;
  }
  (&DAT_803bd391)[(param_1 & 0xff) * 0x30] = param_2;
  return;
}

