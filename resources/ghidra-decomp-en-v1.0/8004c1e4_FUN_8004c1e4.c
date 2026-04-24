// Function: FUN_8004c1e4
// Entry: 8004c1e4
// Size: 32 bytes

void FUN_8004c1e4(double param_1,undefined param_2)

{
  if (param_1 <= (double)FLOAT_803deac8) {
    uRam803db5ef = param_2;
    FLOAT_803db5f0 = (float)param_1;
    return;
  }
  uRam803db5ef = param_2;
  FLOAT_803db5f0 = FLOAT_803deac8;
  return;
}

