// Function: FUN_8000fc10
// Entry: 8000fc10
// Size: 44 bytes

void FUN_8000fc10(double param_1,int param_2)

{
  if (param_2 != 0) {
    DAT_803dd502 = (short)param_2;
    DAT_803dd500 = (short)param_2;
    FLOAT_803dd52c = FLOAT_803dbec4;
    FLOAT_803dd528 = (float)param_1;
    return;
  }
  FLOAT_803dbec4 = (float)param_1;
  return;
}

