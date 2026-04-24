// Function: FUN_8000f458
// Entry: 8000f458
// Size: 40 bytes

void FUN_8000f458(int param_1)

{
  if ((-1 < param_1) && (param_1 < 4)) {
    DAT_803dc88d = (char)param_1;
    return;
  }
  DAT_803dc88d = 0;
  return;
}

