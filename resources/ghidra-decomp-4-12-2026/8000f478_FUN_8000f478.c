// Function: FUN_8000f478
// Entry: 8000f478
// Size: 40 bytes

void FUN_8000f478(int param_1)

{
  if ((-1 < param_1) && (param_1 < 4)) {
    DAT_803dd50d = (char)param_1;
    return;
  }
  DAT_803dd50d = 0;
  return;
}

