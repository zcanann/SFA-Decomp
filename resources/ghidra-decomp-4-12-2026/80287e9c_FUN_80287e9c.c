// Function: FUN_80287e9c
// Entry: 80287e9c
// Size: 100 bytes

void FUN_80287e9c(int param_1)

{
  if (((param_1 != -1) && (-1 < param_1)) && (param_1 < 3)) {
    FUN_8028b660();
    (&DAT_803d7584)[param_1 * 0x224] = 0;
    FUN_8028b658();
  }
  return;
}

