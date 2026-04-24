// Function: FUN_80286eb8
// Entry: 80286eb8
// Size: 52 bytes

void FUN_80286eb8(int param_1)

{
  if (param_1 < 0) {
    return;
  }
  if (0 < param_1) {
    return;
  }
  (&DAT_803d7540)[param_1 * 3] = 0;
  (&DAT_803d7544)[param_1 * 3] = 0;
  (&DAT_803d7548)[param_1 * 3] = 0;
  return;
}

