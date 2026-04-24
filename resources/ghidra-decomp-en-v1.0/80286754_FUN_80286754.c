// Function: FUN_80286754
// Entry: 80286754
// Size: 52 bytes

void FUN_80286754(int param_1)

{
  if (param_1 < 0) {
    return;
  }
  if (0 < param_1) {
    return;
  }
  (&DAT_803d68e0)[param_1 * 3] = 0;
  (&DAT_803d68e4)[param_1 * 3] = 0;
  (&DAT_803d68e8)[param_1 * 3] = 0;
  return;
}

