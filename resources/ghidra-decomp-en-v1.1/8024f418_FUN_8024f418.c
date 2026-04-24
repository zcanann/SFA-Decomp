// Function: FUN_8024f418
// Entry: 8024f418
// Size: 96 bytes

void FUN_8024f418(int param_1)

{
  DAT_803dec54 = 0;
  if (param_1 == 1) {
    DAT_803dd200 = &LAB_8024f5ec;
  }
  else if (param_1 < 1) {
    if (-1 < param_1) {
      DAT_803dd200 = &LAB_8024f478;
    }
  }
  else if (param_1 < 6) {
    DAT_803dd200 = &LAB_8024f760;
  }
  DAT_803dd1fc = param_1;
  return;
}

