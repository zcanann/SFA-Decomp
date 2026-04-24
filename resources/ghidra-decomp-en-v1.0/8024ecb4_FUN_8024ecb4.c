// Function: FUN_8024ecb4
// Entry: 8024ecb4
// Size: 96 bytes

void FUN_8024ecb4(int param_1)

{
  if (param_1 == 1) {
    DAT_803dc598 = &LAB_8024ee88;
  }
  else if (param_1 < 1) {
    if (-1 < param_1) {
      DAT_803dc598 = &LAB_8024ed14;
    }
  }
  else if (param_1 < 6) {
    DAT_803dc598 = &LAB_8024effc;
  }
  DAT_803dc594 = param_1;
  DAT_803ddfd4 = 0;
  return;
}

