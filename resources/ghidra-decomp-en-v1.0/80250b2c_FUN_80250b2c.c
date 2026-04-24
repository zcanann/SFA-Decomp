// Function: FUN_80250b2c
// Entry: 80250b2c
// Size: 256 bytes

void FUN_80250b2c(void)

{
  if ((DAT_803de04c == (int **)0x0) && (DAT_803de040 != (int **)0x0)) {
    DAT_803de04c = DAT_803de040;
    DAT_803de040 = (int **)*DAT_803de040;
  }
  if (DAT_803de04c != (int **)0x0) {
    if (DAT_803de058 < DAT_803de04c[6]) {
      if (DAT_803de04c[2] == (int *)0x0) {
        FUN_8024ffe4(0,DAT_803de04c[4],DAT_803de04c[5],DAT_803de058);
      }
      else {
        FUN_8024ffe4(DAT_803de04c[2],DAT_803de04c[5],DAT_803de04c[4],DAT_803de058);
      }
    }
    else {
      if (DAT_803de04c[2] == (int *)0x0) {
        FUN_8024ffe4(0,DAT_803de04c[4],DAT_803de04c[5]);
      }
      else {
        FUN_8024ffe4(DAT_803de04c[2],DAT_803de04c[5],DAT_803de04c[4]);
      }
      DAT_803de054 = DAT_803de04c[7];
    }
    DAT_803de04c[6] = (int *)((int)DAT_803de04c[6] - (int)DAT_803de058);
    DAT_803de04c[4] = (int *)((int)DAT_803de04c[4] + (int)DAT_803de058);
    DAT_803de04c[5] = (int *)((int)DAT_803de04c[5] + (int)DAT_803de058);
  }
  return;
}

