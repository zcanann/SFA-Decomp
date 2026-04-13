// Function: FUN_8008a78c
// Entry: 8008a78c
// Size: 588 bytes

void FUN_8008a78c(void)

{
  double dVar1;
  
  if (DAT_803dddac != 0) {
    dVar1 = (double)(DAT_8030fe90 * DAT_8030fe90 +
                    DAT_8030fe88 * DAT_8030fe88 + DAT_8030fe8c * DAT_8030fe8c);
    if ((double)FLOAT_803dfcd8 == dVar1) {
      dVar1 = (double)FLOAT_803dfcdc;
    }
    else {
      dVar1 = FUN_80293900(dVar1);
    }
    DAT_8030fe88 = (float)((double)DAT_8030fe88 / dVar1);
    DAT_8030fe8c = (float)((double)DAT_8030fe8c / dVar1);
    DAT_8030fe90 = (float)((double)DAT_8030fe90 / dVar1);
    dVar1 = (double)(DAT_8030fe9c * DAT_8030fe9c +
                    DAT_8030fe94 * DAT_8030fe94 + DAT_8030fe98 * DAT_8030fe98);
    if ((double)FLOAT_803dfcd8 == dVar1) {
      dVar1 = (double)FLOAT_803dfcdc;
    }
    else {
      dVar1 = FUN_80293900(dVar1);
    }
    DAT_8030fe94 = (float)((double)DAT_8030fe94 / dVar1);
    DAT_8030fe98 = (float)((double)DAT_8030fe98 / dVar1);
    DAT_8030fe9c = (float)((double)DAT_8030fe9c / dVar1);
    if ((*(float *)(DAT_803dddac + 0x20c) < FLOAT_803dfd04) ||
       (FLOAT_803dfd08 < *(float *)(DAT_803dddac + 0x20c))) {
      if (DAT_803ddde4 == '\0') {
        FUN_80062bd0(-(double)DAT_8030fe94,(double)DAT_8030fe98,-(double)DAT_8030fe9c,100);
      }
      else {
        FUN_80062bd0((double)DAT_8039b408,(double)DAT_8039b40c,(double)DAT_8039b410,
                     (int)FLOAT_803ddde0);
      }
      (**(code **)(*DAT_803dd6e4 + 0x18))
                (-(double)DAT_8030fe94,(double)DAT_8030fe98,-(double)DAT_8030fe9c,0);
    }
    else {
      if (DAT_803ddde4 == '\0') {
        FUN_80062bd0((double)DAT_8030fe88,(double)DAT_8030fe8c,(double)DAT_8030fe90,100);
      }
      else {
        FUN_80062bd0((double)DAT_8039b408,(double)DAT_8039b40c,(double)DAT_8039b410,
                     (int)FLOAT_803ddde0);
      }
      (**(code **)(*DAT_803dd6e4 + 0x18))
                ((double)DAT_8030fe88,(double)DAT_8030fe8c,(double)DAT_8030fe90,1);
    }
  }
  return;
}

