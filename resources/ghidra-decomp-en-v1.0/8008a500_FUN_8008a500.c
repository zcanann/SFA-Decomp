// Function: FUN_8008a500
// Entry: 8008a500
// Size: 588 bytes

void FUN_8008a500(void)

{
  double dVar1;
  
  if (DAT_803dd12c != 0) {
    if (FLOAT_803df058 ==
        DAT_8030f2d0 * DAT_8030f2d0 + DAT_8030f2c8 * DAT_8030f2c8 + DAT_8030f2cc * DAT_8030f2cc) {
      dVar1 = (double)FLOAT_803df05c;
    }
    else {
      dVar1 = (double)FUN_802931a0();
    }
    DAT_8030f2c8 = (float)((double)DAT_8030f2c8 / dVar1);
    DAT_8030f2cc = (float)((double)DAT_8030f2cc / dVar1);
    DAT_8030f2d0 = (float)((double)DAT_8030f2d0 / dVar1);
    if (FLOAT_803df058 ==
        DAT_8030f2dc * DAT_8030f2dc + DAT_8030f2d4 * DAT_8030f2d4 + DAT_8030f2d8 * DAT_8030f2d8) {
      dVar1 = (double)FLOAT_803df05c;
    }
    else {
      dVar1 = (double)FUN_802931a0();
    }
    DAT_8030f2d4 = (float)((double)DAT_8030f2d4 / dVar1);
    DAT_8030f2d8 = (float)((double)DAT_8030f2d8 / dVar1);
    DAT_8030f2dc = (float)((double)DAT_8030f2dc / dVar1);
    if ((*(float *)(DAT_803dd12c + 0x20c) < FLOAT_803df084) ||
       (FLOAT_803df088 < *(float *)(DAT_803dd12c + 0x20c))) {
      if (DAT_803dd164 == '\0') {
        FUN_80062a54(-(double)DAT_8030f2d4,(double)DAT_8030f2d8,-(double)DAT_8030f2dc,100);
      }
      else {
        FUN_80062a54((double)DAT_8039a7a8,(double)DAT_8039a7ac,(double)DAT_8039a7b0,
                     (int)FLOAT_803dd160);
      }
      (**(code **)(*DAT_803dca64 + 0x18))
                (-(double)DAT_8030f2d4,(double)DAT_8030f2d8,-(double)DAT_8030f2dc,0);
    }
    else {
      if (DAT_803dd164 == '\0') {
        FUN_80062a54((double)DAT_8030f2c8,(double)DAT_8030f2cc,(double)DAT_8030f2d0,100);
      }
      else {
        FUN_80062a54((double)DAT_8039a7a8,(double)DAT_8039a7ac,(double)DAT_8039a7b0,
                     (int)FLOAT_803dd160);
      }
      (**(code **)(*DAT_803dca64 + 0x18))
                ((double)DAT_8030f2c8,(double)DAT_8030f2cc,(double)DAT_8030f2d0,1);
    }
  }
  return;
}

