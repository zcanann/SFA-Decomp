// Function: FUN_802517c0
// Entry: 802517c0
// Size: 112 bytes

undefined4 * FUN_802517c0(undefined4 *param_1)

{
  FUN_80243e74();
  FUN_80251fd0((int)param_1);
  *param_1 = 0;
  param_1[2] = 1;
  FUN_80243e9c();
  if (param_1 == DAT_803decf8) {
    FUN_80251e44((int)param_1);
  }
  return param_1;
}

