// Function: FUN_8024b9a8
// Entry: 8024b9a8
// Size: 104 bytes

undefined4 FUN_8024b9a8(int param_1,undefined4 *param_2)

{
  FUN_8024377c();
  *(undefined4 **)(&DAT_803adfdc)[param_1 * 2] = param_2;
  param_2[1] = (&DAT_803adfdc)[param_1 * 2];
  *param_2 = &DAT_803adfd8 + param_1 * 2;
  (&DAT_803adfdc)[param_1 * 2] = param_2;
  FUN_802437a4();
  return 1;
}

