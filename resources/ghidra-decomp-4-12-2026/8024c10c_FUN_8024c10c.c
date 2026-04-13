// Function: FUN_8024c10c
// Entry: 8024c10c
// Size: 104 bytes

undefined4 FUN_8024c10c(int param_1,undefined4 *param_2)

{
  FUN_80243e74();
  *(undefined4 **)(&DAT_803aec3c)[param_1 * 2] = param_2;
  param_2[1] = (&DAT_803aec3c)[param_1 * 2];
  *param_2 = &DAT_803aec38 + param_1 * 2;
  (&DAT_803aec3c)[param_1 * 2] = param_2;
  FUN_80243e9c();
  return 1;
}

