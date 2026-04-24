// Function: FUN_800d7d18
// Entry: 800d7d18
// Size: 96 bytes

void FUN_800d7d18(double param_1,uint param_2,undefined param_3)

{
  FLOAT_803de0a0 = (float)((double)FLOAT_803e11d8 * param_1);
  FLOAT_803de0a4 =
       -(float)((double)FLOAT_803e11dc * param_1) /
       (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e11d0);
  FLOAT_803de0a8 = FLOAT_803e11e0;
  DAT_803de0ac = param_3;
  DAT_803de0ae = 1;
  return;
}

