// Function: FUN_800d7e58
// Entry: 800d7e58
// Size: 120 bytes

void FUN_800d7e58(uint param_1,undefined param_2)

{
  if ((FLOAT_803de0a4 <= FLOAT_803e11e0) || (FLOAT_803e11d8 == FLOAT_803de0a0)) {
    FLOAT_803de0a0 = FLOAT_803e11e0;
  }
  FLOAT_803de0a4 =
       FLOAT_803e11dc / (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803e11d0)
  ;
  FLOAT_803de0a8 = FLOAT_803e11e0;
  DAT_803de0ac = param_2;
  DAT_803de0ae = 0;
  return;
}

