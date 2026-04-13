// Function: FUN_80056d08
// Entry: 80056d08
// Size: 48 bytes

void FUN_80056d08(int param_1,float *param_2,float *param_3)

{
  float fVar1;
  
  fVar1 = FLOAT_803df848;
  *param_2 = *(float *)(DAT_803ddae8 + param_1 * 0x10) / FLOAT_803df848;
  *param_3 = *(float *)(DAT_803ddae8 + param_1 * 0x10 + 4) / fVar1;
  return;
}

