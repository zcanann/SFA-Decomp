// Function: FUN_80080404
// Entry: 80080404
// Size: 48 bytes

void FUN_80080404(float *param_1,short param_2)

{
  *param_1 = (float)((double)CONCAT44(0x43300000,(int)param_2 ^ 0x80000000) - DOUBLE_803dfc28);
  return;
}

