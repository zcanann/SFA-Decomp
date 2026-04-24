// Function: FUN_80027980
// Entry: 80027980
// Size: 76 bytes

void FUN_80027980(double param_1,int *param_2,int param_3)

{
  float *pfVar1;
  
  if (2 < param_3) {
    return;
  }
  if (*(int *)(*param_2 + 0xdc) == 0) {
    return;
  }
  pfVar1 = (float *)(param_2[10] + param_3 * 0x10);
  if (param_1 != (double)*pfVar1) {
    *pfVar1 = (float)param_1;
  }
  *(byte *)((int)pfVar1 + 0xe) = *(byte *)((int)pfVar1 + 0xe) | 4;
  return;
}

