// Function: FUN_80012e0c
// Entry: 80012e0c
// Size: 180 bytes

void FUN_80012e0c(float *param_1,short *param_2)

{
  double dVar1;
  
  dVar1 = DOUBLE_803de6a8;
  *param_1 = (float)((double)CONCAT44(0x43300000,*param_2 * 10 + 5U ^ 0x80000000) - DOUBLE_803de6a8)
  ;
  param_1[1] = (float)((double)CONCAT44(0x43300000,param_2[1] * 10 + 5U ^ 0x80000000) - dVar1);
  param_1[2] = (float)((double)CONCAT44(0x43300000,param_2[2] * 10 + 5U ^ 0x80000000) - dVar1);
  if (DAT_803dc8cc != 0) {
    FUN_8000e0a0((double)*param_1,(double)param_1[1],(double)param_1[2],param_1,param_1 + 1,
                 param_1 + 2);
  }
  return;
}

