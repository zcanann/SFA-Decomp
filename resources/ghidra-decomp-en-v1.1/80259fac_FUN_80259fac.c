// Function: FUN_80259fac
// Entry: 80259fac
// Size: 208 bytes

void FUN_80259fac(double param_1,double param_2,int param_3,int param_4)

{
  float fVar1;
  float fVar2;
  double dVar3;
  
  if (param_1 < (double)FLOAT_803e8318) {
    param_4 = 0;
  }
  if ((param_2 <= (double)FLOAT_803e8318) || ((double)FLOAT_803e8330 <= param_2)) {
    param_4 = 0;
  }
  if (param_4 == 2) {
    dVar3 = (double)(FLOAT_803e8348 * (float)((double)FLOAT_803e8330 - param_2));
    fVar1 = (float)(dVar3 / (double)(float)(param_1 * (double)(float)(param_2 * param_1)));
    fVar2 = (float)(dVar3 / (double)(float)(param_2 * param_1));
  }
  else {
    fVar1 = FLOAT_803e8318;
    fVar2 = FLOAT_803e8318;
    if (param_4 < 2) {
      if ((param_4 != 0) && (-1 < param_4)) {
        fVar2 = (float)((double)FLOAT_803e8330 - param_2) / (float)(param_2 * param_1);
      }
    }
    else if (param_4 < 4) {
      fVar1 = (float)((double)FLOAT_803e8330 - param_2) /
              (float)(param_1 * (double)(float)(param_2 * param_1));
    }
  }
  *(float *)(param_3 + 0x1c) = FLOAT_803e8330;
  *(float *)(param_3 + 0x20) = fVar2;
  *(float *)(param_3 + 0x24) = fVar1;
  return;
}

