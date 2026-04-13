// Function: FUN_80021730
// Entry: 80021730
// Size: 36 bytes

double FUN_80021730(float *param_1,float *param_2)

{
  return (double)((*param_1 - *param_2) * (*param_1 - *param_2) +
                 (param_1[2] - param_2[2]) * (param_1[2] - param_2[2]));
}

