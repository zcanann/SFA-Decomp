// Function: FUN_80010c50
// Entry: 80010c50
// Size: 20 bytes

double FUN_80010c50(double param_1,float *param_2)

{
  return (double)(float)(param_1 * (double)(float)((double)param_2[1] - (double)*param_2) +
                        (double)*param_2);
}

