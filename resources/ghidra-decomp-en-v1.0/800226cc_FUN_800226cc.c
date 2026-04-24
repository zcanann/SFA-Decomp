// Function: FUN_800226cc
// Entry: 800226cc
// Size: 112 bytes

void FUN_800226cc(double param_1,double param_2,double param_3,float *param_4,float *param_5,
                 float *param_6,float *param_7)

{
  *param_5 = param_4[0xc] +
             (float)((double)param_4[8] * param_3 +
                    (double)(float)((double)*param_4 * param_1 +
                                   (double)(float)((double)param_4[4] * param_2)));
  *param_6 = param_4[0xd] +
             (float)((double)param_4[9] * param_3 +
                    (double)(float)((double)param_4[1] * param_1 +
                                   (double)(float)((double)param_4[5] * param_2)));
  *param_7 = param_4[0xe] +
             (float)((double)param_4[10] * param_3 +
                    (double)(float)((double)param_4[2] * param_1 +
                                   (double)(float)((double)param_4[6] * param_2)));
  return;
}

