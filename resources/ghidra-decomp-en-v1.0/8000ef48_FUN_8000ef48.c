// Function: FUN_8000ef48
// Entry: 8000ef48
// Size: 368 bytes

void FUN_8000ef48(double param_1,double param_2,double param_3,float *param_4,float *param_5,
                 float *param_6,float *param_7)

{
  float fVar1;
  float local_28;
  float local_24;
  float local_20;
  
  local_28 = (float)param_1;
  local_24 = (float)param_2;
  local_20 = (float)param_3;
  FUN_80247494(&DAT_803386d0,&local_28,&local_28);
  *param_7 = local_20;
  *param_4 = DAT_8033875c +
             DAT_80338758 * local_20 + DAT_80338750 * local_28 + DAT_80338754 * local_24;
  *param_5 = DAT_8033876c +
             DAT_80338768 * local_20 + DAT_80338760 * local_28 + DAT_80338764 * local_24;
  *param_6 = DAT_8033877c +
             DAT_80338778 * local_20 + DAT_80338770 * local_28 + DAT_80338774 * local_24;
  fVar1 = DAT_8033878c + DAT_80338788 * local_20 + DAT_80338780 * local_28 + DAT_80338784 * local_24
  ;
  if (FLOAT_803de60c != fVar1) {
    fVar1 = FLOAT_803de5f0 / fVar1;
    *param_4 = *param_4 * fVar1;
    *param_5 = *param_5 * fVar1;
    *param_6 = *param_6 * fVar1;
  }
  return;
}

