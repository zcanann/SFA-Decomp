// Function: FUN_8000ef68
// Entry: 8000ef68
// Size: 368 bytes

void FUN_8000ef68(double param_1,double param_2,double param_3,float *param_4,float *param_5,
                 float *param_6,float *param_7)

{
  float fVar1;
  float local_28;
  float local_24;
  float local_20;
  
  local_28 = (float)param_1;
  local_24 = (float)param_2;
  local_20 = (float)param_3;
  FUN_80247bf8((float *)&DAT_80339330,&local_28,&local_28);
  *param_7 = local_20;
  *param_4 = DAT_803393bc +
             DAT_803393b8 * local_20 + DAT_803393b0 * local_28 + DAT_803393b4 * local_24;
  *param_5 = DAT_803393cc +
             DAT_803393c8 * local_20 + DAT_803393c0 * local_28 + DAT_803393c4 * local_24;
  *param_6 = DAT_803393dc +
             DAT_803393d8 * local_20 + DAT_803393d0 * local_28 + DAT_803393d4 * local_24;
  fVar1 = DAT_803393ec + DAT_803393e8 * local_20 + DAT_803393e0 * local_28 + DAT_803393e4 * local_24
  ;
  if (FLOAT_803df28c != fVar1) {
    fVar1 = FLOAT_803df270 / fVar1;
    *param_4 = *param_4 * fVar1;
    *param_5 = *param_5 * fVar1;
    *param_6 = *param_6 * fVar1;
  }
  return;
}

