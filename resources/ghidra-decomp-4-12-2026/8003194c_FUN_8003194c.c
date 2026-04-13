// Function: FUN_8003194c
// Entry: 8003194c
// Size: 732 bytes

/* WARNING: Removing unreachable block (ram,0x80031c00) */
/* WARNING: Removing unreachable block (ram,0x80031bf8) */
/* WARNING: Removing unreachable block (ram,0x80031bf0) */
/* WARNING: Removing unreachable block (ram,0x80031be8) */
/* WARNING: Removing unreachable block (ram,0x80031be0) */
/* WARNING: Removing unreachable block (ram,0x8003197c) */
/* WARNING: Removing unreachable block (ram,0x80031974) */
/* WARNING: Removing unreachable block (ram,0x8003196c) */
/* WARNING: Removing unreachable block (ram,0x80031964) */
/* WARNING: Removing unreachable block (ram,0x8003195c) */

float * FUN_8003194c(double param_1,double param_2,double param_3,double param_4,double param_5,
                    float *param_6,float *param_7,float *param_8,float *param_9)

{
  float fVar1;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  
  fVar1 = FLOAT_803df590;
  if ((double)FLOAT_803df590 <= param_2) {
    if (param_2 <= param_5) {
      local_64 = (float)((double)FLOAT_803df598 / param_5);
      local_6c = (*param_8 - *param_7) * local_64;
      local_68 = (param_8[1] - param_7[1]) * local_64;
      local_64 = (param_8[2] - param_7[2]) * local_64;
      FUN_800228bc(param_2,param_7,&local_6c,&local_78);
      *param_9 = *param_6 - local_78;
      param_9[1] = FLOAT_803df590;
      param_9[2] = param_6[2] - local_70;
      FUN_800228f0(param_9);
      fVar1 = (float)(param_4 - param_3) * (float)(param_2 / param_5) + (float)(param_3 + param_1);
      *param_9 = *param_9 * fVar1;
      param_9[1] = param_9[1] * fVar1;
      param_9[2] = param_9[2] * fVar1;
      *param_9 = *param_9 + local_78;
      param_9[1] = param_9[1] + local_74;
      param_9[2] = param_9[2] + local_70;
    }
    else {
      *param_9 = *param_6 - *param_8;
      param_9[1] = fVar1;
      param_9[2] = param_6[2] - param_8[2];
      FUN_800228f0(param_9);
      fVar1 = (float)(param_1 + param_4);
      *param_9 = *param_9 * fVar1;
      param_9[1] = param_9[1] * fVar1;
      param_9[2] = param_9[2] * fVar1;
      *param_9 = *param_9 + *param_8;
      param_9[1] = param_9[1] + param_8[1];
      param_9[2] = param_9[2] + param_8[2];
    }
  }
  else {
    *param_9 = *param_6 - *param_7;
    param_9[1] = fVar1;
    param_9[2] = param_6[2] - param_7[2];
    FUN_800228f0(param_9);
    fVar1 = (float)(param_1 + param_3);
    *param_9 = *param_9 * fVar1;
    param_9[1] = param_9[1] * fVar1;
    param_9[2] = param_9[2] * fVar1;
    *param_9 = *param_9 + *param_7;
    param_9[1] = param_9[1] + param_7[1];
    param_9[2] = param_9[2] + param_7[2];
  }
  return param_9;
}

