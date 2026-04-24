// Function: FUN_80031f24
// Entry: 80031f24
// Size: 612 bytes

/* WARNING: Removing unreachable block (ram,0x80032164) */
/* WARNING: Removing unreachable block (ram,0x8003215c) */
/* WARNING: Removing unreachable block (ram,0x80032154) */
/* WARNING: Removing unreachable block (ram,0x80031f44) */
/* WARNING: Removing unreachable block (ram,0x80031f3c) */
/* WARNING: Removing unreachable block (ram,0x80031f34) */

float * FUN_80031f24(double param_1,double param_2,double param_3,double param_4,float *param_5,
                    float *param_6,float *param_7,float *param_8)

{
  float fVar1;
  double dVar2;
  double dVar3;
  float local_88;
  float local_84;
  float local_80;
  float afStack_7c [3];
  float afStack_70 [3];
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  
  if ((double)FLOAT_803df590 < param_1) {
    if (param_1 < param_4) {
      dVar3 = (double)(float)(param_3 - param_2);
      dVar2 = (double)(float)(dVar3 * (double)(float)(param_1 / param_4));
      local_58 = *param_7 - *param_6;
      local_54 = param_7[1] - param_6[1];
      local_50 = param_7[2] - param_6[2];
      FUN_800228f0(&local_58);
      FUN_800228bc(param_1,param_6,&local_58,&local_88);
      local_64 = *param_5 - local_88;
      local_60 = param_5[1] - local_84;
      local_5c = param_5[2] - local_80;
      FUN_800228f0(&local_64);
      if (dVar3 == (double)FLOAT_803df590) {
        *param_8 = local_64;
        param_8[1] = local_60;
        param_8[2] = local_5c;
      }
      else {
        local_58 = (float)((double)local_58 * param_1);
        local_54 = (float)((double)local_54 * param_1);
        local_50 = (float)((double)local_50 * param_1);
        FUN_800228bc(dVar2,&local_58,&local_64,afStack_70);
        FUN_800228f0(afStack_70);
        fVar1 = (float)((double)FLOAT_803df598 / param_1);
        local_58 = local_58 * fVar1;
        local_54 = local_54 * fVar1;
        local_50 = local_50 * fVar1;
        FUN_80022974(&local_64,&local_58,afStack_7c);
        FUN_800228f0(afStack_7c);
        FUN_80022974(afStack_7c,afStack_70,param_8);
      }
    }
    else {
      *param_8 = *param_5 - *param_7;
      param_8[1] = param_5[1] - param_7[1];
      param_8[2] = param_5[2] - param_7[2];
      FUN_800228f0(param_8);
    }
  }
  else {
    *param_8 = *param_5 - *param_7;
    param_8[1] = param_5[1] - param_7[1];
    param_8[2] = param_5[2] - param_7[2];
    FUN_800228f0(param_8);
  }
  return param_8;
}

