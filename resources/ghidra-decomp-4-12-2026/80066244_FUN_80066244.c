// Function: FUN_80066244
// Entry: 80066244
// Size: 1076 bytes

/* WARNING: Removing unreachable block (ram,0x80066654) */
/* WARNING: Removing unreachable block (ram,0x80066254) */

undefined4
FUN_80066244(double param_1,double param_2,float *param_3,float *param_4,float *param_5,
            float *param_6,byte param_7)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  if (param_7 == 3) {
    *param_4 = *param_5;
    param_4[1] = param_5[1];
    param_4[2] = param_5[2];
    local_2c = *param_4 - *param_3;
    local_28 = param_4[1] - param_3[1];
    local_24 = param_4[2] - param_3[2];
    FUN_800228f0(&local_2c);
    fVar1 = (float)((double)(param_6[3] +
                            param_4[2] * param_6[2] + *param_4 * *param_6 + param_4[1] * param_6[1])
                   - param_2);
    fVar2 = (float)((double)(param_6[3] +
                            param_3[2] * param_6[2] + *param_3 * *param_6 + param_3[1] * param_6[1])
                   - param_2);
    fVar3 = FLOAT_803df934;
    if (fVar2 != fVar1) {
      fVar3 = fVar2 / (fVar2 - fVar1);
    }
    fVar1 = param_3[1];
    fVar2 = param_3[2];
    *param_4 = (*param_4 - *param_3) * fVar3;
    param_4[1] = (param_4[1] - fVar1) * fVar3;
    param_4[2] = (param_4[2] - fVar2) * fVar3;
    *param_4 = *param_4 + *param_3;
    param_4[1] = param_4[1] + param_3[1];
    param_4[2] = param_4[2] + param_3[2];
    return 1;
  }
  if ((FLOAT_803df930 <= param_6[1]) || (param_6[1] <= FLOAT_803df96c)) {
    if ((param_7 != 8) && ((7 < param_7 || (param_7 != 5)))) {
      fVar1 = param_6[2];
      fVar2 = *param_6;
      dVar5 = (double)(float)(param_2 -
                             (double)(param_6[3] +
                                     param_4[2] * fVar1 + *param_4 * fVar2 + param_4[1] * param_6[1]
                                     ));
      if (dVar5 <= (double)FLOAT_803df934) {
        return 1;
      }
      FUN_80293900((double)(fVar2 * fVar2 + fVar1 * fVar1));
      FUN_80292d24();
      dVar4 = (double)FUN_802947f8();
      param_4[1] = param_4[1] + (float)(dVar5 / dVar4);
      return 1;
    }
    *param_4 = -(float)(param_1 * (double)*param_6 - (double)*param_4);
    param_4[1] = -(float)(param_1 * (double)param_6[1] - (double)param_4[1]);
    param_4[2] = -(float)(param_1 * (double)param_6[2] - (double)param_4[2]);
    fVar1 = (float)(param_2 -
                   (double)(param_6[3] +
                           param_4[2] * param_6[2] + *param_4 * *param_6 + param_4[1] * param_6[1]))
    ;
    *param_4 = fVar1 * *param_6 + *param_4;
    param_4[1] = fVar1 * param_6[1] + param_4[1];
    param_4[2] = fVar1 * param_6[2] + param_4[2];
    return 1;
  }
  if (param_7 == 8) {
LAB_800663f8:
    fVar1 = param_6[2];
    fVar2 = *param_6;
    dVar5 = (double)(float)(param_2 -
                           (double)(param_6[3] +
                                   param_4[2] * fVar1 + *param_4 * fVar2 + param_4[1] * param_6[1]))
    ;
    if ((double)FLOAT_803df934 < dVar5) {
      FUN_80293900((double)(fVar2 * fVar2 + fVar1 * fVar1));
      FUN_80292d24();
      dVar4 = (double)FUN_80294b54();
      if ((double)FLOAT_803df934 != dVar4) {
        dVar5 = (double)(float)(dVar5 / dVar4);
      }
      local_38 = *param_6;
      local_34 = FLOAT_803df934;
      local_30 = param_6[2];
      FUN_800228f0(&local_38);
      *param_4 = (float)(dVar5 * (double)local_38 + (double)*param_4);
      param_4[2] = (float)(dVar5 * (double)local_30 + (double)param_4[2]);
    }
  }
  else {
    if (param_7 < 8) {
      if (param_7 == 1) goto LAB_800663f8;
    }
    else if (param_7 == 10) goto LAB_800663f8;
    *param_4 = -(float)(param_1 * (double)*param_6 - (double)*param_4);
    param_4[1] = -(float)(param_1 * (double)param_6[1] - (double)param_4[1]);
    param_4[2] = -(float)(param_1 * (double)param_6[2] - (double)param_4[2]);
    fVar1 = (float)(param_2 -
                   (double)(param_6[3] +
                           param_4[2] * param_6[2] + *param_4 * *param_6 + param_4[1] * param_6[1]))
    ;
    *param_4 = fVar1 * *param_6 + *param_4;
    param_4[1] = fVar1 * param_6[1] + param_4[1];
    param_4[2] = fVar1 * param_6[2] + param_4[2];
  }
  return 1;
}

