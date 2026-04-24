// Function: FUN_800660c8
// Entry: 800660c8
// Size: 1076 bytes

/* WARNING: Removing unreachable block (ram,0x800664d8) */

undefined4
FUN_800660c8(double param_1,double param_2,float *param_3,float *param_4,float *param_5,
            float *param_6,byte param_7)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  undefined8 uVar5;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (param_7 == 3) {
    *param_4 = *param_5;
    param_4[1] = param_5[1];
    param_4[2] = param_5[2];
    local_2c = *param_4 - *param_3;
    local_28 = param_4[1] - param_3[1];
    local_24 = param_4[2] - param_3[2];
    FUN_8002282c(&local_2c);
    fVar1 = (float)((double)(param_6[3] +
                            param_4[2] * param_6[2] + *param_4 * *param_6 + param_4[1] * param_6[1])
                   - param_2);
    fVar2 = (float)((double)(param_6[3] +
                            param_3[2] * param_6[2] + *param_3 * *param_6 + param_3[1] * param_6[1])
                   - param_2);
    fVar3 = FLOAT_803decb4;
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
    goto LAB_800664d8;
  }
  if ((FLOAT_803decb0 <= param_6[1]) || (param_6[1] <= FLOAT_803decec)) {
    if ((param_7 == 8) || ((param_7 < 8 && (param_7 == 5)))) {
      *param_4 = -(float)(param_1 * (double)*param_6 - (double)*param_4);
      param_4[1] = -(float)(param_1 * (double)param_6[1] - (double)param_4[1]);
      param_4[2] = -(float)(param_1 * (double)param_6[2] - (double)param_4[2]);
      fVar1 = (float)(param_2 -
                     (double)(param_6[3] +
                             param_4[2] * param_6[2] + *param_4 * *param_6 + param_4[1] * param_6[1]
                             ));
      *param_4 = fVar1 * *param_6 + *param_4;
      param_4[1] = fVar1 * param_6[1] + param_4[1];
      param_4[2] = fVar1 * param_6[2] + param_4[2];
    }
    else {
      fVar1 = param_6[2];
      fVar2 = *param_6;
      dVar7 = (double)(float)(param_2 -
                             (double)(param_6[3] +
                                     param_4[2] * fVar1 + *param_4 * fVar2 + param_4[1] * param_6[1]
                                     ));
      if ((double)FLOAT_803decb4 < dVar7) {
        uVar5 = FUN_802931a0((double)(fVar2 * fVar2 + fVar1 * fVar1));
        FUN_802925c4((double)param_6[1],uVar5);
        dVar6 = (double)FUN_80294098();
        param_4[1] = param_4[1] + (float)(dVar7 / dVar6);
      }
    }
    goto LAB_800664d8;
  }
  if (param_7 == 8) {
LAB_8006627c:
    fVar1 = param_6[2];
    fVar2 = *param_6;
    dVar7 = (double)(float)(param_2 -
                           (double)(param_6[3] +
                                   param_4[2] * fVar1 + *param_4 * fVar2 + param_4[1] * param_6[1]))
    ;
    if ((double)FLOAT_803decb4 < dVar7) {
      uVar5 = FUN_802931a0((double)(fVar2 * fVar2 + fVar1 * fVar1));
      FUN_802925c4((double)param_6[1],uVar5);
      dVar6 = (double)FUN_802943f4();
      if ((double)FLOAT_803decb4 != dVar6) {
        dVar7 = (double)(float)(dVar7 / dVar6);
      }
      local_38 = *param_6;
      local_34 = FLOAT_803decb4;
      local_30 = param_6[2];
      FUN_8002282c(&local_38);
      *param_4 = (float)(dVar7 * (double)local_38 + (double)*param_4);
      param_4[2] = (float)(dVar7 * (double)local_30 + (double)param_4[2]);
    }
  }
  else {
    if (param_7 < 8) {
      if (param_7 == 1) goto LAB_8006627c;
    }
    else if (param_7 == 10) goto LAB_8006627c;
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
LAB_800664d8:
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return 1;
}

