// Function: FUN_8015536c
// Entry: 8015536c
// Size: 328 bytes

/* WARNING: Removing unreachable block (ram,0x80155494) */

void FUN_8015536c(double param_1,double param_2,float *param_3,float *param_4)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f31;
  float local_38;
  float local_34;
  float local_30;
  float local_2c [2];
  float local_24;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  dVar3 = (double)(param_4[6] - FLOAT_803e2a20);
  if ((param_2 <= dVar3) && (dVar3 = param_2, param_2 < (double)(FLOAT_803e2a24 + param_4[5]))) {
    dVar3 = (double)(FLOAT_803e2a24 + param_4[5]);
  }
  dVar5 = (double)param_4[4];
  if (dVar5 <= (double)FLOAT_803e2a00) {
    dVar4 = (double)(float)((double)FLOAT_803e2a20 + dVar5);
    fVar1 = FLOAT_803e2a28;
  }
  else {
    dVar4 = (double)FLOAT_803e2a20;
    fVar1 = (float)(dVar5 - dVar4);
  }
  dVar5 = (double)fVar1;
  if ((param_1 <= dVar5) && (dVar5 = param_1, param_1 < dVar4)) {
    dVar5 = dVar4;
  }
  param_3[1] = (float)dVar3;
  local_38 = FLOAT_803e2a00;
  local_34 = FLOAT_803e2a04;
  local_30 = FLOAT_803e2a00;
  FUN_8024784c(&local_38,param_4,local_2c);
  FUN_80247794(local_2c,local_2c);
  *param_3 = (float)(dVar5 * (double)local_2c[0] + (double)param_4[7]);
  param_3[2] = (float)(dVar5 * (double)local_24 + (double)param_4[8]);
  fVar1 = FLOAT_803e2a2c;
  *param_3 = FLOAT_803e2a2c * *param_4 + *param_3;
  param_3[1] = fVar1 * param_4[1] + param_3[1];
  param_3[2] = fVar1 * param_4[2] + param_3[2];
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

