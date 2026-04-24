// Function: FUN_80031e2c
// Entry: 80031e2c
// Size: 612 bytes

/* WARNING: Removing unreachable block (ram,0x80032064) */
/* WARNING: Removing unreachable block (ram,0x8003205c) */
/* WARNING: Removing unreachable block (ram,0x8003206c) */

float * FUN_80031e2c(double param_1,double param_2,double param_3,double param_4,float *param_5,
                    float *param_6,float *param_7,float *param_8)

{
  float fVar1;
  undefined4 uVar2;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar3;
  undefined8 in_f31;
  double dVar4;
  float local_88;
  float local_84;
  float local_80;
  undefined auStack124 [12];
  undefined auStack112 [12];
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  if ((double)FLOAT_803de910 < param_1) {
    if (param_1 < param_4) {
      dVar4 = (double)(float)(param_3 - param_2);
      dVar3 = (double)(float)(dVar4 * (double)(float)(param_1 / param_4));
      local_58 = *param_7 - *param_6;
      local_54 = param_7[1] - param_6[1];
      local_50 = param_7[2] - param_6[2];
      FUN_8002282c(&local_58);
      FUN_800227f8(param_1,param_6,&local_58,&local_88);
      local_64 = *param_5 - local_88;
      local_60 = param_5[1] - local_84;
      local_5c = param_5[2] - local_80;
      FUN_8002282c(&local_64);
      if (dVar4 == (double)FLOAT_803de910) {
        *param_8 = local_64;
        param_8[1] = local_60;
        param_8[2] = local_5c;
      }
      else {
        local_58 = (float)((double)local_58 * param_1);
        local_54 = (float)((double)local_54 * param_1);
        local_50 = (float)((double)local_50 * param_1);
        FUN_800227f8(dVar3,&local_58,&local_64,auStack112);
        FUN_8002282c(auStack112);
        fVar1 = (float)((double)FLOAT_803de918 / param_1);
        local_58 = local_58 * fVar1;
        local_54 = local_54 * fVar1;
        local_50 = local_50 * fVar1;
        FUN_800228b0(&local_64,&local_58,auStack124);
        FUN_8002282c(auStack124);
        FUN_800228b0(auStack124,auStack112,param_8);
      }
    }
    else {
      *param_8 = *param_5 - *param_7;
      param_8[1] = param_5[1] - param_7[1];
      param_8[2] = param_5[2] - param_7[2];
      FUN_8002282c(param_8);
    }
  }
  else {
    *param_8 = *param_5 - *param_7;
    param_8[1] = param_5[1] - param_7[1];
    param_8[2] = param_5[2] - param_7[2];
    FUN_8002282c(param_8);
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  __psq_l0(auStack40,uVar2);
  __psq_l1(auStack40,uVar2);
  return param_8;
}

