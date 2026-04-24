// Function: FUN_80031b30
// Entry: 80031b30
// Size: 764 bytes

/* WARNING: Removing unreachable block (ram,0x80031dfc) */
/* WARNING: Removing unreachable block (ram,0x80031dec) */
/* WARNING: Removing unreachable block (ram,0x80031de4) */
/* WARNING: Removing unreachable block (ram,0x80031df4) */
/* WARNING: Removing unreachable block (ram,0x80031e04) */

float * FUN_80031b30(double param_1,double param_2,double param_3,double param_4,double param_5,
                    float *param_6,float *param_7,float *param_8,float *param_9)

{
  float fVar1;
  undefined4 uVar2;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  undefined auStack72 [16];
  undefined auStack56 [16];
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
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  if ((double)FLOAT_803de910 <= param_2) {
    if (param_2 <= param_5) {
      local_64 = (float)((double)FLOAT_803de918 / param_5);
      local_6c = (*param_8 - *param_7) * local_64;
      local_68 = (param_8[1] - param_7[1]) * local_64;
      local_64 = (param_8[2] - param_7[2]) * local_64;
      FUN_800227f8(param_2,param_7,&local_6c,&local_78);
      *param_9 = *param_6 - local_78;
      param_9[1] = param_6[1] - local_74;
      param_9[2] = param_6[2] - local_70;
      FUN_8002282c(param_9);
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
      param_9[1] = param_6[1] - param_8[1];
      param_9[2] = param_6[2] - param_8[2];
      FUN_8002282c(param_9);
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
    param_9[1] = param_6[1] - param_7[1];
    param_9[2] = param_6[2] - param_7[2];
    FUN_8002282c(param_9);
    fVar1 = (float)(param_1 + param_3);
    *param_9 = *param_9 * fVar1;
    param_9[1] = param_9[1] * fVar1;
    param_9[2] = param_9[2] * fVar1;
    *param_9 = *param_9 + *param_7;
    param_9[1] = param_9[1] + param_7[1];
    param_9[2] = param_9[2] + param_7[2];
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  __psq_l0(auStack40,uVar2);
  __psq_l1(auStack40,uVar2);
  __psq_l0(auStack56,uVar2);
  __psq_l1(auStack56,uVar2);
  __psq_l0(auStack72,uVar2);
  __psq_l1(auStack72,uVar2);
  return param_9;
}

