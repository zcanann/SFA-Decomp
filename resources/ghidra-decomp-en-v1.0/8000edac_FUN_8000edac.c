// Function: FUN_8000edac
// Entry: 8000edac
// Size: 412 bytes

/* WARNING: Removing unreachable block (ram,0x8000ef24) */

void FUN_8000edac(double param_1,double param_2,double param_3,undefined8 param_4,float *param_5,
                 float *param_6,float *param_7)

{
  float fVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined auStack56 [12];
  float local_2c;
  float local_28;
  float local_24;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  local_2c = (float)param_1;
  local_28 = (float)param_2;
  local_24 = (float)param_3;
  FUN_80247494(&DAT_803386d0,&local_2c,&local_2c);
  FUN_80247794(&local_2c,auStack56);
  FUN_80247778(param_4,auStack56,auStack56);
  FUN_80247754(&local_2c,auStack56,&local_2c);
  *param_5 = DAT_8033875c +
             DAT_80338758 * local_24 + DAT_80338750 * local_2c + DAT_80338754 * local_28;
  *param_6 = DAT_8033876c +
             DAT_80338768 * local_24 + DAT_80338760 * local_2c + DAT_80338764 * local_28;
  *param_7 = DAT_8033877c +
             DAT_80338778 * local_24 + DAT_80338770 * local_2c + DAT_80338774 * local_28;
  fVar1 = DAT_8033878c + DAT_80338788 * local_24 + DAT_80338780 * local_2c + DAT_80338784 * local_28
  ;
  if (FLOAT_803de60c != fVar1) {
    fVar1 = FLOAT_803de5f0 / fVar1;
    *param_5 = *param_5 * fVar1;
    *param_6 = *param_6 * fVar1;
    *param_7 = *param_7 * fVar1;
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

