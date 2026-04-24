// Function: FUN_8000eb88
// Entry: 8000eb88
// Size: 548 bytes

/* WARNING: Removing unreachable block (ram,0x8000ed84) */
/* WARNING: Removing unreachable block (ram,0x8000ed8c) */

void FUN_8000eb88(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,float *param_7,float *param_8,float *param_9,float *param_10)

{
  float fVar1;
  float *pfVar2;
  float *pfVar3;
  undefined4 uVar4;
  double extraout_f1;
  double dVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  undefined8 uVar7;
  float local_58;
  float local_54;
  float local_50;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar7 = FUN_802860d4();
  pfVar2 = (float *)((ulonglong)uVar7 >> 0x20);
  pfVar3 = (float *)uVar7;
  local_58 = (float)extraout_f1;
  local_54 = (float)param_2;
  local_50 = (float)param_3;
  FUN_80247494(&DAT_803386d0,&local_58,&local_58);
  *pfVar2 = DAT_8033875c +
            DAT_80338758 * local_50 + DAT_80338750 * local_58 + DAT_80338754 * local_54;
  *pfVar3 = DAT_8033876c +
            DAT_80338768 * local_50 + DAT_80338760 * local_58 + DAT_80338764 * local_54;
  *param_7 = DAT_8033877c +
             DAT_80338778 * local_50 + DAT_80338770 * local_58 + DAT_80338774 * local_54;
  fVar1 = DAT_8033878c + DAT_80338788 * local_50 + DAT_80338780 * local_58 + DAT_80338784 * local_54
  ;
  if (FLOAT_803de60c != fVar1) {
    fVar1 = FLOAT_803de5f0 / fVar1;
    *pfVar2 = *pfVar2 * fVar1;
    *pfVar3 = *pfVar3 * fVar1;
    *param_7 = *param_7 * fVar1;
    local_50 = (float)((double)local_50 + param_4);
    if (FLOAT_803de624 < local_50) {
      local_50 = FLOAT_803de624;
    }
    fVar1 = DAT_8033878c +
            DAT_80338788 * local_50 + DAT_80338780 * local_58 + DAT_80338784 * local_54;
    if (FLOAT_803de60c != fVar1) {
      dVar6 = (double)(FLOAT_803de5f0 / fVar1);
      dVar5 = (double)FUN_80291cbc((double)(float)(dVar6 * (double)(float)(param_4 *
                                                                          (double)DAT_80338750)));
      *param_8 = (float)dVar5;
      dVar5 = (double)FUN_80291cbc((double)(float)(dVar6 * (double)(float)(param_4 *
                                                                          (double)DAT_80338764)));
      *param_9 = (float)dVar5;
      dVar5 = (double)FUN_80291cbc((double)(float)(dVar6 * (double)(float)(param_4 *
                                                                          (double)DAT_80338778)));
      *param_10 = (float)dVar5;
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  FUN_80286120();
  return;
}

