// Function: FUN_80169ef4
// Entry: 80169ef4
// Size: 356 bytes

/* WARNING: Removing unreachable block (ram,0x8016a02c) */
/* WARNING: Removing unreachable block (ram,0x8016a01c) */
/* WARNING: Removing unreachable block (ram,0x8016a024) */
/* WARNING: Removing unreachable block (ram,0x8016a034) */

undefined4 FUN_80169ef4(double param_1,double param_2,float *param_3,float *param_4,char param_5)

{
  undefined4 uVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 uVar4;
  double dVar5;
  undefined8 in_f28;
  double dVar6;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
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
  dVar3 = (double)FUN_802931a0((double)((*param_3 - *param_4) * (*param_3 - *param_4) +
                                       (param_3[2] - param_4[2]) * (param_3[2] - param_4[2])));
  dVar5 = (double)(param_3[1] - param_4[1]);
  dVar7 = (double)(float)(dVar3 * (double)FLOAT_803e3110);
  dVar3 = (double)(float)((double)(float)((double)FLOAT_803e3114 * param_2) * param_2);
  dVar8 = (double)(float)(param_1 * param_1);
  dVar6 = (double)(float)(-(double)(float)(param_2 * dVar5) - dVar8);
  if ((float)(dVar6 * dVar6 -
             (double)((float)((double)FLOAT_803e3118 * dVar3) *
                     (float)(dVar5 * dVar5 + (double)(float)(dVar7 * dVar7)))) < FLOAT_803e311c) {
    uVar1 = 0x2000;
  }
  else {
    if (param_5 == '\0') {
      dVar5 = (double)FUN_802931a0();
      dVar3 = (double)(FLOAT_803e3120 * (float)(-dVar6 - dVar5)) / dVar3;
    }
    else {
      dVar5 = (double)FUN_802931a0();
      dVar3 = (double)(FLOAT_803e3120 * (float)(-dVar6 + dVar5)) / dVar3;
    }
    dVar3 = (double)FUN_802931a0((double)(float)dVar3);
    dVar3 = (double)(float)(dVar7 / dVar3);
    uVar4 = FUN_802931a0(-(double)(float)(dVar3 * dVar3 - dVar8));
    uVar1 = FUN_800217c0(uVar4,dVar3);
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  __psq_l0(auStack40,uVar2);
  __psq_l1(auStack40,uVar2);
  __psq_l0(auStack56,uVar2);
  __psq_l1(auStack56,uVar2);
  return uVar1;
}

