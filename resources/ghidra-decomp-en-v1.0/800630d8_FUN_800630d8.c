// Function: FUN_800630d8
// Entry: 800630d8
// Size: 656 bytes

/* WARNING: Removing unreachable block (ram,0x8006333c) */
/* WARNING: Removing unreachable block (ram,0x8006332c) */
/* WARNING: Removing unreachable block (ram,0x8006331c) */
/* WARNING: Removing unreachable block (ram,0x80063314) */
/* WARNING: Removing unreachable block (ram,0x80063324) */
/* WARNING: Removing unreachable block (ram,0x80063334) */
/* WARNING: Removing unreachable block (ram,0x80063344) */

undefined4
FUN_800630d8(double param_1,double param_2,double param_3,float *param_4,float *param_5,char param_6
            )

{
  float fVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f25;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
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
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  dVar4 = (double)FLOAT_803decb4;
  if (dVar4 == param_3) {
    uVar2 = 0;
  }
  else {
    dVar7 = (double)*param_4;
    dVar6 = (double)(float)(dVar7 - param_1);
    dVar5 = (double)(float)((double)*param_5 - param_2);
    dVar8 = -(double)(float)(param_3 * param_3 -
                            (double)((float)(dVar6 * dVar6) + (float)(dVar5 * dVar5)));
    if (dVar4 <= dVar8) {
      dVar10 = (double)(float)((double)param_4[1] - dVar7);
      dVar9 = (double)(float)((double)param_5[1] - (double)*param_5);
      dVar7 = (double)(float)(dVar10 * dVar10 + (double)(float)(dVar9 * dVar9));
      if ((dVar4 < dVar7) &&
         (dVar5 = (double)(FLOAT_803decb8 * (float)(dVar10 * dVar6 + (double)(float)(dVar9 * dVar5))
                          ),
         dVar4 <= (double)(float)(dVar5 * dVar5 -
                                 (double)(float)((double)(float)((double)FLOAT_803decbc * dVar7) *
                                                dVar8)))) {
        dVar6 = (double)FUN_802931a0();
        dVar4 = (double)((float)(-dVar5 + dVar6) / (float)((double)FLOAT_803decb8 * dVar7));
        dVar5 = (double)((float)(-dVar5 - dVar6) / (float)((double)FLOAT_803decb8 * dVar7));
        if (dVar4 < (double)FLOAT_803decb4) {
          dVar4 = (double)FLOAT_803decc0;
        }
        if (dVar5 < (double)FLOAT_803decb4) {
          dVar5 = (double)FLOAT_803decc0;
        }
        if (dVar5 < dVar4) {
          dVar4 = dVar5;
        }
        if (((double)FLOAT_803decb4 <= dVar4) && (dVar4 <= (double)FLOAT_803decc4)) {
          FLOAT_803dcf58 = (float)dVar4;
          if (param_6 != '\0') {
            dVar5 = (double)(float)(dVar4 * dVar10 + (double)*param_4);
            dVar4 = (double)(float)(dVar4 * dVar9 + (double)*param_5);
            dVar6 = (double)(float)((double)(float)(dVar5 - param_1) / param_3);
            dVar7 = (double)(float)((double)(float)(dVar4 - param_2) / param_3);
            fVar1 = -(float)(dVar5 * dVar6 + (double)(float)(dVar4 * dVar7));
            dVar4 = (double)(fVar1 + (float)(dVar6 * (double)param_4[1] +
                                            (double)(float)(dVar7 * (double)param_5[1])));
            param_4[1] = -(float)(dVar4 * dVar6 - (double)param_4[1]);
            param_5[1] = -(float)(dVar4 * dVar7 - (double)param_5[1]);
            dVar4 = (double)FLOAT_803decc8;
            while ((double)(fVar1 + (float)((double)param_4[1] * dVar6 +
                                           (double)(float)((double)param_5[1] * dVar7))) < dVar4) {
              param_4[1] = param_4[1] + (float)(dVar4 * dVar6);
              param_5[1] = param_5[1] + (float)(dVar4 * dVar7);
            }
          }
          uVar2 = 1;
          goto LAB_80063314;
        }
      }
      uVar2 = 0;
    }
    else {
      if (param_6 != '\0') {
        param_4[1] = (float)(dVar7 + (double)FLOAT_803dcf54);
        param_5[1] = *param_5 + FLOAT_803dcf50;
      }
      uVar2 = 0;
    }
  }
LAB_80063314:
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  __psq_l0(auStack40,uVar3);
  __psq_l1(auStack40,uVar3);
  __psq_l0(auStack56,uVar3);
  __psq_l1(auStack56,uVar3);
  __psq_l0(auStack72,uVar3);
  __psq_l1(auStack72,uVar3);
  __psq_l0(auStack88,uVar3);
  __psq_l1(auStack88,uVar3);
  __psq_l0(auStack104,uVar3);
  __psq_l1(auStack104,uVar3);
  return uVar2;
}

