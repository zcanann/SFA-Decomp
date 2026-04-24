// Function: FUN_80222550
// Entry: 80222550
// Size: 668 bytes

/* WARNING: Removing unreachable block (ram,0x802227c4) */
/* WARNING: Removing unreachable block (ram,0x802227bc) */
/* WARNING: Removing unreachable block (ram,0x802227cc) */

void FUN_80222550(double param_1,double param_2,short *param_3,float *param_4,uint param_5)

{
  short sVar1;
  uint uVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  undefined8 uVar6;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar7;
  double local_50;
  double local_48;
  double local_40;
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
  dVar7 = (double)(FLOAT_803db414 /
                  (float)((double)CONCAT44(0x43300000,param_5 & 0xffff) - DOUBLE_803e6c48));
  if ((double)FLOAT_803e6c6c < dVar7) {
    dVar7 = (double)FLOAT_803e6c6c;
  }
  uVar2 = FUN_800217c0(-(double)*param_4,-(double)param_4[2]);
  local_50 = (double)CONCAT44(0x43300000,(uVar2 & 0xffff) - ((int)*param_3 & 0xffffU) ^ 0x80000000);
  dVar4 = (double)(float)(local_50 - DOUBLE_803e6c50);
  if ((double)FLOAT_803e6c64 < dVar4) {
    dVar4 = (double)(float)((double)FLOAT_803e6c84 + dVar4);
  }
  if (dVar4 < (double)FLOAT_803e6c8c) {
    dVar4 = (double)(float)((double)FLOAT_803e6c88 + dVar4);
  }
  dVar5 = (double)(float)(dVar4 * dVar7);
  dVar4 = (double)FLOAT_803e6c90;
  if ((dVar4 <= dVar5) && (dVar4 = dVar5, (double)FLOAT_803e6c94 < dVar5)) {
    dVar4 = (double)FLOAT_803e6c94;
  }
  *param_3 = *param_3 + (short)(int)dVar4;
  dVar5 = DOUBLE_803e6c50;
  if (param_1 != (double)FLOAT_803e6c38) {
    local_48 = (double)CONCAT44(0x43300000,(int)param_3[2] ^ 0x80000000);
    param_3[2] = (short)(int)(FLOAT_803e6c98 * (float)(local_48 - DOUBLE_803e6c50));
    param_3[2] = (short)(int)(FLOAT_803db418 * FLOAT_803e6c5c * (float)(dVar4 * param_1) +
                             (float)((double)CONCAT44(0x43300000,(int)param_3[2] ^ 0x80000000) -
                                    dVar5));
    sVar1 = param_3[2];
    if (sVar1 < -0x2000) {
      sVar1 = -0x2000;
    }
    else if (0x2000 < sVar1) {
      sVar1 = 0x2000;
    }
    param_3[2] = sVar1;
  }
  if ((double)FLOAT_803e6c38 != param_2) {
    uVar6 = FUN_802931a0((double)(*param_4 * *param_4 + param_4[2] * param_4[2]));
    uVar2 = FUN_800217c0((double)(float)((double)param_4[1] * param_2),uVar6);
    local_40 = (double)CONCAT44(0x43300000,
                                (uVar2 & 0xffff) - ((int)param_3[1] & 0xffffU) ^ 0x80000000);
    dVar4 = (double)(float)(local_40 - DOUBLE_803e6c50);
    if ((double)FLOAT_803e6c64 < dVar4) {
      dVar4 = (double)(float)((double)FLOAT_803e6c84 + dVar4);
    }
    if (dVar4 < (double)FLOAT_803e6c8c) {
      dVar4 = (double)(float)((double)FLOAT_803e6c88 + dVar4);
    }
    param_3[1] = param_3[1] + (short)(int)(dVar4 * dVar7);
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  __psq_l0(auStack40,uVar3);
  __psq_l1(auStack40,uVar3);
  return;
}

