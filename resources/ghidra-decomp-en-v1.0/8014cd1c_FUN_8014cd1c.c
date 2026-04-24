// Function: FUN_8014cd1c
// Entry: 8014cd1c
// Size: 608 bytes

/* WARNING: Removing unreachable block (ram,0x8014cf50) */
/* WARNING: Removing unreachable block (ram,0x8014cf48) */
/* WARNING: Removing unreachable block (ram,0x8014cf58) */

void FUN_8014cd1c(double param_1,double param_2,short *param_3,int param_4,uint param_5,char param_6
                 )

{
  uint uVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar6;
  double local_50;
  double local_48;
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
  dVar6 = (double)(FLOAT_803db414 /
                  (float)((double)CONCAT44(0x43300000,param_5 & 0xffff) - DOUBLE_803e25e0));
  if ((double)FLOAT_803e256c < dVar6) {
    dVar6 = (double)FLOAT_803e256c;
  }
  uVar1 = FUN_800217c0(-(double)*(float *)(param_4 + 0x2b8),-(double)*(float *)(param_4 + 0x2c0));
  local_50 = (double)CONCAT44(0x43300000,(uVar1 & 0xffff) - ((int)*param_3 & 0xffffU) ^ 0x80000000);
  dVar4 = (double)(float)(local_50 - DOUBLE_803e2580);
  if ((double)FLOAT_803e25b8 < dVar4) {
    dVar4 = (double)(float)((double)FLOAT_803e25ec + dVar4);
  }
  if (dVar4 < (double)FLOAT_803e25f4) {
    dVar4 = (double)(float)((double)FLOAT_803e25f0 + dVar4);
  }
  dVar5 = (double)(float)(dVar4 * dVar6);
  *param_3 = *param_3 + (short)(int)(dVar4 * dVar6);
  if (param_1 != (double)FLOAT_803e2574) {
    if (param_6 == '\0') {
      param_3[2] = (short)(int)(FLOAT_803db418 * (float)(dVar5 * param_1));
      if (param_3[2] < 0x2001) {
        if (param_3[2] < -0x2000) {
          param_3[2] = -0x2000;
        }
      }
      else {
        param_3[2] = 0x2000;
      }
    }
    else {
      param_3[2] = param_3[2] + (short)(int)(param_1 * (double)(float)(dVar5 * dVar6));
    }
  }
  if ((double)FLOAT_803e2574 != param_2) {
    uVar3 = FUN_802931a0((double)(*(float *)(param_4 + 0x2c0) * *(float *)(param_4 + 0x2c0) +
                                 *(float *)(param_4 + 0x2b8) * *(float *)(param_4 + 0x2b8)));
    uVar1 = FUN_800217c0((double)(float)((double)*(float *)(param_4 + 700) * param_2),uVar3);
    local_48 = (double)CONCAT44(0x43300000,
                                (uVar1 & 0xffff) - ((int)param_3[1] & 0xffffU) ^ 0x80000000);
    dVar4 = (double)(float)(local_48 - DOUBLE_803e2580);
    if ((double)FLOAT_803e25b8 < dVar4) {
      dVar4 = (double)(float)((double)FLOAT_803e25ec + dVar4);
    }
    if (dVar4 < (double)FLOAT_803e25f4) {
      dVar4 = (double)(float)((double)FLOAT_803e25f0 + dVar4);
    }
    param_3[1] = param_3[1] + (short)(int)(dVar4 * dVar6);
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  __psq_l0(auStack40,uVar2);
  __psq_l1(auStack40,uVar2);
  return;
}

