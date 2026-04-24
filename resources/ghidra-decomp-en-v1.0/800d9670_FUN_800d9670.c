// Function: FUN_800d9670
// Entry: 800d9670
// Size: 412 bytes

/* WARNING: Removing unreachable block (ram,0x800d97e8) */

void FUN_800d9670(short *param_1,uint *param_2,undefined4 param_3)

{
  undefined4 uVar1;
  double dVar2;
  double dVar3;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if ((*(byte *)(param_2 + 0xd3) & 1) != 0) {
    dVar2 = (double)FUN_80293e80((double)((FLOAT_803e05a4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e0598)) / FLOAT_803e05a8));
    dVar3 = (double)FUN_80294204((double)((FLOAT_803e05a4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e0598)) / FLOAT_803e05a8));
    if ((*(byte *)(param_2 + 0xd3) & 8) == 0) {
      param_2[0xa1] =
           (uint)(float)((double)*(float *)(param_1 + 0x12) * dVar3 -
                        (double)(float)((double)*(float *)(param_1 + 0x16) * dVar2));
      param_2[0xa0] =
           (uint)(float)(-(double)*(float *)(param_1 + 0x16) * dVar3 -
                        (double)(float)((double)*(float *)(param_1 + 0x12) * dVar2));
      if ((*(byte *)(param_2 + 0xd3) & 4) != 0) {
        dVar2 = (double)FUN_802931a0((double)(*(float *)(param_1 + 0x12) *
                                              *(float *)(param_1 + 0x12) +
                                             *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)
                                             ));
        param_2[0xa5] = (uint)(float)dVar2;
      }
    }
    else {
      param_2[0xa0] =
           (uint)(float)(-(double)*(float *)(param_1 + 0x16) * dVar3 -
                        (double)(float)((double)*(float *)(param_1 + 0x12) * dVar2));
      param_2[0xa5] = param_2[0xa0];
    }
    *(undefined *)(param_2 + 0xd3) = 0;
    *param_2 = *param_2 | 0x80000;
    DAT_803dd434 = 1;
    DAT_803dd44f = 0;
    DAT_803dd44e = 1;
    FUN_800d92d0((double)FLOAT_803db414,param_1,param_2,param_3);
  }
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  return;
}

