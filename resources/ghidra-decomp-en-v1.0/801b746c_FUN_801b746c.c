// Function: FUN_801b746c
// Entry: 801b746c
// Size: 324 bytes

/* WARNING: Removing unreachable block (ram,0x801b758c) */

void FUN_801b746c(short *param_1,int param_2)

{
  float *pfVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 in_f31;
  double dVar4;
  undefined auStack8 [8];
  
  dVar3 = DOUBLE_803e4a70;
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  dVar4 = (double)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000)
                          - DOUBLE_803e4a70) / FLOAT_803e4a64);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  pfVar1 = *(float **)(param_1 + 0x5c);
  dVar3 = (double)FUN_80293e80((double)((FLOAT_803e4a68 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) - dVar3
                                               )) / FLOAT_803e4a6c));
  *pfVar1 = (float)(dVar4 * dVar3);
  dVar3 = (double)FUN_80294204((double)((FLOAT_803e4a68 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803e4a70)) / FLOAT_803e4a6c));
  pfVar1[1] = (float)(dVar4 * dVar3);
  pfVar1[3] = FLOAT_803e4a60;
  pfVar1[4] = 0.0;
  FUN_80037200(param_1,0x16);
  param_1[0x58] = param_1[0x58] | 0x2000;
  if (*(int *)(param_2 + 0x14) == 0x49b23) {
    FUN_800200e8(0xc5c,1);
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

