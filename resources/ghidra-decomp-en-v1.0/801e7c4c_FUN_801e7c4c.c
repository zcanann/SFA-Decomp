// Function: FUN_801e7c4c
// Entry: 801e7c4c
// Size: 380 bytes

/* WARNING: Removing unreachable block (ram,0x801e7da0) */
/* WARNING: Removing unreachable block (ram,0x801e7d98) */
/* WARNING: Removing unreachable block (ram,0x801e7da8) */

double FUN_801e7c4c(short *param_1,int param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  double dVar4;
  undefined8 in_f29;
  double dVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
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
  dVar6 = (double)(*(float *)(param_2 + 0xc) - *(float *)(param_1 + 6));
  dVar5 = (double)(*(float *)(param_2 + 0x14) - *(float *)(param_1 + 10));
  dVar4 = (double)FUN_802931a0((double)(float)(dVar6 * dVar6 + (double)(float)(dVar5 * dVar5)));
  if (dVar4 != (double)FLOAT_803e59dc) {
    dVar6 = (double)(float)(dVar6 / dVar4);
    dVar5 = (double)(float)(dVar5 / dVar4);
  }
  if ((double)FLOAT_803e5a24 < dVar4) {
    uVar1 = FUN_800217c0(dVar6,dVar5);
    if (param_3 == 0) {
      iVar2 = (uVar1 & 0xffff) - ((int)*param_1 & 0xffffU);
      if (0x8000 < iVar2) {
        iVar2 = iVar2 + -0xffff;
      }
      if (iVar2 < -0x8000) {
        iVar2 = iVar2 + 0xffff;
      }
      if (iVar2 < 0x2001) {
        if (iVar2 < -0x2000) {
          iVar2 = iVar2 + 0x2000;
        }
        else {
          iVar2 = 0;
        }
      }
      else {
        iVar2 = iVar2 + -0x2000;
      }
      *param_1 = (short)(int)((float)((double)CONCAT44(0x43300000,iVar2 >> 3 ^ 0x80000000) -
                                     DOUBLE_803e5a00) * FLOAT_803db414 +
                             (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                    DOUBLE_803e5a00));
    }
    else {
      *param_1 = (short)(uVar1 & 0xffff);
    }
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  __psq_l0(auStack40,uVar3);
  __psq_l1(auStack40,uVar3);
  return dVar4;
}

