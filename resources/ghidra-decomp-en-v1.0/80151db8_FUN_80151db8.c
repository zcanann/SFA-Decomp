// Function: FUN_80151db8
// Entry: 80151db8
// Size: 588 bytes

/* WARNING: Removing unreachable block (ram,0x80151fd4) */
/* WARNING: Removing unreachable block (ram,0x80151fcc) */
/* WARNING: Removing unreachable block (ram,0x80151fdc) */

void FUN_80151db8(short *param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar3 = FUN_8002b9ec();
  iVar4 = *(int *)(param_1 + 0x26);
  fVar1 = *(float *)(iVar3 + 0x10) - *(float *)(param_1 + 8);
  if (fVar1 < FLOAT_803e27d8) {
    fVar1 = -fVar1;
  }
  if (fVar1 <= FLOAT_803e27dc) {
    dVar6 = (double)FUN_80293e80((double)((FLOAT_803e27e0 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e27f0)) / FLOAT_803e27e4));
    dVar9 = -(double)(float)((double)FLOAT_803e27dc * dVar6 - (double)*(float *)(iVar4 + 8));
    dVar6 = (double)FUN_80294204((double)((FLOAT_803e27e0 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e27f0)) / FLOAT_803e27e4));
    dVar8 = -(double)(float)((double)FLOAT_803e27dc * dVar6 - (double)*(float *)(iVar4 + 0x10));
    fVar1 = (float)((double)*(float *)(iVar3 + 0x18) - dVar9);
    fVar2 = (float)((double)*(float *)(iVar3 + 0x20) - dVar8);
    dVar6 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
    if (dVar6 < (double)*(float *)(param_2 + 0x2ac)) {
      dVar6 = (double)FUN_80293e80((double)((FLOAT_803e27e0 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*param_1 ^ 0x80000000) -
                                                   DOUBLE_803e27f0)) / FLOAT_803e27e4));
      dVar7 = (double)FUN_80294204((double)((FLOAT_803e27e0 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*param_1 ^ 0x80000000) -
                                                   DOUBLE_803e27f0)) / FLOAT_803e27e4));
      fVar1 = -(float)(dVar6 * (double)(float)(dVar9 - dVar6) +
                      (double)(float)(dVar7 * (double)(float)(dVar8 - dVar7)));
      dVar8 = (double)(fVar1 + (float)(dVar6 * (double)*(float *)(iVar3 + 0x8c) +
                                      (double)(float)(dVar7 * (double)*(float *)(iVar3 + 0x94))));
      if ((FLOAT_803e27d8 <
           fVar1 + (float)(dVar6 * (double)*(float *)(iVar3 + 0x18) +
                          (double)(float)(dVar7 * (double)*(float *)(iVar3 + 0x20)))) &&
         ((double)FLOAT_803e27e8 <= dVar8)) {
        *(float *)(iVar3 + 0x18) = -(float)(dVar6 * dVar8 - (double)*(float *)(iVar3 + 0x18));
        *(float *)(iVar3 + 0x20) = -(float)(dVar7 * dVar8 - (double)*(float *)(iVar3 + 0x20));
        FUN_8000e034((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
                     (double)*(float *)(iVar3 + 0x20),iVar3 + 0xc,iVar3 + 0x10,iVar3 + 0x14,
                     *(undefined4 *)(iVar3 + 0x30));
      }
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  return;
}

