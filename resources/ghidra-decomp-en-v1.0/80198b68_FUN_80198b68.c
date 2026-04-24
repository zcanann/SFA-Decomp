// Function: FUN_80198b68
// Entry: 80198b68
// Size: 640 bytes

/* WARNING: Removing unreachable block (ram,0x80198dc0) */
/* WARNING: Removing unreachable block (ram,0x80198db0) */
/* WARNING: Removing unreachable block (ram,0x80198da0) */
/* WARNING: Removing unreachable block (ram,0x80198da8) */
/* WARNING: Removing unreachable block (ram,0x80198db8) */
/* WARNING: Removing unreachable block (ram,0x80198dc8) */

undefined4 FUN_80198b68(short *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f26;
  double dVar11;
  undefined8 in_f27;
  double dVar12;
  undefined8 in_f28;
  double dVar13;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
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
  iVar5 = *(int *)(param_1 + 0x26);
  dVar13 = (double)*param_2;
  dVar12 = (double)param_2[1];
  dVar11 = (double)param_2[2];
  dVar7 = (double)FUN_80293e80((double)((FLOAT_803e40c8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 -(int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803e40d0)) / FLOAT_803e40cc));
  dVar8 = (double)FUN_80294204((double)((FLOAT_803e40c8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 -(int)*param_1 ^ 0x80000000) -
                                               DOUBLE_803e40d0)) / FLOAT_803e40cc));
  dVar9 = (double)FUN_80293e80((double)((FLOAT_803e40c8 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 -(int)param_1[1] ^ 0x80000000) -
                                               DOUBLE_803e40d0)) / FLOAT_803e40cc));
  dVar10 = (double)FUN_80294204((double)((FLOAT_803e40c8 *
                                         (float)((double)CONCAT44(0x43300000,
                                                                  -(int)param_1[1] ^ 0x80000000) -
                                                DOUBLE_803e40d0)) / FLOAT_803e40cc));
  fVar2 = (float)((double)(float)(dVar13 - (double)*(float *)(param_1 + 0xc)) * dVar8 -
                 (double)(float)((double)(float)(dVar11 - (double)*(float *)(param_1 + 0x10)) *
                                dVar7));
  dVar7 = (double)(float)((double)(float)(dVar13 - (double)*(float *)(param_1 + 0xc)) * dVar7 +
                         (double)(float)((double)(float)(dVar11 - (double)*(float *)(param_1 + 0x10)
                                                        ) * dVar8));
  fVar3 = (float)((double)(float)(dVar12 - (double)*(float *)(param_1 + 0xe)) * dVar10 -
                 (double)(float)(dVar7 * dVar9));
  fVar1 = (float)((double)(float)(dVar12 - (double)*(float *)(param_1 + 0xe)) * dVar9 +
                 (double)(float)(dVar7 * dVar10));
  if (fVar2 < FLOAT_803e40d8) {
    fVar2 = -fVar2;
  }
  if (fVar3 < FLOAT_803e40d8) {
    fVar3 = -fVar3;
  }
  if (fVar1 < FLOAT_803e40d8) {
    fVar1 = -fVar1;
  }
  if ((((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x3a) << 1 ^ 0x80000000) -
               DOUBLE_803e40d0) < fVar2) ||
      ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x3b) << 1 ^ 0x80000000) -
              DOUBLE_803e40d0) < fVar3)) ||
     ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x3c) << 1 ^ 0x80000000) -
             DOUBLE_803e40d0) < fVar1)) {
    uVar4 = 0;
  }
  else {
    uVar4 = 1;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  __psq_l0(auStack56,uVar6);
  __psq_l1(auStack56,uVar6);
  __psq_l0(auStack72,uVar6);
  __psq_l1(auStack72,uVar6);
  __psq_l0(auStack88,uVar6);
  __psq_l1(auStack88,uVar6);
  return uVar4;
}

