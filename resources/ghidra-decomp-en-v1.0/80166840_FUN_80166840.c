// Function: FUN_80166840
// Entry: 80166840
// Size: 528 bytes

/* WARNING: Removing unreachable block (ram,0x80166a20) */
/* WARNING: Removing unreachable block (ram,0x80166a10) */
/* WARNING: Removing unreachable block (ram,0x80166a00) */
/* WARNING: Removing unreachable block (ram,0x80166a08) */
/* WARNING: Removing unreachable block (ram,0x80166a18) */
/* WARNING: Removing unreachable block (ram,0x80166a28) */

void FUN_80166840(int param_1,int param_2,undefined4 *param_3,float *param_4)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  undefined auStack88 [16];
  undefined auStack72 [16];
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
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  dVar3 = (double)FLOAT_803e3020;
  dVar6 = (double)*(float *)(param_1 + 0xc);
  dVar11 = (double)(float)(dVar3 * (double)*(float *)(param_2 + 0x7c) + dVar6);
  dVar7 = (double)*(float *)(param_1 + 0x10);
  dVar10 = (double)(float)(dVar3 * (double)*(float *)(param_2 + 0x80) + dVar7);
  dVar8 = (double)*(float *)(param_1 + 0x14);
  dVar9 = (double)(float)(dVar3 * (double)*(float *)(param_2 + 0x84) + dVar8);
  dVar4 = (double)(float)(dVar3 * (double)*(float *)(param_1 + 0x24) + dVar6);
  dVar5 = (double)(float)(dVar3 * (double)*(float *)(param_1 + 0x28) + dVar7);
  dVar3 = (double)(float)(dVar3 * (double)*(float *)(param_1 + 0x2c) + dVar8);
  dVar12 = (double)(float)(dVar7 * (double)(float)(dVar9 - dVar3) +
                          (double)(float)(dVar10 * (double)(float)(dVar3 - dVar8) +
                                         (double)(float)(dVar5 * (double)(float)(dVar8 - dVar9))));
  dVar8 = (double)(float)(dVar8 * (double)(float)(dVar11 - dVar4) +
                         (double)(float)(dVar9 * (double)(float)(dVar4 - dVar6) +
                                        (double)(float)(dVar3 * (double)(float)(dVar6 - dVar11))));
  dVar4 = (double)(float)(dVar6 * (double)(float)(dVar10 - dVar5) +
                         (double)(float)(dVar11 * (double)(float)(dVar5 - dVar7) +
                                        (double)(float)(dVar4 * (double)(float)(dVar7 - dVar10))));
  dVar3 = (double)FUN_802931a0((double)(float)(dVar4 * dVar4 +
                                              (double)(float)(dVar12 * dVar12 +
                                                             (double)(float)(dVar8 * dVar8))));
  if ((double)FLOAT_803e2fdc < dVar3) {
    dVar3 = (double)(float)((double)FLOAT_803e2ff4 / dVar3);
    dVar12 = (double)(float)(dVar12 * dVar3);
    dVar8 = (double)(float)(dVar8 * dVar3);
    dVar4 = (double)(float)(dVar4 * dVar3);
  }
  local_98 = (float)dVar12;
  local_94 = (float)dVar8;
  local_90 = (float)dVar4;
  local_8c = -(float)(dVar9 * dVar4 +
                     (double)(float)(dVar11 * dVar12 + (double)(float)(dVar10 * dVar8)));
  FUN_800228b0(&local_98,param_3,&local_88);
  FUN_8002282c(&local_88);
  fVar1 = FLOAT_803e3004;
  *(float *)(param_1 + 0x24) = FLOAT_803e3004 * local_88;
  *(float *)(param_1 + 0x28) = fVar1 * local_84;
  *(float *)(param_1 + 0x2c) = fVar1 * local_80;
  *(undefined4 *)(param_2 + 0x7c) = *param_3;
  *(undefined4 *)(param_2 + 0x80) = param_3[1];
  *(undefined4 *)(param_2 + 0x84) = param_3[2];
  *(undefined4 *)(param_2 + 0x88) = param_3[3];
  *(float *)(param_1 + 0xc) = *param_4 + *(float *)(param_2 + 0x7c);
  *(float *)(param_1 + 0x10) = param_4[1] + *(float *)(param_2 + 0x80);
  *(float *)(param_1 + 0x14) = param_4[2] + *(float *)(param_2 + 0x84);
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  __psq_l0(auStack40,uVar2);
  __psq_l1(auStack40,uVar2);
  __psq_l0(auStack56,uVar2);
  __psq_l1(auStack56,uVar2);
  __psq_l0(auStack72,uVar2);
  __psq_l1(auStack72,uVar2);
  __psq_l0(auStack88,uVar2);
  __psq_l1(auStack88,uVar2);
  return;
}

