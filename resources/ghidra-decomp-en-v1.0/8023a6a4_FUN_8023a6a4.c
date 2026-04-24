// Function: FUN_8023a6a4
// Entry: 8023a6a4
// Size: 472 bytes

/* WARNING: Removing unreachable block (ram,0x8023a850) */
/* WARNING: Removing unreachable block (ram,0x8023a840) */
/* WARNING: Removing unreachable block (ram,0x8023a830) */
/* WARNING: Removing unreachable block (ram,0x8023a828) */
/* WARNING: Removing unreachable block (ram,0x8023a838) */
/* WARNING: Removing unreachable block (ram,0x8023a848) */
/* WARNING: Removing unreachable block (ram,0x8023a858) */

undefined4 FUN_8023a6a4(double param_1,double param_2,double param_3,int *param_4)

{
  int iVar1;
  short sVar2;
  short sVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f25;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  float local_98;
  float local_94;
  undefined4 local_88;
  uint uStack132;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
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
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  uVar4 = 0;
  iVar1 = *param_4;
  dVar8 = (double)((float)param_4[0x30] - *(float *)(iVar1 + 0xc));
  dVar9 = (double)((float)param_4[0x31] - *(float *)(iVar1 + 0x10));
  dVar7 = (double)((float)param_4[0x32] - *(float *)(iVar1 + 0x14));
  dVar6 = (double)FUN_802931a0((double)(float)(dVar8 * dVar8 + (double)(float)(dVar9 * dVar9)));
  sVar2 = FUN_800217c0(dVar8,dVar9);
  sVar3 = FUN_800217c0(dVar6,dVar7);
  if ((12000 < sVar3) && ((double)FLOAT_803dc4c0 < dVar7)) {
    uVar4 = 1;
  }
  dVar7 = (double)(float)(dVar6 / param_2);
  dVar6 = -param_1;
  if ((dVar6 <= dVar7) && (dVar6 = dVar7, param_1 < dVar7)) {
    dVar6 = param_1;
  }
  uStack132 = (int)sVar2 ^ 0x80000000;
  local_88 = 0x43300000;
  dVar8 = (double)((FLOAT_803e74a0 *
                   (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e7498)) /
                  FLOAT_803e74a4);
  dVar7 = (double)FUN_80293e80(dVar8);
  param_4[0x36] = (int)(float)(dVar6 * dVar7);
  dVar7 = (double)FUN_80294204(dVar8);
  param_4[0x37] = (int)(float)(dVar6 * dVar7);
  FUN_8022d48c(&local_98,*param_4);
  param_4[0x36] = (int)-(local_98 * FLOAT_803dc4c4 - (float)param_4[0x36]);
  param_4[0x37] = (int)-(local_94 * FLOAT_803dc4c4 - (float)param_4[0x37]);
  param_4[0x38] = (int)(float)param_3;
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  __psq_l0(auStack56,uVar5);
  __psq_l1(auStack56,uVar5);
  __psq_l0(auStack72,uVar5);
  __psq_l1(auStack72,uVar5);
  __psq_l0(auStack88,uVar5);
  __psq_l1(auStack88,uVar5);
  __psq_l0(auStack104,uVar5);
  __psq_l1(auStack104,uVar5);
  return uVar4;
}

