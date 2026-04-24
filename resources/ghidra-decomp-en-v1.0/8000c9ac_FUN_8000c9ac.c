// Function: FUN_8000c9ac
// Entry: 8000c9ac
// Size: 532 bytes

/* WARNING: Removing unreachable block (ram,0x8000cb94) */
/* WARNING: Removing unreachable block (ram,0x8000cb84) */
/* WARNING: Removing unreachable block (ram,0x8000cb74) */
/* WARNING: Removing unreachable block (ram,0x8000cb64) */
/* WARNING: Removing unreachable block (ram,0x8000cb54) */
/* WARNING: Removing unreachable block (ram,0x8000cb5c) */
/* WARNING: Removing unreachable block (ram,0x8000cb6c) */
/* WARNING: Removing unreachable block (ram,0x8000cb7c) */
/* WARNING: Removing unreachable block (ram,0x8000cb8c) */
/* WARNING: Removing unreachable block (ram,0x8000cb9c) */

void FUN_8000c9ac(short param_1,short param_2,short param_3,float *param_4)

{
  undefined4 uVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f22;
  double dVar6;
  undefined8 in_f23;
  double dVar7;
  undefined8 in_f24;
  undefined8 in_f25;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar8;
  undefined8 in_f28;
  double dVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  undefined auStack152 [16];
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar1 = 0;
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
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  __psq_st0(auStack152,(int)((ulonglong)in_f22 >> 0x20),0);
  __psq_st1(auStack152,(int)in_f22,0);
  dVar10 = (double)*param_4;
  dVar9 = (double)param_4[1];
  dVar8 = (double)param_4[2];
  dVar11 = (double)((FLOAT_803de5ac *
                    (float)((double)CONCAT44(0x43300000,(int)param_1 ^ 0x80000000) - DOUBLE_803de580
                           )) / FLOAT_803de5b0);
  dVar2 = (double)FUN_80293e80(dVar11);
  dVar7 = (double)((FLOAT_803de5ac *
                   (float)((double)CONCAT44(0x43300000,(int)param_2 ^ 0x80000000) - DOUBLE_803de580)
                   ) / FLOAT_803de5b0);
  dVar3 = (double)FUN_80293e80(dVar7);
  dVar6 = (double)((FLOAT_803de5ac *
                   (float)((double)CONCAT44(0x43300000,(int)param_3 ^ 0x80000000) - DOUBLE_803de580)
                   ) / FLOAT_803de5b0);
  dVar4 = (double)FUN_80293e80(dVar6);
  dVar11 = (double)FUN_80294204(dVar11);
  dVar7 = (double)FUN_80294204(dVar7);
  dVar6 = (double)FUN_80294204(dVar6);
  dVar5 = (double)((float)(dVar10 * dVar11) + (float)(dVar8 * dVar2));
  dVar11 = (double)((float)(dVar8 * dVar11) - (float)(dVar10 * dVar2));
  dVar2 = (double)((float)(dVar9 * dVar7) - (float)(dVar11 * dVar3));
  *param_4 = (float)(dVar5 * dVar6) - (float)(dVar2 * dVar4);
  param_4[1] = (float)(dVar2 * dVar6) + (float)(dVar5 * dVar4);
  param_4[2] = (float)(dVar11 * dVar7) + (float)(dVar9 * dVar3);
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  __psq_l0(auStack24,uVar1);
  __psq_l1(auStack24,uVar1);
  __psq_l0(auStack40,uVar1);
  __psq_l1(auStack40,uVar1);
  __psq_l0(auStack56,uVar1);
  __psq_l1(auStack56,uVar1);
  __psq_l0(auStack72,uVar1);
  __psq_l1(auStack72,uVar1);
  __psq_l0(auStack88,uVar1);
  __psq_l1(auStack88,uVar1);
  __psq_l0(auStack104,uVar1);
  __psq_l1(auStack104,uVar1);
  __psq_l0(auStack120,uVar1);
  __psq_l1(auStack120,uVar1);
  __psq_l0(auStack136,uVar1);
  __psq_l1(auStack136,uVar1);
  __psq_l0(auStack152,uVar1);
  __psq_l1(auStack152,uVar1);
  return;
}

