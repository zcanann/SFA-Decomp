// Function: FUN_8005ab70
// Entry: 8005ab70
// Size: 892 bytes

/* WARNING: Removing unreachable block (ram,0x8005aebc) */
/* WARNING: Removing unreachable block (ram,0x8005aeac) */
/* WARNING: Removing unreachable block (ram,0x8005ae9c) */
/* WARNING: Removing unreachable block (ram,0x8005aea4) */
/* WARNING: Removing unreachable block (ram,0x8005aeb4) */
/* WARNING: Removing unreachable block (ram,0x8005aec4) */

void FUN_8005ab70(void)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  undefined8 uVar7;
  undefined8 in_f26;
  double dVar8;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  float local_e8;
  float local_e4;
  float local_e0;
  short local_dc;
  short local_da;
  undefined2 local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  undefined auStack196 [68];
  longlong local_80;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
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
  iVar3 = FUN_8000faac();
  if (((DAT_803dcde8 & 8) == 0) && ((DAT_803dcde8 & 0x10000) == 0)) {
    dVar5 = (double)FUN_8000fc34();
    dVar5 = dVar5 * (double)FLOAT_803debfc;
  }
  else {
    dVar5 = (double)FUN_8000fc34();
    dVar5 = dVar5 / (double)FLOAT_803debf8;
  }
  dVar5 = (double)(float)dVar5;
  dVar11 = (double)(*(float *)(iVar3 + 0x44) - FLOAT_803dcdd8);
  dVar10 = (double)*(float *)(iVar3 + 0x48);
  dVar9 = (double)(*(float *)(iVar3 + 0x4c) - FLOAT_803dcddc);
  local_d0 = FLOAT_803debcc;
  local_cc = FLOAT_803debcc;
  local_c8 = FLOAT_803debcc;
  local_d4 = FLOAT_803debdc;
  local_dc = -0x8000 - *(short *)(iVar3 + 0x50);
  local_da = -*(short *)(iVar3 + 0x52);
  local_d8 = *(undefined2 *)(iVar3 + 0x54);
  FUN_80021ee8(auStack196,&local_dc);
  FUN_800226cc((double)FLOAT_803debcc,(double)FLOAT_803debcc,(double)FLOAT_803dec00,auStack196,
               &local_e0,&local_e4,&local_e8);
  DAT_8038793c = local_e0;
  DAT_80387940 = local_e4;
  DAT_80387944 = local_e8;
  DAT_80387948 = -(float)(dVar9 * (double)local_e8 +
                         (double)(float)(dVar11 * (double)local_e0 +
                                        (double)(float)(dVar10 * (double)local_e4)));
  local_80 = (longlong)(int)((double)FLOAT_803dec04 * dVar5);
  uVar2 = (int)((double)FLOAT_803dec04 * dVar5) & 0xffff;
  dVar5 = (double)FUN_80293ac4(uVar2);
  dVar6 = (double)FUN_802935ac(uVar2);
  fVar1 = (float)(dVar6 / dVar5) * (float)(dVar6 / dVar5);
  FUN_802931a0((double)(FLOAT_803dec08 * FLOAT_803dec08 * fVar1 + fVar1));
  uVar7 = FUN_80292248();
  dVar5 = (double)FUN_80294098();
  dVar6 = (double)FUN_802943f4(uVar7);
  dVar5 = -dVar5;
  FUN_800226cc(dVar6,(double)FLOAT_803debcc,dVar5,auStack196,&local_e0,&local_e4,&local_e8);
  DAT_80387950 = local_e0;
  DAT_80387954 = local_e4;
  DAT_80387958 = local_e8;
  DAT_8038795c = -(float)(dVar9 * (double)local_e8 +
                         (double)(float)(dVar11 * (double)local_e0 +
                                        (double)(float)(dVar10 * (double)local_e4)));
  dVar8 = -dVar6;
  FUN_800226cc(dVar8,(double)FLOAT_803debcc,dVar5,auStack196,&local_e0,&local_e4,&local_e8);
  DAT_80387964 = local_e0;
  DAT_80387968 = local_e4;
  DAT_8038796c = local_e8;
  DAT_80387970 = -(float)(dVar9 * (double)local_e8 +
                         (double)(float)(dVar11 * (double)local_e0 +
                                        (double)(float)(dVar10 * (double)local_e4)));
  FUN_800226cc((double)FLOAT_803debcc,dVar8,dVar5,auStack196,&local_e0,&local_e4,&local_e8);
  DAT_80387978 = local_e0;
  DAT_8038797c = local_e4;
  DAT_80387980 = local_e8;
  DAT_80387984 = -(float)(dVar9 * (double)local_e8 +
                         (double)(float)(dVar11 * (double)local_e0 +
                                        (double)(float)(dVar10 * (double)local_e4)));
  FUN_800226cc((double)FLOAT_803debcc,dVar6,dVar5,auStack196,&local_e0,&local_e4,&local_e8);
  DAT_8038798c = local_e0;
  DAT_80387990 = local_e4;
  DAT_80387994 = local_e8;
  DAT_80387998 = -(float)(dVar9 * (double)local_e8 +
                         (double)(float)(dVar11 * (double)local_e0 +
                                        (double)(float)(dVar10 * (double)local_e4)));
  FUN_8005a8a4(&DAT_8038793c,5);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  __psq_l0(auStack56,uVar4);
  __psq_l1(auStack56,uVar4);
  __psq_l0(auStack72,uVar4);
  __psq_l1(auStack72,uVar4);
  __psq_l0(auStack88,uVar4);
  __psq_l1(auStack88,uVar4);
  return;
}

