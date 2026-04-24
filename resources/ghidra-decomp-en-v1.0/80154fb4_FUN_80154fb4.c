// Function: FUN_80154fb4
// Entry: 80154fb4
// Size: 952 bytes

/* WARNING: Removing unreachable block (ram,0x80155340) */
/* WARNING: Removing unreachable block (ram,0x80155330) */
/* WARNING: Removing unreachable block (ram,0x80155328) */
/* WARNING: Removing unreachable block (ram,0x80155338) */
/* WARNING: Removing unreachable block (ram,0x80155348) */

uint FUN_80154fb4(double param_1,short *param_2,int param_3,uint param_4)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  short sVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  float local_108;
  float local_104;
  float local_100;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_f0 [2];
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  undefined auStack216 [12];
  float local_cc [2];
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  undefined auStack180 [12];
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  undefined auStack144 [16];
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  longlong local_70;
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
  local_c0 = *(float *)(param_3 + 0x360);
  local_bc = *(float *)(param_3 + 0x358);
  local_b8 = *(float *)(param_3 + 0x364);
  FUN_80247754(&local_c0,param_2 + 6,auStack180);
  dVar6 = (double)FUN_8024782c(auStack180,param_3 + 0x344);
  local_c0 = (float)((double)*(float *)(param_3 + 0x344) * dVar6 + (double)*(float *)(param_2 + 6));
  dVar10 = (double)*(float *)(param_2 + 8);
  local_bc = (float)((double)*(float *)(param_3 + 0x348) * dVar6 + dVar10);
  local_b8 = (float)((double)*(float *)(param_3 + 0x34c) * dVar6 + (double)*(float *)(param_2 + 10))
  ;
  local_fc = FLOAT_803e2a00;
  local_f8 = FLOAT_803e2a04;
  local_f4 = FLOAT_803e2a00;
  FUN_8024784c(&local_fc,param_3 + 0x344,local_cc);
  FUN_80247794(local_cc,local_cc);
  if (FLOAT_803e2a00 == local_cc[0]) {
    local_c4 = (*(float *)(param_2 + 10) - *(float *)(param_3 + 0x364)) / local_c4;
  }
  else {
    local_c4 = (*(float *)(param_2 + 6) - *(float *)(param_3 + 0x360)) / local_cc[0];
  }
  dVar8 = (double)local_c4;
  iVar2 = *(int *)(param_3 + 0x29c);
  local_a8 = *(float *)(iVar2 + 0xc);
  local_a4 = FLOAT_803e2a08 + *(float *)(iVar2 + 0x10);
  local_a0 = *(float *)(iVar2 + 0x14);
  local_e4 = *(float *)(param_3 + 0x360);
  local_e0 = *(float *)(param_3 + 0x358);
  local_dc = *(float *)(param_3 + 0x364);
  FUN_80247754(&local_e4,&local_a8,auStack216);
  dVar6 = (double)FUN_8024782c(auStack216,param_3 + 0x344);
  local_e4 = (float)((double)*(float *)(param_3 + 0x344) * dVar6 + (double)local_a8);
  dVar9 = (double)local_a4;
  local_e0 = (float)((double)*(float *)(param_3 + 0x348) * dVar6 + dVar9);
  local_dc = (float)((double)*(float *)(param_3 + 0x34c) * dVar6 + (double)local_a0);
  local_108 = FLOAT_803e2a00;
  local_104 = FLOAT_803e2a04;
  local_100 = FLOAT_803e2a00;
  FUN_8024784c(&local_108,param_3 + 0x344,local_f0);
  FUN_80247794(local_f0,local_f0);
  if (FLOAT_803e2a00 == local_f0[0]) {
    local_f0[0] = (local_a0 - *(float *)(param_3 + 0x364)) / local_e8;
  }
  else {
    local_f0[0] = (local_a8 - *(float *)(param_3 + 0x360)) / local_f0[0];
  }
  dVar6 = (double)(float)(dVar8 - (double)local_f0[0]);
  dVar9 = (double)(float)(dVar10 - dVar9);
  uVar3 = FUN_800217c0(-dVar9,dVar6);
  uStack116 = (uVar3 & 0xffff) - ((int)param_2[1] & 0xffffU);
  if (0x8000 < (int)uStack116) {
    uStack116 = uStack116 - 0xffff;
  }
  if ((int)uStack116 < -0x8000) {
    uStack116 = uStack116 + 0xffff;
  }
  uStack124 = param_4 & 0xffff;
  local_80 = 0x43300000;
  fVar1 = FLOAT_803db414 / (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e2a10);
  if (FLOAT_803e2a04 < fVar1) {
    fVar1 = FLOAT_803e2a04;
  }
  uStack116 = uStack116 ^ 0x80000000;
  local_78 = 0x43300000;
  uVar3 = (uint)((float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e2a18) * fVar1);
  local_70 = (longlong)(int)uVar3;
  *param_2 = param_2[1] + (short)uVar3;
  param_2[2] = 0x4000;
  param_2[1] = *param_2;
  sVar4 = FUN_800217c0((double)*(float *)(param_3 + 0x34c),-(double)*(float *)(param_3 + 0x344));
  *param_2 = sVar4;
  dVar7 = (double)FUN_802931a0((double)(float)(dVar6 * dVar6 + (double)(float)(dVar9 * dVar9)));
  if (param_1 < dVar7) {
    dVar6 = (double)(float)(param_1 *
                           (double)(float)(dVar6 * (double)(float)((double)FLOAT_803e2a04 / dVar7)))
    ;
    dVar9 = (double)(float)(param_1 *
                           (double)(float)(dVar9 * (double)(float)((double)FLOAT_803e2a04 / dVar7)))
    ;
  }
  FUN_8015536c((double)(float)(dVar8 - dVar6),(double)(float)(dVar10 - dVar9),auStack144,
               param_3 + 0x344);
  FUN_80247754(auStack144,param_2 + 6,&local_9c);
  FUN_8002b95c((double)local_9c,(double)local_98,(double)local_94,param_2);
  fVar1 = FLOAT_803e2a00;
  *(float *)(param_2 + 0x12) = FLOAT_803e2a00;
  *(float *)(param_2 + 0x14) = fVar1;
  *(float *)(param_2 + 0x16) = fVar1;
  if ((int)uVar3 < 0) {
    uVar3 = -uVar3;
  }
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
  return uVar3 & 0xffff;
}

