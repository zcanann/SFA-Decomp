// Function: FUN_80154d0c
// Entry: 80154d0c
// Size: 680 bytes

/* WARNING: Removing unreachable block (ram,0x80154f84) */
/* WARNING: Removing unreachable block (ram,0x80154f7c) */
/* WARNING: Removing unreachable block (ram,0x80154f8c) */

void FUN_80154d0c(int param_1,int param_2,undefined2 *param_3,float *param_4)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  double dVar4;
  undefined8 in_f29;
  double dVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0 [2];
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  undefined auStack136 [12];
  float local_7c [2];
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  undefined auStack100 [12];
  float local_58;
  float local_54;
  float local_50;
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
  local_70 = *(float *)(param_2 + 0x360);
  local_6c = *(float *)(param_2 + 0x358);
  local_68 = *(float *)(param_2 + 0x364);
  FUN_80247754(&local_70,param_1 + 0xc,auStack100);
  dVar4 = (double)FUN_8024782c(auStack100,param_2 + 0x344);
  local_70 = (float)((double)*(float *)(param_2 + 0x344) * dVar4 + (double)*(float *)(param_1 + 0xc)
                    );
  dVar7 = (double)*(float *)(param_1 + 0x10);
  local_6c = (float)((double)*(float *)(param_2 + 0x348) * dVar4 + dVar7);
  local_68 = (float)((double)*(float *)(param_2 + 0x34c) * dVar4 +
                    (double)*(float *)(param_1 + 0x14));
  local_ac = FLOAT_803e2a00;
  local_a8 = FLOAT_803e2a04;
  local_a4 = FLOAT_803e2a00;
  FUN_8024784c(&local_ac,param_2 + 0x344,local_7c);
  FUN_80247794(local_7c,local_7c);
  if (FLOAT_803e2a00 == local_7c[0]) {
    local_74 = (*(float *)(param_1 + 0x14) - *(float *)(param_2 + 0x364)) / local_74;
  }
  else {
    local_74 = (*(float *)(param_1 + 0xc) - *(float *)(param_2 + 0x360)) / local_7c[0];
  }
  dVar6 = (double)local_74;
  iVar1 = *(int *)(param_2 + 0x29c);
  local_58 = *(float *)(iVar1 + 0xc);
  local_54 = FLOAT_803e2a08 + *(float *)(iVar1 + 0x10);
  local_50 = *(float *)(iVar1 + 0x14);
  local_94 = *(float *)(param_2 + 0x360);
  local_90 = *(float *)(param_2 + 0x358);
  local_8c = *(float *)(param_2 + 0x364);
  FUN_80247754(&local_94,&local_58,auStack136);
  dVar4 = (double)FUN_8024782c(auStack136,param_2 + 0x344);
  local_94 = (float)((double)*(float *)(param_2 + 0x344) * dVar4 + (double)local_58);
  dVar5 = (double)local_54;
  local_90 = (float)((double)*(float *)(param_2 + 0x348) * dVar4 + dVar5);
  local_8c = (float)((double)*(float *)(param_2 + 0x34c) * dVar4 + (double)local_50);
  local_b8 = FLOAT_803e2a00;
  local_b4 = FLOAT_803e2a04;
  local_b0 = FLOAT_803e2a00;
  FUN_8024784c(&local_b8,param_2 + 0x344,local_a0);
  FUN_80247794(local_a0,local_a0);
  if (FLOAT_803e2a00 == local_a0[0]) {
    local_a0[0] = (local_50 - *(float *)(param_2 + 0x364)) / local_98;
  }
  else {
    local_a0[0] = (local_58 - *(float *)(param_2 + 0x360)) / local_a0[0];
  }
  dVar6 = (double)(float)(dVar6 - (double)local_a0[0]);
  dVar4 = (double)(float)(dVar7 - dVar5);
  uVar2 = FUN_800217c0(-dVar4,dVar6);
  iVar1 = (uVar2 & 0xffff) - ((int)*(short *)(param_1 + 2) & 0xffffU);
  if (0x8000 < iVar1) {
    iVar1 = iVar1 + -0xffff;
  }
  if (iVar1 < -0x8000) {
    iVar1 = iVar1 + 0xffff;
  }
  if (iVar1 < 0) {
    iVar1 = -iVar1;
  }
  *param_3 = (short)iVar1;
  dVar4 = (double)FUN_802931a0((double)(float)(dVar6 * dVar6 + (double)(float)(dVar4 * dVar4)));
  *param_4 = (float)dVar4;
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  __psq_l0(auStack40,uVar3);
  __psq_l1(auStack40,uVar3);
  return;
}

