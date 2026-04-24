// Function: FUN_80155460
// Entry: 80155460
// Size: 952 bytes

/* WARNING: Removing unreachable block (ram,0x801557f4) */
/* WARNING: Removing unreachable block (ram,0x801557ec) */
/* WARNING: Removing unreachable block (ram,0x801557e4) */
/* WARNING: Removing unreachable block (ram,0x801557dc) */
/* WARNING: Removing unreachable block (ram,0x801557d4) */
/* WARNING: Removing unreachable block (ram,0x80155490) */
/* WARNING: Removing unreachable block (ram,0x80155488) */
/* WARNING: Removing unreachable block (ram,0x80155480) */
/* WARNING: Removing unreachable block (ram,0x80155478) */
/* WARNING: Removing unreachable block (ram,0x80155470) */

uint FUN_80155460(double param_1,short *param_2,int param_3,uint param_4)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
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
  float afStack_d8 [3];
  float local_cc [2];
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float afStack_b4 [3];
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float afStack_90 [4];
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  longlong local_70;
  
  local_c0 = *(float *)(param_3 + 0x360);
  local_bc = *(float *)(param_3 + 0x358);
  local_b8 = *(float *)(param_3 + 0x364);
  FUN_80247eb8(&local_c0,(float *)(param_2 + 6),afStack_b4);
  dVar4 = FUN_80247f90(afStack_b4,(float *)(param_3 + 0x344));
  local_c0 = (float)((double)*(float *)(param_3 + 0x344) * dVar4 + (double)*(float *)(param_2 + 6));
  dVar8 = (double)*(float *)(param_2 + 8);
  local_bc = (float)((double)*(float *)(param_3 + 0x348) * dVar4 + dVar8);
  local_b8 = (float)((double)*(float *)(param_3 + 0x34c) * dVar4 + (double)*(float *)(param_2 + 10))
  ;
  local_fc = FLOAT_803e3698;
  local_f8 = FLOAT_803e369c;
  local_f4 = FLOAT_803e3698;
  FUN_80247fb0(&local_fc,(float *)(param_3 + 0x344),local_cc);
  FUN_80247ef8(local_cc,local_cc);
  if (FLOAT_803e3698 == local_cc[0]) {
    local_cc[0] = (*(float *)(param_2 + 10) - *(float *)(param_3 + 0x364)) / local_c4;
  }
  else {
    local_cc[0] = (*(float *)(param_2 + 6) - *(float *)(param_3 + 0x360)) / local_cc[0];
  }
  dVar6 = (double)local_cc[0];
  iVar2 = *(int *)(param_3 + 0x29c);
  local_a8 = *(float *)(iVar2 + 0xc);
  local_a4 = FLOAT_803e36a0 + *(float *)(iVar2 + 0x10);
  local_a0 = *(float *)(iVar2 + 0x14);
  local_e4 = *(float *)(param_3 + 0x360);
  local_e0 = *(float *)(param_3 + 0x358);
  local_dc = *(float *)(param_3 + 0x364);
  FUN_80247eb8(&local_e4,&local_a8,afStack_d8);
  dVar4 = FUN_80247f90(afStack_d8,(float *)(param_3 + 0x344));
  local_e4 = (float)((double)*(float *)(param_3 + 0x344) * dVar4 + (double)local_a8);
  dVar7 = (double)local_a4;
  local_e0 = (float)((double)*(float *)(param_3 + 0x348) * dVar4 + dVar7);
  local_dc = (float)((double)*(float *)(param_3 + 0x34c) * dVar4 + (double)local_a0);
  local_108 = FLOAT_803e3698;
  local_104 = FLOAT_803e369c;
  local_100 = FLOAT_803e3698;
  FUN_80247fb0(&local_108,(float *)(param_3 + 0x344),local_f0);
  FUN_80247ef8(local_f0,local_f0);
  if (FLOAT_803e3698 == local_f0[0]) {
    local_f0[0] = (local_a0 - *(float *)(param_3 + 0x364)) / local_e8;
  }
  else {
    local_f0[0] = (local_a8 - *(float *)(param_3 + 0x360)) / local_f0[0];
  }
  dVar4 = (double)(float)(dVar6 - (double)local_f0[0]);
  dVar7 = (double)(float)(dVar8 - dVar7);
  uVar3 = FUN_80021884();
  uStack_74 = (uVar3 & 0xffff) - (uint)(ushort)param_2[1];
  if (0x8000 < (int)uStack_74) {
    uStack_74 = uStack_74 - 0xffff;
  }
  if ((int)uStack_74 < -0x8000) {
    uStack_74 = uStack_74 + 0xffff;
  }
  uStack_7c = param_4 & 0xffff;
  local_80 = 0x43300000;
  fVar1 = FLOAT_803dc074 / (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e36a8);
  if (FLOAT_803e369c < fVar1) {
    fVar1 = FLOAT_803e369c;
  }
  uStack_74 = uStack_74 ^ 0x80000000;
  local_78 = 0x43300000;
  uVar3 = (uint)((float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e36b0) * fVar1);
  local_70 = (longlong)(int)uVar3;
  *param_2 = param_2[1] + (short)uVar3;
  param_2[2] = 0x4000;
  param_2[1] = *param_2;
  iVar2 = FUN_80021884();
  *param_2 = (short)iVar2;
  dVar5 = FUN_80293900((double)(float)(dVar4 * dVar4 + (double)(float)(dVar7 * dVar7)));
  if (param_1 < dVar5) {
    dVar4 = (double)(float)(param_1 *
                           (double)(float)(dVar4 * (double)(float)((double)FLOAT_803e369c / dVar5)))
    ;
    dVar7 = (double)(float)(param_1 *
                           (double)(float)(dVar7 * (double)(float)((double)FLOAT_803e369c / dVar5)))
    ;
  }
  FUN_80155818((double)(float)(dVar6 - dVar4),(double)(float)(dVar8 - dVar7),afStack_90,
               (float *)(param_3 + 0x344));
  FUN_80247eb8(afStack_90,(float *)(param_2 + 6),&local_9c);
  FUN_8002ba34((double)local_9c,(double)local_98,(double)local_94,(int)param_2);
  fVar1 = FLOAT_803e3698;
  *(float *)(param_2 + 0x12) = FLOAT_803e3698;
  *(float *)(param_2 + 0x14) = fVar1;
  *(float *)(param_2 + 0x16) = fVar1;
  if ((int)uVar3 < 0) {
    uVar3 = -uVar3;
  }
  return uVar3 & 0xffff;
}

