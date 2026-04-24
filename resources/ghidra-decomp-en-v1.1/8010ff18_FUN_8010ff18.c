// Function: FUN_8010ff18
// Entry: 8010ff18
// Size: 1084 bytes

/* WARNING: Removing unreachable block (ram,0x80110334) */
/* WARNING: Removing unreachable block (ram,0x8011032c) */
/* WARNING: Removing unreachable block (ram,0x80110324) */
/* WARNING: Removing unreachable block (ram,0x8011031c) */
/* WARNING: Removing unreachable block (ram,0x80110314) */
/* WARNING: Removing unreachable block (ram,0x8011030c) */
/* WARNING: Removing unreachable block (ram,0x8010ff50) */
/* WARNING: Removing unreachable block (ram,0x8010ff48) */
/* WARNING: Removing unreachable block (ram,0x8010ff40) */
/* WARNING: Removing unreachable block (ram,0x8010ff38) */
/* WARNING: Removing unreachable block (ram,0x8010ff30) */
/* WARNING: Removing unreachable block (ram,0x8010ff28) */

void FUN_8010ff18(short *param_1)

{
  int iVar1;
  short *psVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  short local_d6;
  short local_d4 [2];
  float local_d0;
  float local_cc;
  float local_c8;
  undefined4 local_c0;
  uint uStack_bc;
  undefined4 local_b8;
  uint uStack_b4;
  undefined4 local_b0;
  uint uStack_ac;
  longlong local_a8;
  undefined4 local_a0;
  uint uStack_9c;
  undefined4 local_98;
  uint uStack_94;
  longlong local_90;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  
  psVar2 = *(short **)(param_1 + 0x52);
  uStack_bc = 0x8000U - (int)*param_1 ^ 0x80000000;
  local_c0 = 0x43300000;
  dVar3 = (double)FUN_802945e0();
  dVar4 = (double)FUN_80294964();
  dVar10 = (double)*(float *)(psVar2 + 0xc);
  local_d0 = (float)(dVar3 * (double)FLOAT_803dc628 + dVar10);
  local_cc = FLOAT_803e2788 + *(float *)(psVar2 + 0xe);
  dVar3 = (double)*(float *)(psVar2 + 0x10);
  local_c8 = (float)(dVar4 * (double)FLOAT_803dc628 + dVar3);
  FUN_80103900(&local_d0,(int)psVar2,&local_d0);
  dVar3 = FUN_80293900((double)((float)((double)local_d0 - dVar10) *
                                (float)((double)local_d0 - dVar10) +
                               (float)((double)local_c8 - dVar3) * (float)((double)local_c8 - dVar3)
                               ));
  FLOAT_803de228 = (float)dVar3;
  FLOAT_803de220 = (float)dVar3;
  FUN_802970dc((int)psVar2,local_d4,&local_d6);
  local_d6 = local_d6 >> 1;
  dVar10 = (double)*(float *)(psVar2 + 0xc);
  dVar4 = (double)(*(float *)(psVar2 + 0xe) + FLOAT_803de224);
  dVar3 = (double)*(float *)(psVar2 + 0x10);
  local_d4[0] = ((-0x8000 - *psVar2) + (local_d4[0] >> 1)) - *param_1;
  if (0x8000 < local_d4[0]) {
    local_d4[0] = local_d4[0] + 1;
  }
  if (local_d4[0] < -0x8000) {
    local_d4[0] = local_d4[0] + -1;
  }
  uStack_b4 = (int)local_d4[0] ^ 0x80000000;
  local_b8 = 0x43300000;
  dVar5 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e2790),
                       (double)FLOAT_803e2798,(double)FLOAT_803dc074);
  uStack_ac = (int)*param_1 ^ 0x80000000;
  local_b0 = 0x43300000;
  iVar1 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_ac) - DOUBLE_803e2790) + dVar5);
  local_a8 = (longlong)iVar1;
  *param_1 = (short)iVar1;
  local_d6 = local_d6 - param_1[1];
  if (0x8000 < local_d6) {
    local_d6 = local_d6 + 1;
  }
  if (local_d6 < -0x8000) {
    local_d6 = local_d6 + -1;
  }
  uStack_9c = (int)local_d6 ^ 0x80000000;
  local_a0 = 0x43300000;
  dVar5 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803e2790),
                       (double)FLOAT_803e2798,(double)FLOAT_803dc074);
  uStack_94 = (int)param_1[1] ^ 0x80000000;
  local_98 = 0x43300000;
  iVar1 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e2790) + dVar5);
  local_90 = (longlong)iVar1;
  param_1[1] = (short)iVar1;
  uStack_84 = (int)*param_1 - 0x4000U ^ 0x80000000;
  local_88 = 0x43300000;
  dVar6 = (double)FUN_802945e0();
  uStack_7c = (int)*param_1 - 0x4000U ^ 0x80000000;
  local_80 = 0x43300000;
  dVar7 = (double)FUN_80294964();
  uStack_74 = (int)param_1[1] ^ 0x80000000;
  local_78 = 0x43300000;
  dVar8 = (double)FUN_80294964();
  uStack_6c = (int)param_1[1] ^ 0x80000000;
  local_70 = 0x43300000;
  dVar9 = (double)FUN_802945e0();
  dVar5 = (double)FLOAT_803de220;
  dVar8 = (double)(float)(dVar5 * dVar8);
  *(float *)(param_1 + 0xc) = (float)(dVar10 + (double)(float)(dVar8 * dVar7));
  *(float *)(param_1 + 0xe) = (float)(dVar4 + (double)(float)(dVar5 * dVar9));
  *(float *)(param_1 + 0x10) = (float)(dVar3 + (double)(float)(dVar8 * dVar6));
  FUN_80103900((float *)(param_1 + 0xc),(int)psVar2,(float *)(param_1 + 0xc));
  FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
}

