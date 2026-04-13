// Function: FUN_800314a0
// Entry: 800314a0
// Size: 1196 bytes

/* WARNING: Removing unreachable block (ram,0x8003192c) */
/* WARNING: Removing unreachable block (ram,0x80031924) */
/* WARNING: Removing unreachable block (ram,0x8003191c) */
/* WARNING: Removing unreachable block (ram,0x80031914) */
/* WARNING: Removing unreachable block (ram,0x800314c8) */
/* WARNING: Removing unreachable block (ram,0x800314c0) */
/* WARNING: Removing unreachable block (ram,0x800314b8) */
/* WARNING: Removing unreachable block (ram,0x800314b0) */

void FUN_800314a0(undefined8 param_1,undefined8 param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,int param_7,undefined4 param_8,int param_9,
                 float *param_10)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  float *pfVar4;
  int iVar5;
  double extraout_f1;
  double dVar6;
  double in_f28;
  double dVar7;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar8;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float afStack_a8 [3];
  float local_9c;
  float local_98;
  float local_94;
  float afStack_90 [9];
  float local_6c;
  float local_68;
  float local_64;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar9 = FUN_80286834();
  pfVar3 = (float *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  local_cc = *(float *)(iVar5 + 0xc) - *(float *)(iVar5 + 0x80);
  local_c8 = *(float *)(iVar5 + 0x10) - *(float *)(iVar5 + 0x84);
  local_c4 = *(float *)(iVar5 + 0x14) - *(float *)(iVar5 + 0x88);
  dVar7 = extraout_f1;
  dVar6 = (double)FUN_800229cc(&local_cc);
  local_d8 = *pfVar3 - local_cc;
  local_d4 = pfVar3[1] - local_c8;
  local_d0 = pfVar3[2] - local_c4;
  local_6c = FLOAT_803df590;
  local_68 = FLOAT_803df590;
  local_64 = FLOAT_803df590;
  local_b4 = FLOAT_803df590;
  local_b0 = FLOAT_803df590;
  local_ac = FLOAT_803df590;
  iVar5 = *(int *)(param_9 + 0x40) * 4;
  pfVar4 = FUN_80031f24((double)*(float *)(param_9 + 0x2c),
                        (double)*(float *)(*(int *)(param_7 + 4) + iVar5),
                        (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(param_9 + 0x44) * 4),
                        (double)*(float *)(*(int *)(param_7 + 0xc) + iVar5),&local_d8,
                        (float *)(param_9 + 8),(float *)(param_9 + 0x14),afStack_a8);
  FUN_800228f0(pfVar4);
  dVar8 = (double)FLOAT_803df590;
  for (iVar5 = param_6; *(int *)(iVar5 + 0x40) != -1; iVar5 = iVar5 + 0x48) {
    iVar2 = *(int *)(iVar5 + 0x40) * 4;
    pfVar4 = FUN_80031c28(dVar7,(double)*(float *)(iVar5 + 0x2c),
                          (double)*(float *)(*(int *)(param_7 + 4) + iVar2),
                          (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(iVar5 + 0x44) * 4),
                          (double)*(float *)(*(int *)(param_7 + 0xc) + iVar2),&local_d8,
                          (float *)(iVar5 + 8),(float *)(iVar5 + 0x14),afStack_90);
    if (param_3 <= dVar8) {
      *(float *)(iVar5 + 0x3c) = (float)dVar8;
    }
    else {
      *(float *)(iVar5 + 0x3c) = (float)((double)*(float *)(iVar5 + 0x3c) / param_3);
    }
    *pfVar4 = *pfVar4 * *(float *)(iVar5 + 0x3c);
    pfVar4[1] = pfVar4[1] * *(float *)(iVar5 + 0x3c);
    pfVar4[2] = pfVar4[2] * *(float *)(iVar5 + 0x3c);
    local_6c = local_6c + *pfVar4;
    local_68 = local_68 + pfVar4[1];
    local_64 = local_64 + pfVar4[2];
    iVar2 = *(int *)(iVar5 + 0x40) * 4;
    pfVar4 = FUN_80031f24((double)*(float *)(iVar5 + 0x2c),
                          (double)*(float *)(*(int *)(param_7 + 4) + iVar2),
                          (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(iVar5 + 0x44) * 4),
                          (double)*(float *)(*(int *)(param_7 + 0xc) + iVar2),pfVar3,
                          (float *)(iVar5 + 8),(float *)(iVar5 + 0x14),afStack_a8);
    FUN_800228f0(pfVar4);
    local_b4 = local_b4 + *pfVar4;
    local_b0 = local_b0 + pfVar4[1];
    local_ac = local_ac + pfVar4[2];
  }
  FUN_800228f0(&local_b4);
  local_c0 = local_6c - local_d8;
  local_bc = local_68 - local_d4;
  local_b8 = local_64 - local_d0;
  dVar8 = (double)FUN_800229cc(&local_c0);
  local_c0 = local_6c - *pfVar3;
  local_bc = local_68 - pfVar3[1];
  local_b8 = local_64 - pfVar3[2];
  FUN_800228f0(&local_cc);
  if (dVar6 <= dVar8) {
    local_9c = FLOAT_803df590;
    local_98 = FLOAT_803df590;
    local_94 = FLOAT_803df590;
  }
  else {
    fVar1 = (float)(dVar6 - dVar8);
    local_cc = local_cc * fVar1;
    local_c8 = local_c8 * fVar1;
    local_c4 = local_c4 * fVar1;
    FUN_80022800(&local_b4,&local_cc,&local_9c);
  }
  local_6c = local_6c + local_9c;
  local_68 = local_68 + local_98;
  local_64 = local_64 + local_94;
  local_9c = FLOAT_803df590;
  local_98 = FLOAT_803df590;
  local_94 = FLOAT_803df590;
  for (; *(int *)(param_6 + 0x40) != -1; param_6 = param_6 + 0x48) {
    iVar5 = *(int *)(param_6 + 0x40) * 4;
    pfVar4 = FUN_80031c28(dVar7,(double)*(float *)(param_6 + 0x2c),
                          (double)*(float *)(*(int *)(param_7 + 4) + iVar5),
                          (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(param_6 + 0x44) * 4),
                          (double)*(float *)(*(int *)(param_7 + 0xc) + iVar5),&local_6c,
                          (float *)(param_6 + 8),(float *)(param_6 + 0x14),afStack_90);
    *pfVar4 = *pfVar4 * *(float *)(param_6 + 0x3c);
    pfVar4[1] = pfVar4[1] * *(float *)(param_6 + 0x3c);
    pfVar4[2] = pfVar4[2] * *(float *)(param_6 + 0x3c);
    local_9c = local_9c + *pfVar4;
    local_98 = local_98 + pfVar4[1];
    local_94 = local_94 + pfVar4[2];
  }
  *param_10 = local_9c - *pfVar3;
  param_10[1] = local_98 - pfVar3[1];
  param_10[2] = local_94 - pfVar3[2];
  FUN_80286880();
  return;
}

