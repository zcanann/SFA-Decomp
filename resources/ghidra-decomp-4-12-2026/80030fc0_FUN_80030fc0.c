// Function: FUN_80030fc0
// Entry: 80030fc0
// Size: 1248 bytes

/* WARNING: Removing unreachable block (ram,0x80031480) */
/* WARNING: Removing unreachable block (ram,0x80031478) */
/* WARNING: Removing unreachable block (ram,0x80031470) */
/* WARNING: Removing unreachable block (ram,0x80031468) */
/* WARNING: Removing unreachable block (ram,0x80031460) */
/* WARNING: Removing unreachable block (ram,0x80030ff0) */
/* WARNING: Removing unreachable block (ram,0x80030fe8) */
/* WARNING: Removing unreachable block (ram,0x80030fe0) */
/* WARNING: Removing unreachable block (ram,0x80030fd8) */
/* WARNING: Removing unreachable block (ram,0x80030fd0) */

void FUN_80030fc0(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,int param_7,undefined4 param_8,int param_9,
                 float *param_10)

{
  int iVar1;
  float fVar2;
  float *pfVar3;
  float *pfVar4;
  int iVar5;
  double extraout_f1;
  double dVar6;
  double in_f27;
  double dVar7;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar8;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float afStack_b8 [3];
  float local_ac;
  float local_a8;
  float local_a4;
  float afStack_a0 [9];
  float local_7c;
  float local_78;
  float local_74;
  float local_48;
  float fStack_44;
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
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  uVar9 = FUN_80286834();
  pfVar3 = (float *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  local_dc = *(float *)(iVar5 + 0x18) - *(float *)(iVar5 + 0x8c);
  local_d8 = *(float *)(iVar5 + 0x10) - *(float *)(iVar5 + 0x90);
  local_d4 = *(float *)(iVar5 + 0x20) - *(float *)(iVar5 + 0x94);
  dVar7 = extraout_f1;
  dVar6 = (double)FUN_800229cc(&local_dc);
  local_dc = (float)((double)local_dc * param_2);
  local_d8 = (float)((double)local_d8 * param_2);
  local_d4 = (float)((double)local_d4 * param_2);
  local_e8 = *pfVar3 - local_dc;
  local_e4 = pfVar3[1] - local_d8;
  local_e0 = pfVar3[2] - local_d4;
  local_7c = FLOAT_803df590;
  local_78 = FLOAT_803df590;
  local_74 = FLOAT_803df590;
  local_c4 = FLOAT_803df590;
  local_c0 = FLOAT_803df590;
  local_bc = FLOAT_803df590;
  iVar5 = *(int *)(param_9 + 0x40) * 4;
  pfVar4 = FUN_80031f24((double)*(float *)(param_9 + 0x2c),
                        (double)*(float *)(*(int *)(param_7 + 4) + iVar5),
                        (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(param_9 + 0x44) * 4),
                        (double)*(float *)(*(int *)(param_7 + 0xc) + iVar5),&local_e8,
                        (float *)(param_9 + 8),(float *)(param_9 + 0x14),afStack_b8);
  FUN_800228f0(pfVar4);
  dVar8 = (double)FLOAT_803df590;
  for (iVar5 = param_6; *(int *)(iVar5 + 0x40) != -1; iVar5 = iVar5 + 0x48) {
    iVar1 = *(int *)(iVar5 + 0x40) * 4;
    pfVar4 = FUN_8003194c(dVar7,(double)*(float *)(iVar5 + 0x2c),
                          (double)*(float *)(*(int *)(param_7 + 4) + iVar1),
                          (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(iVar5 + 0x44) * 4),
                          (double)*(float *)(*(int *)(param_7 + 0xc) + iVar1),&local_e8,
                          (float *)(iVar5 + 8),(float *)(iVar5 + 0x14),afStack_a0);
    if (param_3 <= dVar8) {
      *(float *)(iVar5 + 0x3c) = (float)dVar8;
    }
    else {
      *(float *)(iVar5 + 0x3c) = (float)((double)*(float *)(iVar5 + 0x3c) / param_3);
    }
    *pfVar4 = *pfVar4 * *(float *)(iVar5 + 0x3c);
    pfVar4[1] = pfVar4[1] * *(float *)(iVar5 + 0x3c);
    pfVar4[2] = pfVar4[2] * *(float *)(iVar5 + 0x3c);
    local_7c = local_7c + *pfVar4;
    local_78 = local_78 + pfVar4[1];
    local_74 = local_74 + pfVar4[2];
    iVar1 = *(int *)(iVar5 + 0x40) * 4;
    pfVar4 = FUN_80031f24((double)*(float *)(iVar5 + 0x2c),
                          (double)*(float *)(*(int *)(param_7 + 4) + iVar1),
                          (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(iVar5 + 0x44) * 4),
                          (double)*(float *)(*(int *)(param_7 + 0xc) + iVar1),pfVar3,
                          (float *)(iVar5 + 8),(float *)(iVar5 + 0x14),afStack_b8);
    FUN_800228f0(pfVar4);
    local_c4 = local_c4 + *pfVar4;
    local_c0 = local_c0 + pfVar4[1];
    local_bc = local_bc + pfVar4[2];
  }
  FUN_800228f0(&local_c4);
  local_d0 = local_7c - local_e8;
  local_cc = FLOAT_803df590;
  local_c8 = local_74 - local_e0;
  dVar8 = (double)FUN_800229cc(&local_d0);
  local_d0 = local_7c - *pfVar3;
  local_cc = FLOAT_803df590;
  local_c8 = local_74 - pfVar3[2];
  FUN_800228f0(&local_dc);
  if (dVar6 <= dVar8) {
    local_ac = FLOAT_803df590;
    local_a8 = FLOAT_803df590;
    local_a4 = FLOAT_803df590;
  }
  else {
    fVar2 = (float)(DOUBLE_803df5a8 +
                   (double)((float)((double)FLOAT_803df598 - param_2) * FLOAT_803df5b0)) *
            (float)(dVar6 - dVar8);
    local_dc = local_dc * fVar2;
    local_d8 = local_d8 * fVar2;
    local_d4 = local_d4 * fVar2;
    FUN_80022800(&local_c4,&local_dc,&local_ac);
  }
  local_7c = local_7c + local_ac;
  local_78 = local_78 + local_a8;
  local_74 = local_74 + local_a4;
  local_ac = FLOAT_803df590;
  local_a8 = FLOAT_803df590;
  local_a4 = FLOAT_803df590;
  for (; *(int *)(param_6 + 0x40) != -1; param_6 = param_6 + 0x48) {
    iVar5 = *(int *)(param_6 + 0x40) * 4;
    pfVar4 = FUN_8003194c(dVar7,(double)*(float *)(param_6 + 0x2c),
                          (double)*(float *)(*(int *)(param_7 + 4) + iVar5),
                          (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(param_6 + 0x44) * 4),
                          (double)*(float *)(*(int *)(param_7 + 0xc) + iVar5),&local_7c,
                          (float *)(param_6 + 8),(float *)(param_6 + 0x14),afStack_a0);
    *pfVar4 = *pfVar4 * *(float *)(param_6 + 0x3c);
    pfVar4[1] = pfVar4[1] * *(float *)(param_6 + 0x3c);
    pfVar4[2] = pfVar4[2] * *(float *)(param_6 + 0x3c);
    local_ac = local_ac + *pfVar4;
    local_a8 = local_a8 + pfVar4[1];
    local_a4 = local_a4 + pfVar4[2];
  }
  *param_10 = local_ac - *pfVar3;
  param_10[1] = FLOAT_803df590;
  param_10[2] = local_a4 - pfVar3[2];
  FUN_80286880();
  return;
}

