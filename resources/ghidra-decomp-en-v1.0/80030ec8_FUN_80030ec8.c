// Function: FUN_80030ec8
// Entry: 80030ec8
// Size: 1248 bytes

/* WARNING: Removing unreachable block (ram,0x80031380) */
/* WARNING: Removing unreachable block (ram,0x80031370) */
/* WARNING: Removing unreachable block (ram,0x80031368) */
/* WARNING: Removing unreachable block (ram,0x80031378) */
/* WARNING: Removing unreachable block (ram,0x80031388) */

void FUN_80030ec8(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,int param_7,undefined4 param_8,int param_9,
                 float *param_10)

{
  int iVar1;
  float fVar2;
  float *pfVar3;
  float *pfVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 extraout_f1;
  double dVar7;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar8;
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
  undefined auStack184 [12];
  float local_ac;
  float local_a8;
  float local_a4;
  undefined auStack160 [36];
  float local_7c;
  float local_78;
  float local_74;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
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
  uVar9 = FUN_802860d0();
  pfVar3 = (float *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  local_dc = *(float *)(iVar5 + 0x18) - *(float *)(iVar5 + 0x8c);
  local_d8 = *(float *)(iVar5 + 0x10) - *(float *)(iVar5 + 0x90);
  local_d4 = *(float *)(iVar5 + 0x20) - *(float *)(iVar5 + 0x94);
  uVar9 = extraout_f1;
  dVar7 = (double)FUN_80022908(&local_dc);
  local_dc = (float)((double)local_dc * param_2);
  local_d8 = (float)((double)local_d8 * param_2);
  local_d4 = (float)((double)local_d4 * param_2);
  local_e8 = *pfVar3 - local_dc;
  local_e4 = pfVar3[1] - local_d8;
  local_e0 = pfVar3[2] - local_d4;
  local_7c = FLOAT_803de910;
  local_78 = FLOAT_803de910;
  local_74 = FLOAT_803de910;
  local_c4 = FLOAT_803de910;
  local_c0 = FLOAT_803de910;
  local_bc = FLOAT_803de910;
  iVar5 = *(int *)(param_9 + 0x40) * 4;
  FUN_80031e2c((double)*(float *)(param_9 + 0x2c),(double)*(float *)(*(int *)(param_7 + 4) + iVar5),
               (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(param_9 + 0x44) * 4),
               (double)*(float *)(*(int *)(param_7 + 0xc) + iVar5),&local_e8,param_9 + 8,
               param_9 + 0x14,auStack184);
  FUN_8002282c();
  dVar8 = (double)FLOAT_803de910;
  for (iVar5 = param_6; *(int *)(iVar5 + 0x40) != -1; iVar5 = iVar5 + 0x48) {
    iVar1 = *(int *)(iVar5 + 0x40) * 4;
    pfVar4 = (float *)FUN_80031854(uVar9,(double)*(float *)(iVar5 + 0x2c),
                                   (double)*(float *)(*(int *)(param_7 + 4) + iVar1),
                                   (double)*(float *)(*(int *)(param_7 + 4) +
                                                     *(int *)(iVar5 + 0x44) * 4),
                                   (double)*(float *)(*(int *)(param_7 + 0xc) + iVar1),&local_e8,
                                   iVar5 + 8,iVar5 + 0x14,auStack160);
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
    pfVar4 = (float *)FUN_80031e2c((double)*(float *)(iVar5 + 0x2c),
                                   (double)*(float *)(*(int *)(param_7 + 4) + iVar1),
                                   (double)*(float *)(*(int *)(param_7 + 4) +
                                                     *(int *)(iVar5 + 0x44) * 4),
                                   (double)*(float *)(*(int *)(param_7 + 0xc) + iVar1),pfVar3,
                                   iVar5 + 8,iVar5 + 0x14,auStack184);
    FUN_8002282c();
    local_c4 = local_c4 + *pfVar4;
    local_c0 = local_c0 + pfVar4[1];
    local_bc = local_bc + pfVar4[2];
  }
  FUN_8002282c(&local_c4);
  local_d0 = local_7c - local_e8;
  local_cc = FLOAT_803de910;
  local_c8 = local_74 - local_e0;
  dVar8 = (double)FUN_80022908(&local_d0);
  local_d0 = local_7c - *pfVar3;
  local_cc = FLOAT_803de910;
  local_c8 = local_74 - pfVar3[2];
  FUN_8002282c(&local_dc);
  if (dVar7 <= dVar8) {
    local_ac = FLOAT_803de910;
    local_a8 = FLOAT_803de910;
    local_a4 = FLOAT_803de910;
  }
  else {
    fVar2 = (float)(DOUBLE_803de928 +
                   (double)((float)((double)FLOAT_803de918 - param_2) * FLOAT_803de930)) *
            (float)(dVar7 - dVar8);
    local_dc = local_dc * fVar2;
    local_d8 = local_d8 * fVar2;
    local_d4 = local_d4 * fVar2;
    FUN_8002273c(&local_c4,&local_dc,&local_ac);
  }
  local_7c = local_7c + local_ac;
  local_78 = local_78 + local_a8;
  local_74 = local_74 + local_a4;
  local_ac = FLOAT_803de910;
  local_a8 = FLOAT_803de910;
  local_a4 = FLOAT_803de910;
  for (; *(int *)(param_6 + 0x40) != -1; param_6 = param_6 + 0x48) {
    iVar5 = *(int *)(param_6 + 0x40) * 4;
    pfVar4 = (float *)FUN_80031854(uVar9,(double)*(float *)(param_6 + 0x2c),
                                   (double)*(float *)(*(int *)(param_7 + 4) + iVar5),
                                   (double)*(float *)(*(int *)(param_7 + 4) +
                                                     *(int *)(param_6 + 0x44) * 4),
                                   (double)*(float *)(*(int *)(param_7 + 0xc) + iVar5),&local_7c,
                                   param_6 + 8,param_6 + 0x14,auStack160);
    *pfVar4 = *pfVar4 * *(float *)(param_6 + 0x3c);
    pfVar4[1] = pfVar4[1] * *(float *)(param_6 + 0x3c);
    pfVar4[2] = pfVar4[2] * *(float *)(param_6 + 0x3c);
    local_ac = local_ac + *pfVar4;
    local_a8 = local_a8 + pfVar4[1];
    local_a4 = local_a4 + pfVar4[2];
  }
  *param_10 = local_ac - *pfVar3;
  param_10[1] = FLOAT_803de910;
  param_10[2] = local_a4 - pfVar3[2];
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  __psq_l0(auStack56,uVar6);
  __psq_l1(auStack56,uVar6);
  __psq_l0(auStack72,uVar6);
  __psq_l1(auStack72,uVar6);
  FUN_8028611c(1);
  return;
}

