// Function: FUN_800313a8
// Entry: 800313a8
// Size: 1196 bytes

/* WARNING: Removing unreachable block (ram,0x8003182c) */
/* WARNING: Removing unreachable block (ram,0x8003181c) */
/* WARNING: Removing unreachable block (ram,0x80031824) */
/* WARNING: Removing unreachable block (ram,0x80031834) */

void FUN_800313a8(undefined8 param_1,undefined8 param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,int param_7,undefined4 param_8,int param_9,
                 float *param_10)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  float *pfVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 extraout_f1;
  double dVar7;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar8;
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
  undefined auStack168 [12];
  float local_9c;
  float local_98;
  float local_94;
  undefined auStack144 [36];
  float local_6c;
  float local_68;
  float local_64;
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
  uVar9 = FUN_802860d0();
  pfVar3 = (float *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  local_cc = *(float *)(iVar5 + 0xc) - *(float *)(iVar5 + 0x80);
  local_c8 = *(float *)(iVar5 + 0x10) - *(float *)(iVar5 + 0x84);
  local_c4 = *(float *)(iVar5 + 0x14) - *(float *)(iVar5 + 0x88);
  uVar9 = extraout_f1;
  dVar7 = (double)FUN_80022908(&local_cc);
  local_d8 = *pfVar3 - local_cc;
  local_d4 = pfVar3[1] - local_c8;
  local_d0 = pfVar3[2] - local_c4;
  local_6c = FLOAT_803de910;
  local_68 = FLOAT_803de910;
  local_64 = FLOAT_803de910;
  local_b4 = FLOAT_803de910;
  local_b0 = FLOAT_803de910;
  local_ac = FLOAT_803de910;
  iVar5 = *(int *)(param_9 + 0x40) * 4;
  FUN_80031e2c((double)*(float *)(param_9 + 0x2c),(double)*(float *)(*(int *)(param_7 + 4) + iVar5),
               (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(param_9 + 0x44) * 4),
               (double)*(float *)(*(int *)(param_7 + 0xc) + iVar5),&local_d8,param_9 + 8,
               param_9 + 0x14,auStack168);
  FUN_8002282c();
  dVar8 = (double)FLOAT_803de910;
  for (iVar5 = param_6; *(int *)(iVar5 + 0x40) != -1; iVar5 = iVar5 + 0x48) {
    iVar2 = *(int *)(iVar5 + 0x40) * 4;
    pfVar4 = (float *)FUN_80031b30(uVar9,(double)*(float *)(iVar5 + 0x2c),
                                   (double)*(float *)(*(int *)(param_7 + 4) + iVar2),
                                   (double)*(float *)(*(int *)(param_7 + 4) +
                                                     *(int *)(iVar5 + 0x44) * 4),
                                   (double)*(float *)(*(int *)(param_7 + 0xc) + iVar2),&local_d8,
                                   iVar5 + 8,iVar5 + 0x14,auStack144);
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
    pfVar4 = (float *)FUN_80031e2c((double)*(float *)(iVar5 + 0x2c),
                                   (double)*(float *)(*(int *)(param_7 + 4) + iVar2),
                                   (double)*(float *)(*(int *)(param_7 + 4) +
                                                     *(int *)(iVar5 + 0x44) * 4),
                                   (double)*(float *)(*(int *)(param_7 + 0xc) + iVar2),pfVar3,
                                   iVar5 + 8,iVar5 + 0x14,auStack168);
    FUN_8002282c();
    local_b4 = local_b4 + *pfVar4;
    local_b0 = local_b0 + pfVar4[1];
    local_ac = local_ac + pfVar4[2];
  }
  FUN_8002282c(&local_b4);
  local_c0 = local_6c - local_d8;
  local_bc = local_68 - local_d4;
  local_b8 = local_64 - local_d0;
  dVar8 = (double)FUN_80022908(&local_c0);
  local_c0 = local_6c - *pfVar3;
  local_bc = local_68 - pfVar3[1];
  local_b8 = local_64 - pfVar3[2];
  FUN_8002282c(&local_cc);
  if (dVar7 <= dVar8) {
    local_9c = FLOAT_803de910;
    local_98 = FLOAT_803de910;
    local_94 = FLOAT_803de910;
  }
  else {
    fVar1 = (float)(dVar7 - dVar8);
    local_cc = local_cc * fVar1;
    local_c8 = local_c8 * fVar1;
    local_c4 = local_c4 * fVar1;
    FUN_8002273c(&local_b4,&local_cc,&local_9c);
  }
  local_6c = local_6c + local_9c;
  local_68 = local_68 + local_98;
  local_64 = local_64 + local_94;
  local_9c = FLOAT_803de910;
  local_98 = FLOAT_803de910;
  local_94 = FLOAT_803de910;
  for (; *(int *)(param_6 + 0x40) != -1; param_6 = param_6 + 0x48) {
    iVar5 = *(int *)(param_6 + 0x40) * 4;
    pfVar4 = (float *)FUN_80031b30(uVar9,(double)*(float *)(param_6 + 0x2c),
                                   (double)*(float *)(*(int *)(param_7 + 4) + iVar5),
                                   (double)*(float *)(*(int *)(param_7 + 4) +
                                                     *(int *)(param_6 + 0x44) * 4),
                                   (double)*(float *)(*(int *)(param_7 + 0xc) + iVar5),&local_6c,
                                   param_6 + 8,param_6 + 0x14,auStack144);
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
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  __psq_l0(auStack56,uVar6);
  __psq_l1(auStack56,uVar6);
  FUN_8028611c(1);
  return;
}

