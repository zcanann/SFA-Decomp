// Function: FUN_8001cdac
// Entry: 8001cdac
// Size: 716 bytes

/* WARNING: Removing unreachable block (ram,0x8001d048) */
/* WARNING: Removing unreachable block (ram,0x8001d050) */

undefined4 FUN_8001cdac(int param_1,int param_2)

{
  float *pfVar1;
  float fVar2;
  undefined4 uVar3;
  uint uVar4;
  float *pfVar5;
  float *pfVar6;
  uint uVar7;
  int iVar8;
  undefined4 uVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar12;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94 [25];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  dVar12 = (double)(*(float *)(param_2 + 8) * *(float *)(param_2 + 0xa8));
  pfVar6 = &local_98;
  pfVar5 = (float *)&DAT_802c1a84;
  iVar8 = 0xc;
  do {
    pfVar1 = pfVar5 + 1;
    pfVar5 = pfVar5 + 2;
    fVar2 = *pfVar5;
    pfVar6[1] = *pfVar1;
    pfVar6 = pfVar6 + 2;
    *pfVar6 = fVar2;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  local_b8 = *(float *)(param_2 + 0xc) - FLOAT_803dcdd8;
  local_b4 = *(float *)(param_2 + 0x10);
  local_b0 = *(float *)(param_2 + 0x14) - FLOAT_803dcddc;
  FUN_80247494(param_1 + 0x170,&local_b8,&local_a0);
  if (*(int *)(param_1 + 0x168) == 0) {
    dVar11 = (double)*(float *)(param_2 + 0xa8);
    if ((((*(float *)(param_1 + 0x15c) < (float)((double)local_a0 - dVar11)) ||
         ((float)((double)local_a0 + dVar12) < *(float *)(param_1 + 0x158))) ||
        (*(float *)(param_1 + 0x150) < (float)((double)local_9c - dVar11))) ||
       ((((float)((double)local_9c + dVar12) < *(float *)(param_1 + 0x154) ||
         (*(float *)(param_1 + 0x164) < (float)((double)local_98 - dVar11))) ||
        ((float)((double)local_98 + dVar12) < *(float *)(param_1 + 0x160))))) {
      uVar3 = 0;
    }
    else {
      uVar3 = 1;
    }
  }
  else if ((*(float *)(param_1 + 0x164) <
            (float)((double)local_98 - (double)*(float *)(param_2 + 0xa8))) ||
          ((float)((double)local_98 + dVar12) < *(float *)(param_1 + 0x160))) {
    uVar3 = 0;
  }
  else {
    uVar7 = 0x3f;
    iVar8 = 0;
    pfVar5 = local_94;
    dVar11 = (double)FLOAT_803de75c;
    do {
      local_b8 = (float)(dVar12 * (double)*pfVar5 + (double)local_a0);
      local_b4 = (float)(dVar12 * (double)pfVar5[1] + (double)local_9c);
      local_b0 = (float)(dVar12 * (double)pfVar5[2] + (double)local_98);
      FUN_80247494(param_1 + 0x1f0,&local_b8,&local_ac);
      dVar10 = (double)local_a4;
      if (dVar11 != dVar10) {
        local_ac = (float)((double)local_ac / dVar10);
        local_a8 = (float)((double)local_a8 / dVar10);
      }
      uVar4 = 0;
      if (local_b0 < *(float *)(param_1 + 0x160)) {
        uVar4 = 0x10;
      }
      if (*(float *)(param_1 + 0x164) < local_b0) {
        uVar4 = uVar4 | 0x20;
      }
      if (dVar11 <= (double)local_ac) {
        if ((double)FLOAT_803de760 < (double)local_ac) {
          uVar4 = uVar4 | 2;
        }
      }
      else {
        uVar4 = uVar4 | 1;
      }
      if (dVar11 <= (double)local_a8) {
        if ((double)FLOAT_803de760 < (double)local_a8) {
          uVar4 = uVar4 | 8;
        }
      }
      else {
        uVar4 = uVar4 | 4;
      }
      if (uVar4 == 0) {
        uVar3 = 1;
        goto LAB_8001d048;
      }
      uVar7 = uVar7 & uVar4;
      if (uVar7 == 0) {
        uVar3 = 1;
        goto LAB_8001d048;
      }
      pfVar5 = pfVar5 + 3;
      iVar8 = iVar8 + 1;
    } while (iVar8 < 8);
    uVar3 = 0;
  }
LAB_8001d048:
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  return uVar3;
}

