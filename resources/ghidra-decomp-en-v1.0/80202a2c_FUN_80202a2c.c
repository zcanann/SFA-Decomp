// Function: FUN_80202a2c
// Entry: 80202a2c
// Size: 588 bytes

/* WARNING: Removing unreachable block (ram,0x80202c50) */
/* WARNING: Removing unreachable block (ram,0x80202c40) */
/* WARNING: Removing unreachable block (ram,0x80202c48) */
/* WARNING: Removing unreachable block (ram,0x80202c58) */

void FUN_80202a2c(undefined4 param_1,undefined4 param_2,float *param_3,int param_4)

{
  float fVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 uVar7;
  double dVar8;
  double extraout_f1;
  double dVar9;
  undefined8 in_f28;
  double dVar10;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar13 = FUN_802860d8();
  psVar2 = (short *)((ulonglong)uVar13 >> 0x20);
  puVar6 = (undefined4 *)uVar13;
  iVar5 = *(int *)(psVar2 + 0x5c);
  dVar11 = (double)FLOAT_803e62a8;
  dVar12 = (double)FLOAT_803e635c;
  dVar10 = extraout_f1;
  dVar8 = dVar11;
  for (iVar4 = 0; iVar4 < param_4; iVar4 = iVar4 + 1) {
    local_78 = (float)dVar12;
    iVar3 = FUN_80036d60(*puVar6,psVar2,&local_78);
    if (iVar3 != 0) {
      if (local_78 == FLOAT_803e62a8) goto LAB_80202c40;
      fVar1 = FLOAT_803e62c8 - local_78 / FLOAT_803e635c;
      fVar1 = fVar1 * fVar1;
      fVar1 = fVar1 * fVar1;
      local_6c = FLOAT_803e62c8 / local_78;
      local_74 = (*(float *)(iVar3 + 0xc) - *(float *)(psVar2 + 6)) * local_6c;
      local_70 = (*(float *)(iVar3 + 0x10) - *(float *)(psVar2 + 8)) * local_6c;
      local_6c = (*(float *)(iVar3 + 0x14) - *(float *)(psVar2 + 10)) * local_6c;
      dVar8 = -(double)(float)(dVar10 * (double)(local_74 * fVar1 * *param_3) - dVar8);
      dVar11 = -(double)(float)(dVar10 * (double)(local_6c * fVar1 * *param_3) - dVar11);
    }
    puVar6 = puVar6 + 1;
    param_3 = param_3 + 1;
  }
  uStack100 = (int)*psVar2 ^ 0x80000000;
  local_68 = 0x43300000;
  dVar12 = (double)FUN_80293e80((double)((FLOAT_803e6360 *
                                         (float)((double)CONCAT44(0x43300000,uStack100) -
                                                DOUBLE_803e6368)) / FLOAT_803e6364));
  uStack92 = (int)*psVar2 ^ 0x80000000;
  local_60 = 0x43300000;
  dVar9 = (double)FUN_80294204((double)((FLOAT_803e6360 *
                                        (float)((double)CONCAT44(0x43300000,uStack92) -
                                               DOUBLE_803e6368)) / FLOAT_803e6364));
  *(float *)(iVar5 + 0x284) =
       *(float *)(iVar5 + 0x284) + (float)(dVar8 * dVar9 - (double)(float)(dVar11 * dVar12));
  *(float *)(iVar5 + 0x280) =
       *(float *)(iVar5 + 0x280) + (float)(-dVar11 * dVar9 - (double)(float)(dVar8 * dVar12));
  dVar12 = (double)*(float *)(iVar5 + 0x280);
  dVar8 = -dVar10;
  dVar11 = dVar8;
  if ((dVar8 <= dVar12) && (dVar11 = dVar12, dVar10 < dVar12)) {
    dVar11 = dVar10;
  }
  *(float *)(iVar5 + 0x280) = (float)dVar11;
  dVar11 = (double)*(float *)(iVar5 + 0x284);
  if ((dVar8 <= dVar11) && (dVar8 = dVar11, dVar10 < dVar11)) {
    dVar8 = dVar10;
  }
  *(float *)(iVar5 + 0x284) = (float)dVar8;
LAB_80202c40:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  __psq_l0(auStack56,uVar7);
  __psq_l1(auStack56,uVar7);
  FUN_80286124(0);
  return;
}

