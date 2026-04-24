// Function: FUN_80106d84
// Entry: 80106d84
// Size: 500 bytes

/* WARNING: Removing unreachable block (ram,0x80106f50) */
/* WARNING: Removing unreachable block (ram,0x80106f40) */
/* WARNING: Removing unreachable block (ram,0x80106f30) */
/* WARNING: Removing unreachable block (ram,0x80106f28) */
/* WARNING: Removing unreachable block (ram,0x80106f38) */
/* WARNING: Removing unreachable block (ram,0x80106f48) */
/* WARNING: Removing unreachable block (ram,0x80106f58) */

void FUN_80106d84(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined4 param_7,undefined4 param_8,int *param_9)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  undefined4 uVar7;
  double extraout_f1;
  undefined8 in_f25;
  double dVar8;
  undefined8 in_f26;
  double dVar9;
  undefined8 in_f27;
  double dVar10;
  undefined8 in_f28;
  double dVar11;
  undefined8 in_f29;
  double dVar12;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar13;
  ushort local_e8 [2];
  short local_e4;
  undefined2 local_e2;
  undefined2 local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  undefined auStack208 [2];
  short local_ce [19];
  undefined4 local_a8;
  uint uStack164;
  undefined4 local_a0;
  uint uStack156;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
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
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  uVar13 = FUN_802860d0();
  iVar2 = (int)((ulonglong)uVar13 >> 0x20);
  sVar1 = (short)((ulonglong)uVar13 >> 0x20);
  if (sVar1 < 0) {
    iVar2 = (int)-sVar1;
  }
  local_e8[0] = 0;
  dVar12 = extraout_f1;
  FUN_8010684c(auStack208,local_e8,0,iVar2,(int)uVar13);
  dVar10 = (double)(float)(param_3 - dVar12);
  dVar9 = (double)(float)(param_6 - param_4);
  dVar8 = (double)(float)(param_5 - param_2);
  iVar4 = 3;
  psVar6 = local_ce;
  iVar5 = 0xc;
  uVar3 = (int)(short)iVar2 ^ 0x80000000;
  dVar11 = DOUBLE_803e1750;
  for (iVar2 = 1; iVar2 < (int)(uint)local_e8[0]; iVar2 = iVar2 + 1) {
    local_dc = (float)dVar10;
    local_d8 = (float)dVar9;
    local_d4 = (float)dVar8;
    if (sVar1 < 0) {
      local_e4 = *psVar6;
    }
    else {
      local_e4 = -*psVar6;
    }
    local_e2 = 0;
    local_e0 = 0;
    FUN_80021ac8(&local_e4,&local_dc);
    *(float *)(DAT_803dd538 + iVar5 + 0x1c) = (float)(dVar12 + (double)local_dc);
    uStack164 = (int)*psVar6 ^ 0x80000000U;
    local_a8 = 0x43300000;
    uStack156 = uVar3;
    local_a0 = 0x43300000;
    *(float *)(DAT_803dd538 + iVar5 + 0x6c) =
         (float)(dVar9 * (double)((float)((double)CONCAT44(0x43300000,(int)*psVar6 ^ 0x80000000U) -
                                         dVar11) /
                                 (float)((double)CONCAT44(0x43300000,uVar3) - dVar11)) + param_4);
    *(float *)(DAT_803dd538 + iVar5 + 0xbc) = (float)(param_2 + (double)local_d4);
    psVar6 = psVar6 + 1;
    iVar5 = iVar5 + 4;
    iVar4 = iVar4 + 1;
  }
  *param_9 = iVar4;
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  __psq_l0(auStack56,uVar7);
  __psq_l1(auStack56,uVar7);
  __psq_l0(auStack72,uVar7);
  __psq_l1(auStack72,uVar7);
  __psq_l0(auStack88,uVar7);
  __psq_l1(auStack88,uVar7);
  __psq_l0(auStack104,uVar7);
  __psq_l1(auStack104,uVar7);
  FUN_8028611c();
  return;
}

