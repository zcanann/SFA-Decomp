// Function: FUN_80113d64
// Entry: 80113d64
// Size: 544 bytes

/* WARNING: Removing unreachable block (ram,0x80113f5c) */
/* WARNING: Removing unreachable block (ram,0x80113f4c) */
/* WARNING: Removing unreachable block (ram,0x80113f3c) */
/* WARNING: Removing unreachable block (ram,0x80113f44) */
/* WARNING: Removing unreachable block (ram,0x80113f54) */
/* WARNING: Removing unreachable block (ram,0x80113f64) */

void FUN_80113d64(void)

{
  short sVar1;
  short *psVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  ushort uVar6;
  undefined4 uVar7;
  double extraout_f1;
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
  double dVar13;
  undefined8 in_f31;
  double dVar14;
  undefined8 uVar15;
  char local_100 [4];
  undefined auStack252 [8];
  undefined auStack244 [8];
  float local_ec;
  float local_e8;
  float local_e4;
  undefined auStack224 [88];
  undefined4 local_88;
  uint uStack132;
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
  uVar15 = FUN_802860d0();
  psVar2 = (short *)((ulonglong)uVar15 >> 0x20);
  uVar5 = 0;
  local_ec = *(float *)(psVar2 + 6);
  local_e8 = FLOAT_803e1c68 + *(float *)(psVar2 + 8);
  local_e4 = *(float *)(psVar2 + 10);
  dVar14 = extraout_f1;
  FUN_80012d00(&local_ec,auStack252);
  if (*(short **)(psVar2 + 0x18) == (short *)0x0) {
    sVar1 = *psVar2;
  }
  else {
    sVar1 = *psVar2 + **(short **)(psVar2 + 0x18);
  }
  dVar10 = (double)FLOAT_803e1c80;
  dVar12 = (double)FLOAT_803e1c84;
  dVar13 = (double)FLOAT_803e1c68;
  dVar11 = DOUBLE_803e1c30;
  for (uVar6 = 0; uVar6 < 4; uVar6 = uVar6 + 1) {
    uStack132 = (int)sVar1 + (uint)uVar6 * 0x4000 ^ 0x80000000;
    local_88 = 0x43300000;
    dVar9 = (double)(float)((double)(float)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,
                                                                                      uStack132) -
                                                                    dVar11)) / dVar12);
    dVar8 = (double)FUN_80293e80(dVar9);
    local_ec = -(float)(dVar14 * dVar8 - (double)*(float *)(psVar2 + 6));
    local_e8 = (float)(dVar13 + (double)*(float *)(psVar2 + 8));
    dVar8 = (double)FUN_80294204(dVar9);
    local_e4 = -(float)(dVar14 * dVar8 - (double)*(float *)(psVar2 + 10));
    FUN_80012d00(&local_ec,auStack244);
    if (*(int *)(psVar2 + 0x18) == 0) {
      uVar4 = FUN_800128dc(auStack244,auStack252,0,local_100,0);
      uVar4 = uVar4 & 0xff;
      if (local_100[0] == '\x01') {
        uVar4 = 1;
      }
    }
    else {
      uVar4 = 1;
    }
    if (uVar4 != 0) {
      iVar3 = FUN_800640cc((double)FLOAT_803e1c48,psVar2 + 6,&local_ec,0,auStack224,psVar2,
                           *(undefined *)((int)uVar15 + 0x261),0xffffffff,0,0);
      if (iVar3 != 0) {
        uVar4 = 0;
      }
    }
    uVar5 = uVar5 | uVar4 << (uint)uVar6 & 0xff;
  }
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
  FUN_8028611c(uVar5);
  return;
}

