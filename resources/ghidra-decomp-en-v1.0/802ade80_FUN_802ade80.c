// Function: FUN_802ade80
// Entry: 802ade80
// Size: 1536 bytes

/* WARNING: Removing unreachable block (ram,0x802ae458) */
/* WARNING: Removing unreachable block (ram,0x802ae448) */
/* WARNING: Removing unreachable block (ram,0x802ae450) */
/* WARNING: Removing unreachable block (ram,0x802ae460) */

void FUN_802ade80(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short sVar5;
  uint uVar4;
  int iVar6;
  int iVar7;
  bool bVar8;
  undefined4 uVar9;
  double dVar10;
  undefined8 in_f28;
  double dVar11;
  undefined8 in_f29;
  double dVar12;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar13;
  undefined8 uVar14;
  float local_108;
  float local_104;
  float local_100;
  undefined auStack252 [4];
  float local_f8;
  undefined auStack244 [8];
  float local_ec;
  float local_e8;
  float local_e4;
  float local_e0;
  undefined2 local_dc;
  undefined2 local_da;
  undefined2 local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  undefined auStack196 [68];
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  double local_70;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar14 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar14 >> 0x20);
  iVar6 = (int)uVar14;
  dVar11 = (double)*(float *)(iVar6 + 0x83c);
  uStack124 = (uint)*(ushort *)(iVar6 + 0x89c);
  local_80 = 0x43300000;
  dVar10 = (double)FUN_80293e80((double)((FLOAT_803e7f94 *
                                         (float)((double)CONCAT44(0x43300000,uStack124) -
                                                DOUBLE_803e7f38)) / FLOAT_803e7f98));
  uStack116 = (uint)*(ushort *)(iVar6 + 0x89c);
  local_78 = 0x43300000;
  iVar7 = (int)(FLOAT_803e8114 * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e7f38));
  local_70 = (double)(longlong)iVar7;
  *(short *)(iVar6 + 0x89c) = (short)iVar7;
  fVar1 = (float)(dVar11 + dVar10) - *(float *)(iVar3 + 0x10);
  if (FLOAT_803e7fa0 < fVar1) {
    fVar1 = FLOAT_803e7fa0;
  }
  *(float *)(iVar3 + 0x28) =
       (fVar1 / FLOAT_803e7fa0) * FLOAT_803e8118 * FLOAT_803db414 + *(float *)(iVar3 + 0x28);
  *(float *)(iVar3 + 0x28) = -(FLOAT_803e7efc * FLOAT_803db414 - *(float *)(iVar3 + 0x28));
  dVar10 = (double)FUN_80292b44((double)FLOAT_803e7fd0,(double)FLOAT_803db414);
  *(float *)(iVar3 + 0x28) = (float)((double)*(float *)(iVar3 + 0x28) * dVar10);
  fVar1 = *(float *)(iVar3 + 0x28);
  fVar2 = FLOAT_803e811c;
  if ((FLOAT_803e811c <= fVar1) && (fVar2 = fVar1, FLOAT_803e8120 < fVar1)) {
    fVar2 = FLOAT_803e8120;
  }
  *(float *)(iVar3 + 0x28) = fVar2;
  FUN_802ab690((double)FLOAT_803e7ee0,&local_104,&local_108,iVar3);
  uStack100 = (int)*(short *)(iVar6 + 0x478) ^ 0x80000000;
  local_68 = 0x43300000;
  dVar10 = (double)FUN_80293e80((double)((FLOAT_803e7f94 *
                                         (float)((double)CONCAT44(0x43300000,uStack100) -
                                                DOUBLE_803e7ec0)) / FLOAT_803e7f98));
  uStack92 = (int)*(short *)(iVar6 + 0x478) ^ 0x80000000;
  local_60 = 0x43300000;
  dVar11 = (double)FUN_80294204((double)((FLOAT_803e7f94 *
                                         (float)((double)CONCAT44(0x43300000,uStack92) -
                                                DOUBLE_803e7ec0)) / FLOAT_803e7f98));
  fVar1 = FLOAT_803e7efc;
  *(float *)(iVar6 + 0x440) =
       FLOAT_803db414 *
       FLOAT_803e7efc *
       ((float)((double)local_104 * dVar11 - (double)(float)((double)local_108 * dVar10)) -
       *(float *)(iVar6 + 0x440)) + *(float *)(iVar6 + 0x440);
  *(float *)(iVar6 + 0x43c) =
       FLOAT_803db414 *
       fVar1 * ((float)(-(double)local_108 * dVar11 - (double)(float)((double)local_104 * dVar10)) -
               *(float *)(iVar6 + 0x43c)) + *(float *)(iVar6 + 0x43c);
  bVar8 = false;
  if (*(short *)(param_3 + 0x274) == 1) {
    if ((*(uint *)(param_3 + 0x314) & 0x200) != 0) {
      FUN_8000bae0((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar6 + 0x83c),
                   (double)*(float *)(iVar3 + 0x14),iVar3,0xe);
    }
    if ((*(float *)(iVar6 + 0x838) < FLOAT_803e7fa0) && ((*(uint *)(param_3 + 0x314) & 0x200) != 0))
    {
      uStack92 = FUN_800221a0(0xffffffec,0x14);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_100 = (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e7ec0) / FLOAT_803e7ed8;
      uStack100 = FUN_800221a0(0xffffffec,0x14);
      uStack100 = uStack100 ^ 0x80000000;
      local_68 = 0x43300000;
      local_f8 = (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e7ec0) / FLOAT_803e7ed8;
      bVar8 = true;
    }
  }
  else {
    if ((*(uint *)(param_3 + 0x314) & 1) != 0) {
      FUN_8000bae0((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar6 + 0x83c),
                   (double)*(float *)(iVar3 + 0x14),iVar3,0xf);
    }
    if ((*(float *)(iVar6 + 0x838) < FLOAT_803e7fa0) && ((*(uint *)(param_3 + 0x314) & 0x200) != 0))
    {
      uStack92 = FUN_800221a0(0xffffffec,0x14);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_100 = (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e7ec0) / FLOAT_803e7ed8;
      local_f8 = FLOAT_803e8124;
      bVar8 = true;
    }
  }
  if (bVar8) {
    local_d0 = *(float *)(iVar3 + 0xc);
    local_cc = FLOAT_803e7ea4;
    local_c8 = *(float *)(iVar3 + 0x14);
    local_dc = *(undefined2 *)(iVar6 + 0x478);
    local_da = 0;
    local_d8 = 0;
    local_d4 = FLOAT_803e7ee0;
    FUN_80021ee8(auStack196,&local_dc);
    FUN_800226cc((double)local_100,(double)FLOAT_803e7ea4,(double)local_f8,auStack196,&local_100,
                 auStack252,&local_f8);
    (**(code **)(*DAT_803dca98 + 0x14))
              ((double)local_100,(double)*(float *)(iVar6 + 0x83c),(double)local_f8,
               (double)FLOAT_803e7ea4,0,5);
    if ((FLOAT_803e8128 < *(float *)(iVar6 + 0x838)) &&
       (FLOAT_803e7e9c < *(float *)(param_3 + 0x294))) {
      sVar5 = FUN_800217c0((double)*(float *)(param_3 + 0x284),(double)*(float *)(param_3 + 0x280));
      (**(code **)(*DAT_803dca98 + 0x18))
                ((double)local_100,(double)*(float *)(iVar6 + 0x83c),(double)local_f8,
                 (double)FLOAT_803e7ea4,(int)(short)(*(short *)(iVar6 + 0x478) - sVar5));
    }
  }
  FUN_8003842c(iVar3,0x13,&local_d0,&local_cc,&local_c8,0);
  bVar8 = FLOAT_803e7f10 < *(float *)(iVar6 + 0x83c) - local_cc;
  dVar13 = (double)FLOAT_803e7fa4;
  dVar11 = (double)FLOAT_803e808c;
  dVar12 = (double)FLOAT_803e7ea4;
  dVar10 = DOUBLE_803e7ec0;
  for (iVar7 = 0; iVar7 < (int)(uint)bVar8; iVar7 = iVar7 + 1) {
    uStack92 = FUN_800221a0(0xffffff9c,100);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_e8 = local_d0 +
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack92) - dVar10) / dVar13);
    uStack100 = FUN_800221a0(0xffffff9c,100);
    uStack100 = uStack100 ^ 0x80000000;
    local_68 = 0x43300000;
    local_e4 = local_cc +
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack100) - dVar10) / dVar11);
    uVar4 = FUN_800221a0(0xffffff9c,100);
    local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_e0 = local_c8 + (float)((double)(float)(local_70 - dVar10) / dVar13);
    local_ec = *(float *)(iVar6 + 0x83c) - local_e4;
    if (dVar12 < (double)local_ec) {
      (**(code **)(*DAT_803dca88 + 8))(iVar3,0x202,auStack244,0x200001,0xffffffff,0);
    }
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  __psq_l0(auStack56,uVar9);
  __psq_l1(auStack56,uVar9);
  FUN_80286128();
  return;
}

