// Function: FUN_801d129c
// Entry: 801d129c
// Size: 704 bytes

/* WARNING: Removing unreachable block (ram,0x801d1534) */
/* WARNING: Removing unreachable block (ram,0x801d1524) */
/* WARNING: Removing unreachable block (ram,0x801d1514) */
/* WARNING: Removing unreachable block (ram,0x801d1504) */
/* WARNING: Removing unreachable block (ram,0x801d14fc) */
/* WARNING: Removing unreachable block (ram,0x801d150c) */
/* WARNING: Removing unreachable block (ram,0x801d151c) */
/* WARNING: Removing unreachable block (ram,0x801d152c) */
/* WARNING: Removing unreachable block (ram,0x801d153c) */

void FUN_801d129c(void)

{
  int iVar1;
  short sVar5;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  undefined4 uVar9;
  double extraout_f1;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f23;
  double dVar17;
  undefined8 in_f24;
  double dVar18;
  undefined8 in_f25;
  double dVar19;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar20;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar21;
  float local_c0;
  undefined4 local_bc;
  float local_b8;
  undefined4 local_b0;
  uint uStack172;
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
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
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  uVar21 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar21 >> 0x20);
  dVar17 = extraout_f1;
  sVar5 = FUN_800217c0(-(double)(*(float *)(iVar1 + 0xc) - *(float *)((int)uVar21 + 0xc)),
                       -(double)(*(float *)(iVar1 + 0x14) - *(float *)((int)uVar21 + 0x14)));
  uVar8 = (uint)sVar5;
  uStack172 = uVar8 ^ 0x80000000;
  local_b0 = 0x43300000;
  dVar18 = (double)((FLOAT_803e52b4 *
                    (float)((double)CONCAT44(0x43300000,uStack172) - DOUBLE_803e52c8)) /
                   FLOAT_803e52b8);
  dVar10 = (double)FUN_80293e80(dVar18);
  dVar18 = (double)FUN_80294204(dVar18);
  local_c0 = -(float)(dVar17 * dVar10 - (double)*(float *)(iVar1 + 0xc));
  local_bc = *(undefined4 *)(iVar1 + 0x10);
  local_b8 = -(float)(dVar17 * dVar18 - (double)*(float *)(iVar1 + 0x14));
  iVar2 = FUN_800640cc((double)FLOAT_803e52d0,iVar1 + 0xc,&local_c0,3,0,iVar1,8,0xffffffff,0xff,0);
  uVar4 = uVar8;
  if (iVar2 != 0) {
    dVar20 = dVar10;
    dVar11 = (double)FUN_80293e80((double)FLOAT_803e52d4);
    dVar12 = (double)FUN_80293e80((double)FLOAT_803e52d8);
    dVar19 = dVar18;
    dVar13 = (double)FUN_80294204((double)FLOAT_803e52d4);
    dVar14 = (double)FUN_80294204((double)FLOAT_803e52d8);
    iVar2 = 0;
    uVar6 = uVar8;
    uVar7 = uVar8;
    while( true ) {
      uVar7 = uVar7 + 0xe38;
      dVar15 = (double)(float)(dVar10 * dVar13 + (double)(float)(dVar18 * dVar11));
      dVar18 = (double)(float)(dVar18 * dVar13 - (double)(float)(dVar10 * dVar11));
      local_c0 = -(float)(dVar17 * dVar15 - (double)*(float *)(iVar1 + 0xc));
      local_b8 = -(float)(dVar17 * dVar18 - (double)*(float *)(iVar1 + 0x14));
      iVar3 = FUN_800640cc((double)FLOAT_803e52d0,iVar1 + 0xc,&local_c0,1,0,iVar1,8,0xffffffff,0xff,
                           0);
      uVar4 = uVar7;
      if (iVar3 == 0) break;
      uVar6 = uVar6 - 0xe38;
      dVar16 = (double)(float)(dVar20 * dVar14 + (double)(float)(dVar19 * dVar12));
      dVar19 = (double)(float)(dVar19 * dVar14 - (double)(float)(dVar20 * dVar12));
      local_c0 = -(float)(dVar17 * dVar16 - (double)*(float *)(iVar1 + 0xc));
      local_b8 = -(float)(dVar17 * dVar19 - (double)*(float *)(iVar1 + 0x14));
      iVar3 = FUN_800640cc((double)FLOAT_803e52d0,iVar1 + 0xc,&local_c0,1,0,iVar1,8,0xffffffff,0xff,
                           0);
      uVar4 = uVar6;
      if ((iVar3 == 0) ||
         (iVar2 = iVar2 + 1, uVar4 = uVar8, dVar10 = dVar15, dVar20 = dVar16, 7 < iVar2)) break;
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
  __psq_l0(auStack72,uVar9);
  __psq_l1(auStack72,uVar9);
  __psq_l0(auStack88,uVar9);
  __psq_l1(auStack88,uVar9);
  __psq_l0(auStack104,uVar9);
  __psq_l1(auStack104,uVar9);
  __psq_l0(auStack120,uVar9);
  __psq_l1(auStack120,uVar9);
  __psq_l0(auStack136,uVar9);
  __psq_l1(auStack136,uVar9);
  FUN_80286128(uVar4);
  return;
}

