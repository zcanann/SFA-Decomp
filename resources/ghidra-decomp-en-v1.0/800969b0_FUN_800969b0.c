// Function: FUN_800969b0
// Entry: 800969b0
// Size: 740 bytes

/* WARNING: Removing unreachable block (ram,0x80096c6c) */
/* WARNING: Removing unreachable block (ram,0x80096c5c) */
/* WARNING: Removing unreachable block (ram,0x80096c4c) */
/* WARNING: Removing unreachable block (ram,0x80096c3c) */
/* WARNING: Removing unreachable block (ram,0x80096c34) */
/* WARNING: Removing unreachable block (ram,0x80096c44) */
/* WARNING: Removing unreachable block (ram,0x80096c54) */
/* WARNING: Removing unreachable block (ram,0x80096c64) */
/* WARNING: Removing unreachable block (ram,0x80096c74) */

void FUN_800969b0(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined4 param_6,undefined4 param_7,uint param_8)

{
  int iVar1;
  int iVar2;
  short *psVar3;
  undefined4 uVar4;
  int iVar5;
  short *psVar6;
  short *psVar7;
  float *pfVar8;
  short *psVar9;
  undefined4 uVar10;
  double extraout_f1;
  double dVar11;
  undefined8 in_f23;
  double dVar12;
  undefined8 in_f24;
  double dVar13;
  undefined8 in_f25;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar14;
  undefined8 in_f30;
  double dVar15;
  undefined8 in_f31;
  double dVar16;
  undefined8 uVar17;
  undefined auStack296 [8];
  float local_120;
  float local_11c;
  float local_118;
  float local_114;
  undefined4 local_110;
  uint uStack268;
  longlong local_108;
  undefined4 local_100;
  uint uStack252;
  undefined4 local_f8;
  uint uStack244;
  longlong local_f0;
  undefined4 local_e8;
  uint uStack228;
  undefined4 local_e0;
  uint uStack220;
  longlong local_d8;
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
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
  uVar17 = FUN_802860bc();
  iVar1 = (int)((ulonglong)uVar17 >> 0x20);
  psVar3 = (short *)uVar17;
  iVar5 = 0;
  pfVar8 = (float *)&DAT_8030f9d8;
  psVar6 = (short *)&DAT_803db788;
  dVar12 = (double)FLOAT_803df35c;
  dVar13 = (double)FLOAT_803df354;
  dVar15 = (double)(float)((double)FLOAT_803df350 / extraout_f1);
  dVar16 = (double)FLOAT_803df358;
  psVar7 = psVar3;
  psVar9 = psVar3;
  dVar14 = DOUBLE_803df360;
  do {
    iVar2 = FUN_800221a0(0x78,0x7f);
    uStack268 = iVar5 * iVar2 ^ 0x80000000;
    local_110 = 0x43300000;
    iVar2 = (int)(dVar15 + (double)(float)((double)CONCAT44(0x43300000,uStack268) - dVar14));
    local_108 = (longlong)iVar2;
    psVar9[0x12] = (short)iVar2;
    uStack252 = (int)psVar9[0x12] ^ 0x80000000;
    local_100 = 0x43300000;
    uStack244 = (int)psVar9[0xe] ^ 0x80000000;
    local_f8 = 0x43300000;
    iVar2 = (int)((float)((double)CONCAT44(0x43300000,uStack252) - dVar14) * FLOAT_803db414 +
                 (float)((double)CONCAT44(0x43300000,uStack244) - dVar14));
    local_f0 = (longlong)iVar2;
    psVar9[0xe] = (short)iVar2;
    dVar11 = (double)FUN_8029333c(psVar9[0xe]);
    *(float *)(psVar7 + 6) = *pfVar8 * (float)((double)(float)(dVar13 + dVar11) * dVar16);
    uStack228 = (int)*psVar6 ^ 0x80000000;
    local_e8 = 0x43300000;
    uStack220 = (int)psVar9[0x16] ^ 0x80000000;
    local_e0 = 0x43300000;
    iVar2 = (int)(FLOAT_803db414 * (float)((double)CONCAT44(0x43300000,uStack228) - dVar14) +
                 (float)((double)CONCAT44(0x43300000,uStack220) - dVar14));
    local_d8 = (longlong)iVar2;
    psVar9[0x16] = (short)iVar2;
    *psVar3 = psVar9[0x16];
    *(undefined4 *)(psVar3 + 4) = *(undefined4 *)(psVar7 + 6);
    for (iVar2 = 0; iVar2 < 0xffff; iVar2 = iVar2 + 0x7fff) {
      local_11c = (float)((double)*(float *)(psVar3 + 4) * param_2 + param_4);
      local_118 = (float)((double)*(float *)(psVar3 + 4) * param_3 + param_5);
      local_114 = (float)dVar12;
      *psVar3 = *psVar3 + 0x7fff;
      FUN_80021ac8(psVar3,&local_11c);
      local_11c = local_11c + *(float *)(iVar1 + 0xc);
      local_118 = local_118 + *(float *)(iVar1 + 0x10);
      local_114 = local_114 + *(float *)(iVar1 + 0x14);
      local_120 = (float)dVar13;
      uVar4 = 0x200001;
      if ((param_8 & 0xff) != 0) {
        uVar4 = 0x20200001;
      }
      (**(code **)(*DAT_803dca88 + 8))(iVar1,0x7ec,auStack296,uVar4,0xffffffff,0);
    }
    psVar9 = psVar9 + 1;
    pfVar8 = pfVar8 + 1;
    psVar7 = psVar7 + 2;
    psVar6 = psVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 4);
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  __psq_l0(auStack56,uVar10);
  __psq_l1(auStack56,uVar10);
  __psq_l0(auStack72,uVar10);
  __psq_l1(auStack72,uVar10);
  __psq_l0(auStack88,uVar10);
  __psq_l1(auStack88,uVar10);
  __psq_l0(auStack104,uVar10);
  __psq_l1(auStack104,uVar10);
  __psq_l0(auStack120,uVar10);
  __psq_l1(auStack120,uVar10);
  __psq_l0(auStack136,uVar10);
  __psq_l1(auStack136,uVar10);
  FUN_80286108();
  return;
}

